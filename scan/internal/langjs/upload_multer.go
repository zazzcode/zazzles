package langjs

import (
	"sort"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
	"github.com/zazzcode/zazzles/scan/internal/parse"
)

// Upload for Express (lane decision D-10). The operation is a verified multer
// middleware (multerMiddleware) on a route registration: multer reads the
// multipart body before the handlers run and, with disk storage, writes each
// file itself. One file_upload_candidate is recorded per middleware per
// route, on the entry of the route's last handler.
//
// What multer documents (https://github.com/expressjs/multer#readme) and this
// file relies on:
//
//   - memoryStorage writes no file; the upload is file.buffer. Whether it is
//     stored is decided by the handlers after the middleware, so the stored
//     name, the extension and the destination are recorded as unknown and the
//     handlers are attached as context. Their writes are not followed here.
//   - diskStorage stores a file under the directory its destination option
//     names and the name its filename callback passes on. With no filename
//     callback, and with the dest shorthand, the name is random and has no
//     extension.
//   - file.originalname and file.mimetype are what the client sent.
//
// Type controls are the conditions inside the storage callbacks and the
// fileFilter option. Controls are evidence, never a filter.

var uploadRouteMethods = map[string]bool{"get": true, "post": true, "put": true, "patch": true, "delete": true, "all": true, "use": true}

// uploadCandidates records the D-10 operations of every selected module. It
// runs after entries exist and before input facts are assembled.
func (s *moduleSet) uploadCandidates(out *analysis.AnalysisReport, selected []string) {
	var mounts []servedDirectory
	mountsRead := false
	for _, file := range selected {
		m := s.modules[file]
		if m == nil || m.tree.RootNode().HasError() {
			continue
		}
		walkCalls(m.tree.RootNode(), func(call *sitter.Node) {
			fn, args := call.ChildByFieldName("function"), call.ChildByFieldName("arguments")
			if fn == nil || args == nil || fn.Kind() != "member_expression" {
				return
			}
			obj, prop := fn.ChildByFieldName("object"), fn.ChildByFieldName("property")
			if obj == nil || prop == nil || obj.Kind() != "identifier" || !uploadRouteMethods[prop.Utf8Text(m.src)] ||
				!receiverUsable(m, call, obj.Utf8Text(m.src)) {
				return
			}
			for i := uint(0); i < args.NamedChildCount(); i++ {
				b, ok := multerMiddleware(m, args.NamedChild(i))
				if !ok || b.method == "none" { // none() accepts text fields only
					continue
				}
				if !mountsRead {
					mounts, mountsRead = s.servedDirectories(selected), true
				}
				s.recordUpload(out, m, call, i, b, mounts)
			}
		})
	}
}

func (s *moduleSet) recordUpload(out *analysis.AnalysisReport, m *sourceModule, route *sitter.Node, index uint, b multerBinding, mounts []servedDirectory) {
	entries := s.entriesFor(out, m, route)
	if len(entries) == 0 {
		out.Gaps = append(out.Gaps, analysis.Gap{Kind: "upload_entry_missing", Detail: "a multer middleware was read and no HTTP entry carries it", At: parse.Span(m.file, b.call)})
		return
	}
	args := route.ChildByFieldName("arguments")
	entry := s.uploadEntry(m, args, entries)

	facts := &analysis.UploadFacts{Operation: "multer." + b.storage + "Storage." + b.method, ContractID: analysispacks.NodeMulterMemory,
		StoredName: "unknown", ExtensionOrigin: "unknown", DestinationServed: "unknown", Paths: []analysis.CommandPath{}}
	content := analysis.Dependency{SinkSlot: "upload_content", Source: m.evidence("input_source", b.call), Transfers: []analysis.Evidence{}}
	content.Source.ModelText = "The middleware reads the multipart request body; each file part is an upload the client sent."
	deps := []analysis.Dependency{content}

	binding := []analysis.Evidence{m.evidence("sink_binding", b.declaration), m.evidence("sink_binding", b.ctor), m.evidence("sink_binding", b.call)}
	operands := []analysis.Evidence{m.evidence("upload_operand", b.ctor)}
	var conditions []uploadCondition
	var blockers, coverage []analysis.Gap
	var callables []analysis.Evidence
	if b.storage == "disk" {
		facts.ContractID = analysispacks.NodeMulterDisk
		d := s.multerDisk(m, b, mounts)
		facts.StoredName, facts.ExtensionOrigin, facts.Destination, facts.DestinationServed = d.stored, d.extension, d.destination, d.served
		deps = append(deps, d.deps...)
		operands = append(operands, d.operands...)
		conditions, blockers, callables = d.conditions, d.blockers, d.callables
	} else {
		coverage = append(coverage, analysis.Gap{Kind: "upload_memory_write_unresolved", Detail: "memory storage writes no file; a write of the buffer by a later handler is not followed", At: parse.Span(m.file, b.call)})
	}
	if b.filter != nil {
		if cb := uploadCallbackOf(m, b.filter); cb != nil {
			conditions = append(conditions, cb.conditions(m, true)...)
			callables = append(callables, m.evidence("invoked_callable", cb.fn))
		} else {
			blockers = append(blockers, analysis.Gap{Kind: "upload_callback_unresolved", Detail: "the fileFilter option is not a function this module defines", At: parse.Span(m.file, b.filter)})
		}
	}
	for i := range deps {
		facts.Paths = append(facts.Paths, analysis.CommandPath{Dependency: i, Operand: deps[i].SinkSlot, Protection: "raw"})
	}

	context := append(append([]analysis.Evidence{}, binding...), operands...)
	registration := m.evidence("route_registration", route)
	flow := []analysis.Evidence{m.evidence("operation", b.call), registration}
	context = append(context, registration)
	for _, c := range conditions {
		facts.TypeControls = append(facts.TypeControls, analysis.UploadControl{Kind: c.kind, Context: len(context), ClientControlled: c.kind == analysis.UploadClientDeclaredType})
		context = append(context, asEvidenceKind(c.at, "upload_type_test"))
		flow = append(flow, c.at)
		if c.kind == analysis.UploadExtensionAllowList && facts.ExtensionOrigin == "client" {
			facts.ExtensionOrigin = "allow_listed"
		}
	}
	// The handlers after the middleware receive the upload: they are the
	// callables this request invokes, and with memory storage the only place a
	// write can be.
	for i := index + 1; i < args.NamedChildCount(); i++ {
		hm, body, gaps := s.uploadHandler(m, args.NamedChild(i))
		if body == nil {
			for _, g := range gaps {
				if g.At.File == "" {
					g.At = parse.Span(m.file, args.NamedChild(i))
				}
				coverage = append(coverage, g)
			}
			continue
		}
		callables = append(callables, hm.evidence("invoked_callable", body))
	}
	if len(callables) == 0 {
		callables = []analysis.Evidence{asEvidenceKind(registration, "invoked_callable")}
	}
	// Context copies carry upload-specific kinds: the entry's invocation
	// context collects invoked_callable and branch_precondition context
	// evidence as its controls, and the identifier of every record on the entry
	// is derived from that context. These records add evidence to their own
	// claim only.
	for _, c := range callables {
		context = append(context, asEvidenceKind(c, "upload_callable"))
	}

	u := analysis.CandidateUse{
		EntryID: entry.ID, Kind: "file_upload_candidate", Sink: m.evidence("file_upload_candidate", b.call),
		Dependencies: deps, Context: context, Gaps: []analysis.Gap{}, Upload: facts,
		APIModel:   analysispacks.UploadContract(facts.ContractID),
		Assessment: analysis.Assessment{Status: "not_run"},
	}
	if blockers == nil {
		blockers = []analysis.Gap{}
	}
	if coverage == nil {
		coverage = []analysis.Gap{}
	}
	u.Completeness = parse.UploadCompleteness(&u, map[string][]analysis.Evidence{
		"sink_binding":     binding,
		"invoked_callable": callables,
		"control_flow":     flow,
		"upload_operand":   operands,
	}, blockers, coverage)
	out.Uses = append(out.Uses, u)
}

// uploadEntry picks the entry of the route's last handler when it resolved,
// otherwise the first entry that has a request context, otherwise the first.
func (s *moduleSet) uploadEntry(m *sourceModule, args *sitter.Node, entries []analysis.EntryPoint) analysis.EntryPoint {
	if n := args.NamedChildCount(); n > 0 {
		if hm, body, _ := s.uploadHandler(m, args.NamedChild(n-1)); body != nil {
			for _, e := range entries {
				if c := s.nodeHTTP[e.ID]; c != nil && c.handler == hm && c.body != nil && c.body.StartByte() == body.StartByte() {
					return e
				}
			}
		}
	}
	for _, e := range entries {
		if s.nodeHTTP[e.ID] != nil {
			return e
		}
	}
	return entries[0]
}

// uploadHandler resolves a handler argument the way the route's own chain
// stages are resolved (pathChainEvidence), so it finds the same bodies.
func (s *moduleSet) uploadHandler(m *sourceModule, arg *sitter.Node) (*sourceModule, *sitter.Node, []analysis.Gap) {
	hm, node := s.pathHandler(m, arg)
	if hm == nil {
		_, _, _, gaps := s.handler(m, arg)
		return nil, nil, gaps
	}
	_, body, _, gaps := s.handler(hm, node)
	return hm, body, gaps
}

type multerDiskFacts struct {
	stored, extension, destination, served string
	deps                                   []analysis.Dependency
	operands, callables                    []analysis.Evidence
	conditions                             []uploadCondition
	blockers                               []analysis.Gap
}

// multerDisk reads the destination and filename options of disk storage.
func (s *moduleSet) multerDisk(m *sourceModule, b multerBinding, mounts []servedDirectory) multerDiskFacts {
	// No filename callback: multer generates a random name with no extension.
	d := multerDiskFacts{stored: "server_generated", extension: "fixed", served: "unknown"}
	destination, filename := b.dest, (*sitter.Node)(nil)
	if b.options != nil {
		destination, filename = property(b.options, "destination", m.src), property(b.options, "filename", m.src)
	}
	var directory servedDirectory
	resolved := false
	if destination != nil {
		d.operands = append(d.operands, m.evidence("upload_operand", destination))
		if cb := uploadCallbackOf(m, destination); cb != nil {
			d.callables = append(d.callables, m.evidence("invoked_callable", cb.fn))
			d.conditions = append(d.conditions, cb.conditions(m, false)...)
			results := cb.results(m)
			for i, r := range results {
				dir, ok := resolveDirectory(m, r, 0)
				if !ok || i > 0 && dir != directory {
					resolved = false
					break
				}
				directory, resolved = dir, true
			}
		} else {
			directory, resolved = resolveDirectory(m, destination, 0)
		}
	}
	if resolved {
		d.destination, d.served = directory.path, directory.servedBy(mounts)
	}
	if filename == nil {
		return d
	}
	cb := uploadCallbackOf(m, filename)
	if cb == nil {
		d.stored, d.extension = "unknown", "unknown"
		d.blockers = append(d.blockers, analysis.Gap{Kind: "upload_callback_unresolved", Detail: "the filename option is not a function this module defines", At: parse.Span(m.file, filename)})
		return d
	}
	d.callables = append(d.callables, m.evidence("invoked_callable", cb.fn))
	d.conditions = append(d.conditions, cb.conditions(m, false)...)
	results := cb.results(m)
	if len(results) == 0 {
		d.stored, d.extension = "unknown", "unknown"
		return d
	}
	sources := map[string]*sitter.Node{}
	for i, r := range results {
		d.operands = append(d.operands, m.evidence("upload_operand", r))
		stored, extension := cb.storedName(m, r)
		if i > 0 && (stored != d.stored || extension != d.extension) {
			stored, extension = "unknown", "unknown"
		}
		d.stored, d.extension = stored, extension
		for _, field := range []string{"originalname", "mimetype"} {
			if cb.mentions(m, r, field) && sources[field] == nil {
				sources[field] = cb.firstRead(m, field)
			}
		}
	}
	fields := make([]string, 0, len(sources))
	for field, node := range sources {
		if node != nil {
			fields = append(fields, field)
		}
	}
	sort.Strings(fields)
	for _, field := range fields {
		d.deps = append(d.deps, analysis.Dependency{SinkSlot: "stored_name", Source: m.evidence("input_source", sources[field]), Transfers: []analysis.Evidence{}})
	}
	return d
}
