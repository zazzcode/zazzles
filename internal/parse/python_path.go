package parse

import (
	"fmt"
	"regexp"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
)

// pyPathlibOps are the verified pathlib.Path read/write/delete methods: the receiver
// carries the path; text, bytes, encoding and mode arguments are separate.
var pyPathlibOps = map[string]struct{ role, content string }{
	"read_text": {"read", ""}, "read_bytes": {"read", ""}, "write_text": {"write", "data"}, "write_bytes": {"write", "data"}, "open": {"", ""}, "unlink": {"delete", ""},
}

var pyPathObjectNames = map[string]bool{"pathlib.Path": true, "pathlib.PurePath": true, "pathlib.PosixPath": true, "pathlib.PurePosixPath": true}

// pyModeledPathCalls are qualified calls modeled as path transformations. None
// of them checks containment.
var pyModeledPathCalls = map[string]bool{
	"os.path.join": true, "os.path.abspath": true, "os.path.normpath": true, "os.path.realpath": true, "os.path.basename": true, "os.path.dirname": true,
	"os.path.relpath": true, "os.path.commonpath": true, "os.path.isabs": true, "os.path.expanduser": true, "os.path.normcase": true,
	"posixpath.join": true, "posixpath.abspath": true, "posixpath.normpath": true, "posixpath.realpath": true, "posixpath.basename": true, "posixpath.dirname": true,
	"urllib.parse.unquote": true, "urllib.parse.unquote_plus": true, "os.getcwd": true, "werkzeug.utils.secure_filename": true,
}

// pyPathMethods are pathlib receiver methods that return another path object.
var pyPathMethods = map[string]bool{"resolve": true, "joinpath": true, "absolute": true, "with_name": true, "with_suffix": true, "expanduser": true, "relative_to": true, "is_relative_to": true}

// pyArchiveOpens are the verified archive/compressed-file opens whose first
// argument is the file name; the value is the keyword that names it.
var pyArchiveOpens = map[string]string{
	"tarfile.open": "name", "tarfile.TarFile": "name", "tarfile.TarFile.open": "name",
	"bz2.open": "filename", "bz2.BZ2File": "filename", "gzip.open": "filename", "gzip.GzipFile": "filename",
	"lzma.open": "filename", "lzma.LZMAFile": "filename",
}

func pyPathModule(q string) bool {
	return strings.HasPrefix(q, "pathlib.") || strings.HasPrefix(q, "os.path.") || strings.HasPrefix(q, "posixpath.") || q == "io.open"
}

type pyPathBuilder struct {
	f       *pythonFlow
	facts   *analysis.PathFacts
	deps    []pythonDep
	context []analysis.Evidence
	gaps    []analysis.Gap
	names   map[string]bool
	request bool
}

func (b *pyPathBuilder) operand(slot, kind string, n *sitter.Node, v pythonValue) {
	o := analysis.PathOperand{Slot: slot}
	if text, ok := pyLiteral(b.f.module, n); ok {
		o.Constant = text
	} else {
		o.Dynamic = true
	}
	o.Context = append(o.Context, len(b.context))
	b.context = append(b.context, b.f.module.evidence(kind, n))
	for _, d := range v.deps {
		if slot == analysis.PathSlotFile && !requestOrigin(d.dep) {
			continue // a stored, file or API value is not a request field
		}
		d.dep.SinkSlot = slot
		idx := len(b.deps)
		o.Dependencies = append(o.Dependencies, idx)
		if slot == analysis.PathSlotFile {
			b.facts.Paths = append(b.facts.Paths, analysis.PathFlow{Dependency: idx, Operand: slot, Protection: "raw", Transforms: pathTransforms(d.dep), Root: pathRoot(d.dep)})
			b.request = true
			b.names[d.container+"."+d.key] = true
			b.names[d.dep.Source.Text] = true
			for _, name := range commandDepNames(d.dep) {
				b.names[name] = true
			}
		}
		b.deps = append(b.deps, d)
	}
	if slot == analysis.PathSlotFile {
		pyWalk(n, func(c *sitter.Node) {
			if c.Kind() == "identifier" {
				b.names[pyText(b.f.module, c)] = true
			}
		})
		b.gaps = append(b.gaps, v.gaps...)
	}
	b.facts.Operands = append(b.facts.Operands, o)
}

// openRole reads the mode of open/io.open/Path.open: a literal selects read or
// write, a dynamic mode is unknown, and the default is read.
func (f *pythonFlow) openRole(call *sitter.Node, modeNode *sitter.Node) string {
	if modeNode == nil {
		return "read"
	}
	mode, ok := pyLiteral(f.module, modeNode)
	if !ok {
		return "unknown"
	}
	if strings.ContainsAny(mode, "wax+") {
		return "write"
	}
	return "read"
}

func (f *pythonFlow) rootImportEvidence(name string, fn *sitter.Node) []analysis.Evidence {
	m := f.module
	root := strings.Split(name, ".")[0]
	evidence := []analysis.Evidence{}
	if imp, found := f.imports[root]; found {
		evidence = append(evidence, m.evidence("sink_binding", imp.node))
	} else if imp, found := m.imports[root]; found {
		evidence = append(evidence, m.evidence("sink_binding", imp.node))
	}
	return append(evidence, m.evidence("sink_binding", fn))
}

// pathOperation resolves the called function or method to a verified read/write/delete
// of the supported open/io.open/pathlib/os/flask/archive contracts. Shadowing,
// imports, aliases and local modules are verified; a wrapper or fake object is not.
func (f *pythonFlow) pathOperation(call, fn *sitter.Node, receiver pythonValue, object *sitter.Node, method string) (op, contract, role string, path *sitter.Node, content *sitter.Node, evidence []analysis.Evidence, ok bool) {
	m := f.module
	name := pyText(m, fn)
	positional := pyArgs(call)
	argument := func(index int, keyword string) *sitter.Node {
		if len(positional) > index {
			return positional[index]
		}
		return pyKeywordIn(m, call, keyword)
	}
	q := f.qualified(name)
	switch {
	case fn.Kind() == "identifier" && name == "open" && f.builtin("open"):
		if path = argument(0, "file"); path == nil || path.Kind() == "list_splat" {
			return
		}
		return "open", analysispacks.PythonOpenContract, f.openRole(call, argument(1, "mode")), path, nil, []analysis.Evidence{m.evidence("sink_binding", fn)}, true
	case q == "io.open":
		if path = argument(0, "file"); path == nil || path.Kind() == "list_splat" || f.set.commandTampered(m, "io") {
			return
		}
		return "io.open", analysispacks.PythonOpenContract, f.openRole(call, argument(1, "mode")), path, nil, f.rootImportEvidence(name, fn), true
	case q == "os.remove" || q == "os.unlink":
		if path = argument(0, "path"); path == nil || path.Kind() == "list_splat" || f.set.commandTampered(m, "os") {
			return
		}
		return q, analysispacks.PythonOSFileContract, "delete", path, nil, f.rootImportEvidence(name, fn), true
	case q == "flask.send_file" || q == "flask.send_from_directory":
		if f.set.commandTampered(m, "flask") {
			return
		}
		if q == "flask.send_file" {
			path = argument(0, "path_or_file")
		} else if path = argument(1, "path"); path == nil {
			path = pyKeywordIn(m, call, "filename")
		}
		if path == nil || path.Kind() == "list_splat" {
			return
		}
		return q, analysispacks.FlaskSendContract, "read", path, nil, f.rootImportEvidence(name, fn), true
	case pyArchiveOpens[q] != "":
		if path = argument(0, pyArchiveOpens[q]); path == nil || path.Kind() == "list_splat" || f.set.commandTampered(m, strings.Split(q, ".")[0]) {
			return
		}
		return q, analysispacks.PythonArchiveContract, f.openRole(call, argument(1, "mode")), path, nil, f.rootImportEvidence(name, fn), true
	case method == "save" && object != nil && fn.Kind() == "attribute" && uploadReceiver(receiver):
		if path = argument(0, "dst"); path == nil || path.Kind() == "list_splat" {
			return
		}
		return "werkzeug.FileStorage.save", analysispacks.PythonSaveContract, "write", path, nil, []analysis.Evidence{m.evidence("sink_binding", object), m.evidence("sink_binding", fn)}, true
	case receiver.binding == "pathlib_path" && object != nil:
		spec, known := pyPathlibOps[method]
		if !known || f.set.commandTampered(m, "pathlib") {
			return
		}
		role = spec.role
		if method == "open" {
			role = f.openRole(call, argument(0, "mode"))
		}
		if spec.content != "" {
			content = argument(0, "data")
		}
		return "pathlib.Path." + method, analysispacks.PythonPathlibContract, role, object, content, []analysis.Evidence{m.evidence("sink_binding", object)}, true
	}
	return
}

// uploadReceiver reports a value taken from request.files: a werkzeug FileStorage.
func uploadReceiver(v pythonValue) bool {
	if len(v.deps) == 0 {
		return false
	}
	for _, d := range v.deps {
		if d.container != "files" {
			return false
		}
	}
	return true
}

var sanitizerCallee = regexp.MustCompile(`^\s*([A-Za-z_][\w.]*)\s*\(`)

// verifiedSanitizers returns the transfer evidence of each verified
// werkzeug.utils.secure_filename call on the dependency's value chain; a local
// function of the same name is not one.
func (f *pythonFlow) verifiedSanitizers(d analysis.Dependency) []analysis.Evidence {
	var out []analysis.Evidence
	for _, e := range d.Transfers {
		if transformKind(e) != analysis.PathTransformSanitize {
			continue
		}
		if m := sanitizerCallee.FindStringSubmatch(e.Text); len(m) == 2 && f.qualified(m[1]) == "werkzeug.utils.secure_filename" {
			out = append(out, e)
		}
	}
	return out
}

// pathCall records a path_traversal_candidate when request data reaches the
// path operand of a verified filesystem call. It is additive: the call is then
// handled exactly as before.
func (f *pythonFlow) pathCall(call, fn *sitter.Node, receiver pythonValue, object *sitter.Node, method string) {
	op, contract, role, pathNode, contentNode, binding, ok := f.pathOperation(call, fn, receiver, object, method)
	if !ok {
		return
	}
	m := f.module
	b := &pyPathBuilder{f: f, names: map[string]bool{}, facts: &analysis.PathFacts{Operation: op, ContractID: contract, Platform: "posix", Role: role,
		Operands: []analysis.PathOperand{}, Paths: []analysis.PathFlow{}, Guards: []analysis.PathGuard{}}}
	args := call.ChildByFieldName("arguments")
	for i := uint(0); args != nil && i < args.NamedChildCount(); i++ {
		if c := args.NamedChild(i); c.Kind() == "list_splat" || c.Kind() == "dictionary_splat" {
			b.gaps = append(b.gaps, f.gap("path_spread_unresolved", "*args/**kwargs in a filesystem call are not modeled", c))
		}
	}
	b.operand(analysis.PathSlotFile, "path_operand", pathNode, f.quiet(pathNode))
	if !b.request {
		return
	}
	if contentNode != nil {
		b.operand(analysis.PathSlotContent, "path_content", contentNode, f.quiet(contentNode))
	}
	id := fmt.Sprintf("use:%s:%s:%d:%s", f.invocation.ID, m.file, call.StartByte(), "path_traversal_candidate")
	for _, existing := range f.report.Uses {
		if existing.ID == id {
			return // several syntactic paths reach one call in one invocation; one record
		}
	}
	var all pythonValue
	for _, d := range b.deps {
		all.deps = append(all.deps, d)
	}
	all.gaps = b.gaps
	u := f.addUse("path_traversal_candidate", call, all)
	u.Path = b.facts
	u.APIModel = analysispacks.PathContract(contract)
	u.Dependencies = make([]analysis.Dependency, len(b.deps))
	for i, d := range b.deps {
		u.Dependencies[i] = d.dep
	}
	u.Context = append(u.Context, binding...)
	base := len(u.Context)
	u.Context = append(u.Context, b.context...)
	for i := range u.Path.Operands {
		for j := range u.Path.Operands[i].Context {
			u.Path.Operands[i].Context[j] += base
		}
	}
	info := newPathGuardInfo()
	guards, declEvidence := f.pythonPathGuards(call, u, b.names, info)
	u.Context = append(u.Context, declEvidence...)
	if op == "flask.send_from_directory" {
		// The library joins the path to the directory with safe_join and rejects an
		// escape; that holds only when the directory is a verified constant base.
		directory := pyKeywordIn(m, call, "directory")
		if args := pyArgs(call); directory == nil && len(args) > 0 {
			directory = args[0]
		}
		if directory != nil && f.safeSendDirectory(m, directory) {
			ev := m.evidence("framework_root", directory)
			covered := map[int]bool{}
			for i, d := range u.Dependencies {
				if d.SinkSlot == analysis.PathSlotFile {
					covered[i] = true
				}
			}
			info.note(ev, analysis.PathGuardFrameworkRoot, covered)
			guards = append(guards, ev)
		}
	}
	for i, d := range u.Dependencies {
		if d.SinkSlot != analysis.PathSlotFile {
			continue
		}
		sanitizers := f.verifiedSanitizers(d)
		for _, e := range sanitizers {
			info.note(e, analysis.PathGuardComponentSanitizer, map[int]bool{i: true})
			guards = append(guards, e)
		}
		for j := range u.Path.Paths {
			if u.Path.Paths[j].Dependency != i {
				continue
			}
			kept := u.Path.Paths[j].Transforms[:0:0]
			for _, t := range u.Path.Paths[j].Transforms {
				if t != analysis.PathTransformSanitize || len(sanitizers) > 0 {
					kept = append(kept, t)
				}
			}
			u.Path.Paths[j].Transforms = kept
		}
	}
	guardIndex := []int{}
	for _, g := range guards {
		guardIndex = append(guardIndex, len(u.Context))
		u.Context = append(u.Context, g)
	}
	f.completePythonPath(u, call, all, guards, guardIndex, b.names, info)
}
