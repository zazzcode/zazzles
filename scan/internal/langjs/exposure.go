package langjs

import (
	"fmt"
	"slices"
	"sort"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
	"github.com/zazzcode/zazzles/scan/internal/parse"
)

// Information exposure for Express (lane decision D-8). Each operation is a
// documented contract of a library or of the Node.js process object:
//
//   - the errorhandler package's middleware sends the stack trace of an error
//     (https://github.com/expressjs/errorhandler#readme);
//   - prom-client's register.metrics() returns every registered metric, process
//     and runtime metrics included;
//   - swagger-ui-express's setup(document) serves the API description;
//   - process.env, process.memoryUsage() and its siblings, and an Error's
//     stack property are server state when a response body carries them.
//
// A condition on process.env.NODE_ENV that dominates the operation is recorded
// as a guard. Guards are evidence, never a filter.

var exposureRegistrationMethods = map[string]bool{"use": true, "get": true, "post": true, "put": true, "patch": true, "delete": true, "all": true}
var exposureResponseMethods = map[string]bool{"send": true, "end": true, "json": true, "jsonp": true, "write": true}
var processStateCalls = map[string]bool{"memoryUsage": true, "cpuUsage": true, "resourceUsage": true}

type exposureOp struct {
	operation, subject string
	at                 *sitter.Node // the operation node (evidence "diagnostic_operation")
	sink               *sitter.Node // the sink anchor
	receiver           string       // the registering receiver, for a middleware registration
}

// exposureCandidates records the D-8 operations of every selected module.
// It runs after entries and mounts exist.
func (s *moduleSet) exposureCandidates(out *analysis.AnalysisReport, selected []string) {
	for _, file := range selected {
		m := s.modules[file]
		if m == nil || m.tree.RootNode().HasError() {
			continue
		}
		walkCalls(m.tree.RootNode(), func(call *sitter.Node) {
			for _, op := range s.exposureOps(m, call) {
				s.recordExposure(out, m, op)
			}
		})
	}
}

func (s *moduleSet) exposureOps(m *sourceModule, call *sitter.Node) []exposureOp {
	fn, args := call.ChildByFieldName("function"), call.ChildByFieldName("arguments")
	if fn == nil || args == nil || fn.Kind() != "member_expression" {
		return nil
	}
	obj, prop := fn.ChildByFieldName("object"), fn.ChildByFieldName("property")
	if obj == nil || prop == nil {
		return nil
	}
	name := prop.Utf8Text(m.src)
	var ops []exposureOp
	if exposureRegistrationMethods[name] && obj.Kind() == "identifier" && receiverUsable(m, call, obj.Utf8Text(m.src)) {
		for i := uint(0); i < args.NamedChildCount(); i++ {
			arg := args.NamedChild(i)
			switch {
			case libraryCall(m, arg, "errorhandler", ""):
				ops = append(ops, exposureOp{"errorhandler", analysis.ExposureStack, arg, call, obj.Utf8Text(m.src)})
			case libraryCall(m, arg, "swagger-ui-express", "setup"):
				ops = append(ops, exposureOp{"swagger-ui-express.setup", analysis.ExposureConfiguration, arg, call, obj.Utf8Text(m.src)})
			}
		}
		return ops
	}
	if exposureResponseMethods[name] && args.NamedChildCount() > 0 {
		handler := enclosingFunction(call)
		if handler == nil {
			return nil
		}
		params := plainParameters(handler, m.src)
		if len(params) < 2 || chainRoot(fn, m.src) != params[1] {
			return nil
		}
		arg := args.NamedChild(0)
		if arg.Kind() == "await_expression" && arg.NamedChildCount() == 1 {
			arg = arg.NamedChild(0)
		}
		if op, ok := s.stateOperand(m, call, arg); ok {
			op.at, op.sink = arg, call
			return []exposureOp{op}
		}
	}
	return nil
}

// stateOperand classifies a response body that is server state.
func (s *moduleSet) stateOperand(m *sourceModule, at, arg *sitter.Node) (exposureOp, bool) {
	switch arg.Kind() {
	case "call_expression":
		fn := arg.ChildByFieldName("function")
		if fn == nil || fn.Kind() != "member_expression" {
			return exposureOp{}, false
		}
		obj, prop := fn.ChildByFieldName("object"), fn.ChildByFieldName("property")
		if obj == nil || prop == nil {
			return exposureOp{}, false
		}
		switch method := prop.Utf8Text(m.src); {
		case method == "metrics" && promRegister(m, obj, 0):
			return exposureOp{operation: "prom-client.metrics", subject: analysis.ExposureRuntimeState}, true
		case processStateCalls[method] && processObject(m, at, obj):
			return exposureOp{operation: "process." + method, subject: analysis.ExposureRuntimeState}, true
		}
	case "member_expression":
		obj, prop := arg.ChildByFieldName("object"), arg.ChildByFieldName("property")
		if obj == nil || prop == nil {
			return exposureOp{}, false
		}
		switch member := prop.Utf8Text(m.src); {
		case member == "env" && processObject(m, at, obj):
			return exposureOp{operation: "process.env", subject: analysis.ExposureEnvironment}, true
		case member == "versions" && processObject(m, at, obj):
			return exposureOp{operation: "process.versions", subject: analysis.ExposureRuntimeState}, true
		case member == "stack" && obj.Kind() == "identifier" && catchParameter(at, obj.Utf8Text(m.src), m.src):
			return exposureOp{operation: "error.stack", subject: analysis.ExposureStack}, true
		}
	}
	return exposureOp{}, false
}

// libraryCall reports whether n is a call of the default (or namespace)
// export of module, or of its member when member is set.
func libraryCall(m *sourceModule, n *sitter.Node, module, member string) bool {
	if n == nil || n.Kind() != "call_expression" {
		return false
	}
	fn := n.ChildByFieldName("function")
	if fn == nil {
		return false
	}
	if member == "" {
		if fn.Kind() != "identifier" || shadowed(n, fn.Utf8Text(m.src), m.src) {
			return false
		}
		imp, ok := m.imports[fn.Utf8Text(m.src)]
		return ok && imp.module == module && (imp.name == "default" || imp.name == "*") && !bindingReassigned(m, fn.Utf8Text(m.src))
	}
	if fn.Kind() != "member_expression" {
		return false
	}
	obj, prop := fn.ChildByFieldName("object"), fn.ChildByFieldName("property")
	if obj == nil || prop == nil || obj.Kind() != "identifier" || prop.Utf8Text(m.src) != member || shadowed(n, obj.Utf8Text(m.src), m.src) {
		return false
	}
	imp, ok := m.imports[obj.Utf8Text(m.src)]
	return ok && imp.module == module && (imp.name == "default" || imp.name == "*") && !bindingReassigned(m, obj.Utf8Text(m.src))
}

// promRegister reports whether n is prom-client's global registry: the
// `register` export, the member of the module object, or a constant bound to
// either one step away.
func promRegister(m *sourceModule, n *sitter.Node, depth int) bool {
	switch n.Kind() {
	case "identifier":
		name := n.Utf8Text(m.src)
		if imp, ok := m.imports[name]; ok && topVariable(m, name) == nil {
			return imp.module == "prom-client" && imp.name == "register" && !bindingReassigned(m, name)
		}
		if depth == 0 {
			if v := unwrapTS(topVariable(m, name)); v != nil && !bindingReassigned(m, name) {
				return promRegister(m, v, depth+1)
			}
		}
	case "member_expression":
		obj, prop := n.ChildByFieldName("object"), n.ChildByFieldName("property")
		if obj == nil || prop == nil || obj.Kind() != "identifier" || prop.Utf8Text(m.src) != "register" {
			return false
		}
		imp, ok := m.imports[obj.Utf8Text(m.src)]
		return ok && imp.module == "prom-client" && (imp.name == "default" || imp.name == "*") && !bindingReassigned(m, obj.Utf8Text(m.src))
	}
	return false
}

// processObject reports whether n is the Node.js global process object: the
// identifier is not declared or imported anywhere in the module.
func processObject(m *sourceModule, at, n *sitter.Node) bool {
	if n.Kind() != "identifier" || n.Utf8Text(m.src) != "process" {
		return false
	}
	if _, imported := m.imports["process"]; imported || moduleBinds(m, "process") {
		return false
	}
	return !shadowed(at, "process", m.src)
}

// catchParameter reports whether name is the parameter of a catch clause that
// encloses n.
func catchParameter(n *sitter.Node, name string, src []byte) bool {
	for p := n.Parent(); p != nil; p = p.Parent() {
		if p.Kind() == "catch_clause" {
			if param := p.ChildByFieldName("parameter"); param != nil && param.Kind() == "identifier" && param.Utf8Text(src) == name {
				return true
			}
		}
	}
	return false
}

// environmentGuards returns the conditions on the environment mode that
// dominate n, as guard evidence: process.env.NODE_ENV, or the Express
// application setting read by app.get('env') (Express API, "Application
// Settings": env is process.env.NODE_ENV, or "development" when it is unset).
func environmentGuards(m *sourceModule, n *sitter.Node) []analysis.Evidence {
	var guards []analysis.Evidence
	child := n
	for p := n.Parent(); p != nil; child, p = p, p.Parent() {
		if p.Kind() != "if_statement" {
			continue
		}
		cond := p.ChildByFieldName("condition")
		if cond == nil || cond.StartByte() <= child.StartByte() && child.EndByte() <= cond.EndByte() {
			continue
		}
		if mentionsNodeEnv(m, cond) {
			guards = append(guards, m.evidence("configuration_precondition", cond))
		}
	}
	return guards
}

func mentionsNodeEnv(m *sourceModule, n *sitter.Node) bool {
	found := false
	var walk func(*sitter.Node)
	walk = func(x *sitter.Node) {
		if x == nil || found {
			return
		}
		if x.Kind() == "member_expression" && x.Utf8Text(m.src) == "process.env.NODE_ENV" {
			found = true
			return
		}
		if x.Kind() == "call_expression" && expressEnvSetting(m, x) {
			found = true
			return
		}
		for i := uint(0); i < x.NamedChildCount(); i++ {
			walk(x.NamedChild(i))
		}
	}
	walk(n)
	return found
}

// expressEnvSetting reports a call receiver.get('env') on a verified Express
// application.
func expressEnvSetting(m *sourceModule, call *sitter.Node) bool {
	fn, args := call.ChildByFieldName("function"), call.ChildByFieldName("arguments")
	if fn == nil || args == nil || fn.Kind() != "member_expression" || args.NamedChildCount() != 1 {
		return false
	}
	obj, prop := fn.ChildByFieldName("object"), fn.ChildByFieldName("property")
	if obj == nil || prop == nil || obj.Kind() != "identifier" || prop.Utf8Text(m.src) != "get" || !receiverUsable(m, call, obj.Utf8Text(m.src)) {
		return false
	}
	name, ok := stringLiteral(args.NamedChild(0), m.src)
	return ok && name == "env"
}

// recordExposure emits one candidate per operation per entry.
func (s *moduleSet) recordExposure(out *analysis.AnalysisReport, m *sourceModule, op exposureOp) {
	entries := s.entriesFor(out, m, op.sink)
	if len(entries) == 0 && op.receiver != "" {
		entries = s.mountEntry(out, m, op.sink, op.receiver)
	}
	if len(entries) == 0 {
		out.Gaps = append(out.Gaps, analysis.Gap{Kind: "exposure_entry_missing", Detail: "a diagnostic operation was read and no HTTP entry carries it", At: m.evidence("diagnostic_operation", op.sink).Span})
		return
	}
	sink := m.evidence(analysis.ExposureKind, op.sink)
	operation := m.evidence("diagnostic_operation", op.at)
	guards := environmentGuards(m, op.sink)
	for _, e := range entries {
		facts := analysis.ExposureFacts{Operation: op.operation, Subject: op.subject, EntryServed: "yes", Guards: slices.Clone(guards)}
		entryEvidence := []analysis.Evidence{e.Location}
		flowEvidence := append([]analysis.Evidence{asEvidenceKind(sink, "operation")}, guards...)
		evidence := map[string][]analysis.Evidence{
			"diagnostic_operation": {operation},
			"entry":                entryEvidence,
			"control_flow":         flowEvidence,
			"sink_binding":         {asEvidenceKind(sink, "sink_binding")},
		}
		// A mount entry has no handler callable; its registration is the
		// dispatch the claim rests on.
		evidence["dispatch_binding"] = entryEvidence
		if len(guards) > 0 {
			evidence["guard"] = guards
		}
		out.Uses = append(out.Uses, analysis.CandidateUse{
			EntryID: e.ID, Kind: analysis.ExposureKind, Sink: sink, Exposure: &facts,
			APIModel:   analysispacks.ExposureContract(analysispacks.NodeDiagnosticOutput),
			Assessment: analysis.Assessment{Status: "not_run"},
			Completeness: &analysis.Completeness{
				ClaimKind: "exposure", Required: analysispacks.ExposureRoles(),
				Scope:    "Verified diagnostic operation, its entry and its dominating conditions; no request source.",
				Evidence: evidence, Blockers: []analysis.Gap{}, Coverage: []analysis.Gap{},
			},
		})
	}
}

func asEvidenceKind(e analysis.Evidence, kind string) analysis.Evidence {
	e.Kind = kind
	return e
}

// entriesFor returns the HTTP entries that carry a node: the entries a
// registration call created, or the entries whose handler callable contains
// the node. The result is sorted by entry ID.
func (s *moduleSet) entriesFor(out *analysis.AnalysisReport, m *sourceModule, node *sitter.Node) []analysis.EntryPoint {
	byID := map[string]analysis.EntryPoint{}
	for _, e := range out.Entries {
		if e.Kind != "http" {
			continue
		}
		span := e.Location.Span
		if span.File == m.file && span.StartByte == int(node.StartByte()) && span.EndByte == int(node.EndByte()) {
			byID[e.ID] = e
		}
	}
	if len(byID) == 0 {
		callables := map[string]analysis.Callable{}
		for _, c := range out.Callables {
			def := c.Definition.Span
			if def.File == m.file && def.StartByte <= int(node.StartByte()) && int(node.EndByte()) <= def.EndByte {
				callables[c.ID] = c
			}
		}
		entries := map[string]analysis.EntryPoint{}
		for _, e := range out.Entries {
			entries[e.ID] = e
		}
		for _, b := range out.DispatchBindings {
			if _, ok := callables[b.CallableID]; ok {
				if e, ok := entries[b.EntryID]; ok && e.Kind == "http" {
					byID[e.ID] = e
				}
			}
		}
	}
	var list []analysis.EntryPoint
	for _, e := range byID {
		list = append(list, e)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	return list
}

// mountEntry registers the USE entry of a middleware registration that names
// no path (app.use(middleware())). Such a call is middleware for every route,
// not a route, so the route inventory has no entry for it; a claim about the
// middleware needs one to ride. It is created only for a registration that
// carries a recorded diagnostic operation, and the entry's access record is
// computed like a route's (D-2): the mount's access is the entry's.
func (s *moduleSet) mountEntry(out *analysis.AnalysisReport, m *sourceModule, call *sitter.Node, receiver string) []analysis.EntryPoint {
	reg := m.evidence("entry_registration", call)
	route := analysis.Route{
		ID: fmt.Sprintf("route:%s:%d:USE:/", m.file, call.StartByte()), Method: "USE", PathPattern: "/",
		Framework: "express", Registration: reg.Span,
	}
	e := parse.HTTPEntry(route, reg, m.file+":"+m.hash+":"+receiver)
	e.HTTP.Receiver, e.HTTP.SourcePath = receiver, "/"
	e.Gaps = []analysis.Gap{}
	if access := s.expressAccess(m, call, "/", nil); access.Authentication != analysis.AccessNone {
		e.Access = &access
	}
	parse.RegisterInvocation(out, e, nil, "direct_registration", nil, e.Gaps)
	return []analysis.EntryPoint{out.Entries[len(out.Entries)-1]}
}
