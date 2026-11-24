package langjs

import (
	"fmt"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
	"github.com/zazzcode/zazzles/scan/internal/parse"
)

// Generated REST resources (lane decision D-5). A `resource({ model, endpoints })`
// call of finale-rest (or its predecessor epilogue) generates handlers for the
// model. The library documentation
// (https://github.com/tommybananas/finale#readme, "Controllers and endpoints"
// and "resource()") gives:
//
//   - create: POST endpoints[0]; update: PUT endpoints[1] (the method is
//     `updateMethod` of initialize(), PUT by default); delete: DELETE endpoints[1];
//   - `actions` restricts which of the actions are created; the default is all;
//   - `excludeAttributes` removes attributes "from read and list operations".
//     It is recorded as an option of the call and is not a limit on what a
//     create or update writes.
//
// Each generated create and update records a mass-assignment candidate, and
// each generated update and delete an authorization candidate whose selector
// is the :id route parameter. A resource whose model or endpoints cannot be
// resolved from a literal, or from a loop over a literal array, records a gap
// and no candidate. The generated entry carries the access of the chain
// registered for its method and path before the call.

type generatedEndpoint struct {
	method, path, action string
}

func (s *moduleSet) generatedResources(out *analysis.AnalysisReport, selected []string) {
	for _, file := range selected {
		m := s.modules[file]
		if m == nil || m.tree.RootNode().HasError() {
			continue
		}
		updateMethod := "PUT"
		walkCalls(m.tree.RootNode(), func(call *sitter.Node) {
			if libraryMember(m, call, []string{"finale-rest", "epilogue"}, "initialize") {
				if o := objectOf(m, firstArg(call.ChildByFieldName("arguments"))); o != nil {
					if v := property(o, "updateMethod", m.src); v != nil {
						if lit, ok := stringLiteral(v, m.src); ok {
							updateMethod = strings.ToUpper(lit)
						}
					}
				}
			}
		})
		walkCalls(m.tree.RootNode(), func(call *sitter.Node) {
			if !libraryMember(m, call, []string{"finale-rest", "epilogue"}, "resource") {
				return
			}
			s.generatedResource(out, m, call, updateMethod)
		})
	}
}

// libraryMember reports a call `X.member(...)` where X is the default or
// namespace export of one of the modules.
func libraryMember(m *sourceModule, call *sitter.Node, modules []string, member string) bool {
	fn := call.ChildByFieldName("function")
	if fn == nil || fn.Kind() != "member_expression" || memberName(m, fn) != member {
		return false
	}
	obj := fn.ChildByFieldName("object")
	if obj == nil || obj.Kind() != "identifier" || shadowed(call, obj.Utf8Text(m.src), m.src) {
		return false
	}
	imp, ok := m.imports[obj.Utf8Text(m.src)]
	if !ok || (imp.name != "default" && imp.name != "*") {
		return false
	}
	for _, mod := range modules {
		if imp.module == mod {
			return true
		}
	}
	return false
}

func (s *moduleSet) generatedResource(out *analysis.AnalysisReport, m *sourceModule, call *sitter.Node, updateMethod string) {
	unresolved := func(detail string) {
		out.Gaps = append(out.Gaps, analysis.Gap{Kind: "generated_resource_unresolved", Detail: detail, At: m.evidence("generated_resource", call).Span})
	}
	opts := objectOf(m, firstArg(call.ChildByFieldName("arguments")))
	if opts == nil {
		unresolved("the resource options are not an object literal")
		return
	}
	modelNode, endpointsNode := propertyOrShorthand(opts, "model", m.src), propertyOrShorthand(opts, "endpoints", m.src)
	if modelNode == nil || endpointsNode == nil {
		unresolved("the resource options lack a model or endpoints")
		return
	}
	actions := map[string]bool{"create": true, "list": true, "read": true, "update": true, "delete": true}
	if a := property(opts, "actions", m.src); a != nil {
		list, ok := literalStrings(m, unwrapTS(a))
		if !ok {
			unresolved("actions is not a literal array")
			return
		}
		actions = map[string]bool{}
		for _, x := range list {
			actions[x] = true
		}
	}
	for _, env := range s.loopBindings(m, call) {
		model, ok := resolveName(m, modelNode, env)
		if !ok {
			unresolved("the model is not an identifier or a binding of a loop over a literal array")
			continue
		}
		info, ok := s.modelAttributes(m, model)
		if !ok || info.kind != "sequelize" {
			unresolved("the model is not a verified Sequelize model")
			continue
		}
		endpoints, ok := resolveStrings(m, endpointsNode, env)
		if !ok || len(endpoints) != 2 {
			unresolved("endpoints is not two literal paths")
			continue
		}
		plural, singular := endpoints[0], endpoints[1]
		var eps []generatedEndpoint
		if actions["create"] {
			eps = append(eps, generatedEndpoint{"POST", plural, "create"})
		}
		if actions["update"] {
			eps = append(eps, generatedEndpoint{updateMethod, singular, "update"})
		}
		if actions["delete"] {
			eps = append(eps, generatedEndpoint{"DELETE", singular, "delete"})
		}
		for _, ep := range eps {
			access, chain := s.generatedAccess(m, call, ep)
			if access.RejectsAll {
				// No request reaches the generated handler through this
				// endpoint, so it makes no claim.
				continue
			}
			entry := s.generatedEntry(out, m, call, ep, access)
			if ep.action == "create" || ep.action == "update" {
				note := "finale-rest " + ep.action + " writes each field of the request body to the model attribute of the same name; the request chooses the attribute names."
				writable, extra := info, []analysis.Evidence(nil)
				if over := s.overwrittenFields(m, chain); len(over) > 0 {
					writable.attrs = nil
					for _, a := range info.attrs {
						if ev, ok := over[a.name]; ok {
							extra = append(extra, ev)
							continue
						}
						writable.attrs = append(writable.attrs, a)
					}
					note += " A middleware registered for this endpoint overwrites some request fields before the write; those attributes are not request-chosen and are left out."
				}
				s.recordMass(out, entry, m, call, call, writable, extra, note)
			}
			if ep.action == "update" || ep.action == "delete" {
				s.recordGeneratedAuthorization(out, entry, m, call, info, ep)
			}
		}
	}
}

// loopBindings returns the environments a resource call runs under: one per
// element of an enclosing for-of loop over a literal array of object literals,
// or a single empty environment when the call is not in such a loop.
func (s *moduleSet) loopBindings(m *sourceModule, call *sitter.Node) []map[string]*sitter.Node {
	for p := call.Parent(); p != nil; p = p.Parent() {
		if p.Kind() != "for_in_statement" {
			continue
		}
		left, right := p.ChildByFieldName("left"), p.ChildByFieldName("right")
		if left == nil || right == nil || p.ChildByFieldName("operator") == nil || p.ChildByFieldName("operator").Utf8Text(m.src) != "of" {
			continue
		}
		pattern := left
		if pattern.Kind() != "object_pattern" {
			pattern = nil
			for i := uint(0); i < left.NamedChildCount(); i++ {
				if c := left.NamedChild(i); c.Kind() == "object_pattern" {
					pattern = c
				}
			}
		}
		arr := unwrapTS(right)
		if arr != nil && arr.Kind() == "identifier" && !bindingReassigned(m, arr.Utf8Text(m.src)) {
			name := arr.Utf8Text(m.src)
			if local := unwrapTS(localConst(m, arr, name)); local != nil {
				arr = local
			} else {
				arr = unwrapTS(topVariable(m, name))
			}
		}
		if pattern == nil || arr == nil || arr.Kind() != "array" {
			return nil
		}
		var envs []map[string]*sitter.Node
		for i := uint(0); i < arr.NamedChildCount(); i++ {
			elem := unwrapTS(arr.NamedChild(i))
			if elem == nil || elem.Kind() != "object" {
				return nil
			}
			env := map[string]*sitter.Node{}
			for j := uint(0); j < pattern.NamedChildCount(); j++ {
				c := pattern.NamedChild(j)
				if c.Kind() == "shorthand_property_identifier_pattern" {
					if v := property(elem, c.Utf8Text(m.src), m.src); v != nil {
						env[c.Utf8Text(m.src)] = v
					}
				}
			}
			envs = append(envs, env)
		}
		return envs
	}
	return []map[string]*sitter.Node{{}}
}

// resolveName resolves a model reference: an identifier bound by the loop to an
// identifier, or a plain identifier.
func resolveName(m *sourceModule, n *sitter.Node, env map[string]*sitter.Node) (string, bool) {
	n = unwrapTS(n)
	if n == nil || (n.Kind() != "identifier" && n.Kind() != "shorthand_property_identifier") {
		return "", false
	}
	name := n.Utf8Text(m.src)
	if v, ok := env[name]; ok {
		if v = unwrapTS(v); v != nil && v.Kind() == "identifier" {
			return v.Utf8Text(m.src), true
		}
		return "", false
	}
	return name, true
}

func resolveStrings(m *sourceModule, n *sitter.Node, env map[string]*sitter.Node) ([]string, bool) {
	n = unwrapTS(n)
	if n == nil || n.Kind() != "array" {
		return nil, false
	}
	var out []string
	for i := uint(0); i < n.NamedChildCount(); i++ {
		c := n.NamedChild(i)
		if c.Kind() == "comment" {
			continue
		}
		v, ok := resolveString(m, c, env)
		if !ok {
			return nil, false
		}
		out = append(out, v)
	}
	return out, true
}

func resolveString(m *sourceModule, n *sitter.Node, env map[string]*sitter.Node) (string, bool) {
	n = unwrapTS(n)
	if n == nil {
		return "", false
	}
	if lit, ok := stringLiteral(n, m.src); ok {
		return lit, true
	}
	switch n.Kind() {
	case "identifier":
		if v, ok := env[n.Utf8Text(m.src)]; ok {
			return resolveString(m, v, nil)
		}
	case "template_string":
		var b strings.Builder
		for i := uint(0); i < n.ChildCount(); i++ {
			c := n.Child(i)
			switch c.Kind() {
			case "`":
			case "template_substitution":
				if c.NamedChildCount() != 1 {
					return "", false
				}
				v, ok := resolveString(m, c.NamedChild(0), env)
				if !ok {
					return "", false
				}
				b.WriteString(v)
			default:
				b.WriteString(c.Utf8Text(m.src))
			}
		}
		return b.String(), true
	}
	return "", false
}

func literalStrings(m *sourceModule, n *sitter.Node) ([]string, bool) {
	if n == nil || n.Kind() != "array" {
		return nil, false
	}
	var out []string
	for i := uint(0); i < n.NamedChildCount(); i++ {
		c := n.NamedChild(i)
		if c.Kind() == "comment" {
			continue
		}
		v, ok := stringLiteral(c, m.src)
		if !ok {
			return nil, false
		}
		out = append(out, v)
	}
	return out, true
}

// generatedEntry registers the HTTP entry of a generated endpoint, anchored at
// the resource call, with the access of the chain registered for its method
// and path before the call.
func (s *moduleSet) generatedEntry(out *analysis.AnalysisReport, m *sourceModule, call *sitter.Node, ep generatedEndpoint, access analysis.EntryAccess) analysis.EntryPoint {
	reg := m.evidence("entry_registration", call)
	route := analysis.Route{
		ID: fmt.Sprintf("route:%s:%d:%s:%s", m.file, call.StartByte(), ep.method, ep.path), Method: ep.method, PathPattern: ep.path,
		Framework: "express", Registration: reg.Span,
	}
	e := parse.HTTPEntry(route, reg, m.file+":"+m.hash+":generated")
	e.HTTP.SourcePath = ep.path
	e.Gaps = []analysis.Gap{}
	if access.Authentication != analysis.AccessNone {
		e.Access = &access
	}
	parse.RegisterInvocation(out, e, nil, "direct_registration", nil, e.Gaps)
	return out.Entries[len(out.Entries)-1]
}

// generatedAccess reads the chain registered for the endpoint: earlier app.use
// calls that cover the path, and earlier registrations of the same method and
// path, written as app.post(path, middleware) or as a method of an
// app.route(path) chain. It also returns those middleware argument nodes.
func (s *moduleSet) generatedAccess(m *sourceModule, call *sitter.Node, ep generatedEndpoint) (analysis.EntryAccess, []*sitter.Node) {
	var extra []*sitter.Node
	walkCalls(m.tree.RootNode(), func(reg *sitter.Node) {
		if reg.StartByte() >= call.StartByte() {
			return
		}
		fn, args := reg.ChildByFieldName("function"), reg.ChildByFieldName("arguments")
		if fn == nil || args == nil || fn.Kind() != "member_expression" {
			return
		}
		obj, prop := fn.ChildByFieldName("object"), fn.ChildByFieldName("property")
		if obj == nil || prop == nil {
			return
		}
		method := strings.ToUpper(prop.Utf8Text(m.src))
		if method != ep.method && method != "ALL" {
			return
		}
		first := uint(1)
		switch obj.Kind() {
		case "identifier":
			if args.NamedChildCount() < 2 || !receiverUsable(m, reg, obj.Utf8Text(m.src)) {
				return
			}
			if path, ok := stringLiteral(args.NamedChild(0), m.src); !ok || path != ep.path {
				return
			}
		case "call_expression":
			// receiver.route(path).get(a).put(b): every argument is middleware.
			if path, ok := routeChainPath(m, obj); !ok || path != ep.path {
				return
			}
			first = 0
		default:
			return
		}
		for i := first; i < args.NamedChildCount(); i++ {
			extra = append(extra, args.NamedChild(i))
		}
	})
	return s.expressAccessForNodes(m, call, ep.path, nil, 0, 0, extra), extra
}

// routeChainPath returns the literal path of the receiver.route(path) call at
// the base of a chain of method calls.
func routeChainPath(m *sourceModule, n *sitter.Node) (string, bool) {
	for n != nil && n.Kind() == "call_expression" {
		fn, args := n.ChildByFieldName("function"), n.ChildByFieldName("arguments")
		if fn == nil || fn.Kind() != "member_expression" {
			return "", false
		}
		obj, prop := fn.ChildByFieldName("object"), fn.ChildByFieldName("property")
		if obj == nil || prop == nil {
			return "", false
		}
		if obj.Kind() == "identifier" {
			if prop.Utf8Text(m.src) != "route" || args == nil || args.NamedChildCount() != 1 || !receiverUsable(m, n, obj.Utf8Text(m.src)) {
				return "", false
			}
			return stringLiteral(args.NamedChild(0), m.src)
		}
		n = obj
	}
	return "", false
}

func (s *moduleSet) recordGeneratedAuthorization(out *analysis.AnalysisReport, e analysis.EntryPoint, m *sourceModule, call *sitter.Node, info modelInfo, ep generatedEndpoint) {
	sink := m.evidence(analysis.AuthorizationKind, call)
	selection := m.evidence("subject_selection", call)
	selection.ModelText = "route placeholder"
	operation := m.evidence("protected_operation", call)
	operation.ModelText = "finale-rest " + ep.action + " acts on the row of the model that the :id route parameter selects"
	access, _ := expressEntryAccess(e)
	accessEvidence := append([]analysis.Evidence{}, access.Sources...)
	if len(accessEvidence) == 0 {
		accessEvidence = []analysis.Evidence{e.Location}
	}
	op := "update"
	if ep.action == "delete" {
		op = "delete"
	}
	facts := &analysis.AuthorizationFacts{
		Facets: []string{analysis.FacetObjectLevel}, SubjectClass: "model:" + info.class, SubjectProvenance: analysis.SubjectRequestSelected,
		Operation:      analysis.StateChange{StorageKey: "js-model:" + info.class, Operation: op, Span: sink.Span},
		SecurityFields: []analysis.SecurityFieldFact{}, Guards: []analysis.AuthorizationGuard{}, MethodSafe: "no",
	}
	if op == "update" {
		// A generated update writes the attributes the request body names.
		facts.Written = &analysis.WrittenValues{RequestDependent: "yes"}
	}
	out.Uses = append(out.Uses, analysis.CandidateUse{
		EntryID: e.ID, Kind: analysis.AuthorizationKind, Sink: sink, Authorization: facts,
		Dependencies: []analysis.Dependency{{Source: asEvidenceKind(selection, "input_source")}},
		APIModel:     analysispacks.AuthorizationContract(analysispacks.NodeAuthorizationOperation),
		Gaps:         []analysis.Gap{}, Assessment: analysis.Assessment{Status: "not_run"},
		Completeness: &analysis.Completeness{
			ClaimKind: "authorization", Required: analysispacks.AuthorizationRoles(),
			Scope: "One protected operation, the keys that select its record, the entry's access and the conditions that dominate it.",
			Evidence: map[string][]analysis.Evidence{
				"subject_selection": {selection}, "protected_operation": {operation}, "entry_access": accessEvidence,
				"control_flow": {asEvidenceKind(sink, "operation")}, "sink_binding": {asEvidenceKind(sink, "sink_binding")},
				"dispatch_binding": {e.Location},
			},
			Blockers: []analysis.Gap{}, Coverage: []analysis.Gap{},
		},
	})
}

// propertyOrShorthand returns the value of an object property, or the
// identifier of a shorthand property `{ name }`.
func propertyOrShorthand(obj *sitter.Node, name string, src []byte) *sitter.Node {
	if v := property(obj, name, src); v != nil {
		return v
	}
	for i := uint(0); i < obj.NamedChildCount(); i++ {
		if c := obj.NamedChild(i); c.Kind() == "shorthand_property_identifier" && c.Utf8Text(src) == name {
			return c
		}
	}
	return nil
}
