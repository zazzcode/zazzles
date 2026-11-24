package langjs

import (
	"fmt"
	"sort"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
	"github.com/zazzcode/zazzles/scan/internal/parse"
)

// Object-level authorization for Express (lane decision D-3). A candidate is a
// state change on a record the request selects:
//
//   - a Sequelize Model.update, destroy, increment or decrement with a where
//     option (https://sequelize.org/docs/v6/core-concepts/model-querying-basics/),
//   - an update, destroy or save on an instance that findByPk or findOne
//     returned for a request-selected key,
//   - an update or remove on a Mongo-style collection that the nosql family
//     already models.
//
// A key of the selector carries a request value that reaches it without a
// server-side lookup. A second key whose value is not the request's (a lookup
// result, or a request field that a middleware on the entry's chain overwrites
// before the handler) is recorded as an ownership_check guard in the
// query_scope form. Guards never suppress the record. Reads are not covered.
var sequelizeStaticWrites = map[string]string{"update": "update", "destroy": "delete", "increment": "update", "decrement": "update"}
var instanceWrites = map[string]string{"update": "update", "destroy": "delete", "save": "update"}
var collectionWrites = map[string]string{"update": "update", "remove": "delete"}

type authzSelector struct {
	subject   string
	operation string
	call      *sitter.Node
	pairs     map[string]*sitter.Node // selector key -> value node
	order     []string
}

func (s *moduleSet) authorizationCandidates(out *analysis.AnalysisReport) {
	callables := map[string]analysis.Callable{}
	for _, c := range out.Callables {
		callables[c.ID] = c
	}
	bindings := map[string]string{}
	for _, b := range out.DispatchBindings {
		bindings[b.EntryID] = b.CallableID
	}
	nosqlCalls := map[string]bool{}
	for _, u := range out.Uses {
		if u.Kind == "nosql_query_candidate" {
			nosqlCalls[authzSpanKey(u.Sink.Span)] = true
		}
	}
	entries := append([]analysis.EntryPoint{}, out.Entries...)
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	for _, e := range entries {
		if e.Kind != "http" || e.HTTP == nil || e.HTTP.Method == "USE" || e.HTTP.Framework != "express" {
			continue
		}
		if e.Access != nil && e.Access.RejectsAll {
			continue
		}
		def := callables[bindings[e.ID]].Definition.Span
		m := s.modules[def.File]
		if m == nil || def.File == "" {
			continue
		}
		node := parse.NodeAt(m.tree.RootNode(), def.StartByte, def.EndByte)
		if node == nil {
			continue
		}
		fn, body := handlerFunction(node)
		if body == nil || fn == nil {
			continue
		}
		params := plainOrDestructuredParameters(fn, m.src)
		overwritten := s.chainOverwrites(out, e)
		walkCalls(body, func(call *sitter.Node) {
			if f := enclosingFunction(call); f != nil && f.StartByte() != fn.StartByte() {
				return
			}
			sel, ok := s.authzSelectorOf(m, call, params, nosqlCalls)
			if !ok {
				if read, found := s.authzReadOf(m, fn, call, params); found && !instanceWritten(m, fn, call) {
					s.recordAuthorizationRead(out, e, m, params, overwritten, read)
				}
				return
			}
			s.recordAuthorization(out, e, m, params, overwritten, sel)
		})
	}
}

func authzSpanKey(sp analysis.Span) string {
	return fmt.Sprintf("%s:%d:%d", sp.File, sp.StartByte, sp.EndByte)
}

// authzSelectorOf recognizes a protected operation and its selector.
func (s *moduleSet) authzSelectorOf(m *sourceModule, call *sitter.Node, p handlerParams, nosqlCalls map[string]bool) (authzSelector, bool) {
	fn, args := call.ChildByFieldName("function"), call.ChildByFieldName("arguments")
	if fn == nil || args == nil || fn.Kind() != "member_expression" {
		return authzSelector{}, false
	}
	obj := fn.ChildByFieldName("object")
	if obj == nil {
		return authzSelector{}, false
	}
	method := memberName(m, fn)
	// Mongo-style collection write, on a call the nosql family records.
	if op, ok := collectionWrites[method]; ok && nosqlCalls[authzSpanKey(m.evidence("x", call).Span)] && firstArg(args) != nil {
		name := obj.Utf8Text(m.src)
		if i := strings.LastIndex(name, "."); i >= 0 {
			name = name[i+1:]
		}
		return selectorFrom(m, "collection:"+name, op, call, firstArg(args)), true
	}
	if obj.Kind() != "identifier" {
		return authzSelector{}, false
	}
	name := obj.Utf8Text(m.src)
	// Sequelize static write on a verified model.
	if op, ok := sequelizeStaticWrites[method]; ok && !shadowed(call, name, m.src) && strings.HasPrefix(s.modelIdentity(m, name, 0), "sequelize:") {
		for i := uint(0); i < args.NamedChildCount(); i++ {
			if o := unwrapTS(args.NamedChild(i)); o != nil && o.Kind() == "object" {
				if w := property(o, "where", m.src); w != nil {
					return selectorFrom(m, "model:"+name, op, call, w), true
				}
			}
		}
		return authzSelector{}, false
	}
	// Instance write on a record that findByPk or findOne returned.
	if op, ok := instanceWrites[method]; ok {
		init := unwrapTS(localConst(m, call, name))
		if init != nil && init.Kind() == "await_expression" && init.NamedChildCount() == 1 {
			init = init.NamedChild(0)
		}
		if init == nil || init.Kind() != "call_expression" {
			return authzSelector{}, false
		}
		ifn, iargs := init.ChildByFieldName("function"), init.ChildByFieldName("arguments")
		if ifn == nil || iargs == nil || ifn.Kind() != "member_expression" || firstArg(iargs) == nil {
			return authzSelector{}, false
		}
		model := ifn.ChildByFieldName("object")
		if model == nil || model.Kind() != "identifier" || shadowed(init, model.Utf8Text(m.src), m.src) || !strings.HasPrefix(s.modelIdentity(m, model.Utf8Text(m.src), 0), "sequelize:") {
			return authzSelector{}, false
		}
		switch memberName(m, ifn) {
		case "findByPk":
			sel := authzSelector{subject: "model:" + model.Utf8Text(m.src), operation: op, call: call, pairs: map[string]*sitter.Node{"primary key": firstArg(iargs)}, order: []string{"primary key"}}
			return sel, true
		case "findOne":
			if o := unwrapTS(firstArg(iargs)); o != nil && o.Kind() == "object" {
				if w := property(o, "where", m.src); w != nil {
					return selectorFrom(m, "model:"+model.Utf8Text(m.src), op, call, w), true
				}
			}
		}
	}
	return authzSelector{}, false
}

func selectorFrom(m *sourceModule, subject, op string, call, sel *sitter.Node) authzSelector {
	out := authzSelector{subject: subject, operation: op, call: call, pairs: map[string]*sitter.Node{}}
	obj := unwrapTS(sel)
	if obj == nil || obj.Kind() != "object" {
		return out
	}
	for i := uint(0); i < obj.NamedChildCount(); i++ {
		c := obj.NamedChild(i)
		switch c.Kind() {
		case "pair":
			if k, v := c.ChildByFieldName("key"), c.ChildByFieldName("value"); k != nil && v != nil {
				key := strings.Trim(k.Utf8Text(m.src), `"'`)
				out.pairs[key] = v
				out.order = append(out.order, key)
			}
		case "shorthand_property_identifier":
			out.pairs[c.Utf8Text(m.src)] = c
			out.order = append(out.order, c.Utf8Text(m.src))
		}
	}
	return out
}

// chainOverwrites returns the request fields that a middleware on the entry's
// registration call assigns before the handler, with the assignment evidence.
func (s *moduleSet) chainOverwrites(out *analysis.AnalysisReport, e analysis.EntryPoint) map[string]analysis.Evidence {
	fields := map[string]analysis.Evidence{}
	m := s.modules[e.Location.Span.File]
	if m == nil {
		return fields
	}
	call := parse.NodeAt(m.tree.RootNode(), e.Location.Span.StartByte, e.Location.Span.EndByte)
	if call == nil || call.Kind() != "call_expression" {
		return fields
	}
	args := call.ChildByFieldName("arguments")
	if args == nil {
		return fields
	}
	var chain []*sitter.Node
	for i := uint(1); i+1 < args.NamedChildCount(); i++ {
		chain = append(chain, args.NamedChild(i))
	}
	return s.overwrittenFields(m, chain)
}

// overwrittenFields returns the request fields that the given middleware
// arguments assign before the handler runs, keyed by the field's last name.
func (s *moduleSet) overwrittenFields(m *sourceModule, chain []*sitter.Node) map[string]analysis.Evidence {
	fields := map[string]analysis.Evidence{}
	for _, arg := range chain {
		hm, body, req, gaps := s.handler(m, arg)
		if body == nil || len(gaps) > 0 || req == "" {
			continue
		}
		var walk func(*sitter.Node)
		walk = func(x *sitter.Node) {
			if x == nil || (x != body && isFunction(x)) {
				return
			}
			if x.Kind() == "assignment_expression" {
				left := x.ChildByFieldName("left")
				if left != nil && left.Kind() == "member_expression" && chainRoot(left, hm.src) == req {
					fields[memberName(hm, left)] = hm.evidence("chain_overwrite", x)
				}
			}
			for j := uint(0); j < x.NamedChildCount(); j++ {
				walk(x.NamedChild(j))
			}
		}
		walk(body)
	}
	return fields
}

// requestKeyed reports whether a selector value is a request value that is not
// overwritten by the chain.
func (s *moduleSet) requestKeyed(m *sourceModule, value *sitter.Node, p handlerParams, overwritten map[string]analysis.Evidence) (*sitter.Node, bool) {
	src := s.requestValue(m, value, p, 0)
	if src == nil {
		return nil, false
	}
	if src.Kind() == "member_expression" {
		if _, ok := overwritten[memberName(m, src)]; ok {
			return nil, false
		}
	}
	return src, true
}

func (s *moduleSet) recordAuthorization(out *analysis.AnalysisReport, e analysis.EntryPoint, m *sourceModule, p handlerParams, overwritten map[string]analysis.Evidence, sel authzSelector) {
	var selecting []string
	var source *sitter.Node
	for _, key := range sel.order {
		if src, ok := s.requestKeyed(m, sel.pairs[key], p, overwritten); ok {
			selecting = append(selecting, key)
			if source == nil {
				source = src
			}
		}
	}
	if source == nil {
		return
	}
	var guards []analysis.AuthorizationGuard
	for _, key := range sel.order {
		if contains(selecting, key) {
			continue
		}
		v := sel.pairs[key]
		if lit := unwrapTS(v); lit == nil || isLiteralNode(lit) {
			continue // a constant scopes the write but not to the caller
		}
		ev := m.evidence("guard_test", v)
		if src := s.requestValue(m, v, p, 0); src != nil && src.Kind() == "member_expression" {
			if over, ok := overwritten[memberName(m, src)]; ok {
				ev = over
			}
		}
		guards = append(guards, analysis.AuthorizationGuard{Kind: analysis.GuardOwnership, Form: "query_scope", Evidence: ev})
	}
	sink := m.evidence(analysis.AuthorizationKind, sel.call)
	subject := m.evidence("subject_selection", source)
	operation := m.evidence("protected_operation", sel.call)
	access, _ := expressEntryAccess(e)
	accessEvidence := append([]analysis.Evidence{}, access.Sources...)
	if len(accessEvidence) == 0 {
		accessEvidence = []analysis.Evidence{e.Location}
	}
	safe := "no"
	switch e.HTTP.Method {
	case "GET", "HEAD", "OPTIONS":
		safe = "yes"
	}
	flowEvidence := []analysis.Evidence{asEvidenceKind(sink, "operation")}
	for _, g := range guards {
		flowEvidence = append(flowEvidence, g.Evidence)
	}
	facts := &analysis.AuthorizationFacts{
		Facets: []string{analysis.FacetObjectLevel}, SubjectClass: sel.subject, SubjectProvenance: analysis.SubjectRequestSelected,
		Operation:      analysis.StateChange{StorageKey: "js-" + sel.subject, Operation: sel.operation, Span: sink.Span},
		SecurityFields: []analysis.SecurityFieldFact{}, Guards: append([]analysis.AuthorizationGuard{}, guards...), MethodSafe: safe,
	}
	evidence := map[string][]analysis.Evidence{
		"subject_selection": {subject}, "protected_operation": {operation}, "entry_access": accessEvidence,
		"control_flow": flowEvidence, "sink_binding": {asEvidenceKind(sink, "sink_binding")},
	}
	out.Uses = append(out.Uses, analysis.CandidateUse{
		EntryID: e.ID, Kind: analysis.AuthorizationKind, Sink: sink, Authorization: facts,
		Dependencies: []analysis.Dependency{{Source: asEvidenceKind(subject, "input_source")}},
		APIModel:     analysispacks.AuthorizationContract(analysispacks.NodeAuthorizationOperation),
		Gaps:         []analysis.Gap{}, Assessment: analysis.Assessment{Status: "not_run"},
		Completeness: &analysis.Completeness{
			ClaimKind: "authorization", Required: analysispacks.AuthorizationRoles(),
			Scope:    "One protected operation, the keys that select its record, the entry's access and the conditions that dominate it.",
			Evidence: evidence, Blockers: []analysis.Gap{}, Coverage: []analysis.Gap{},
		},
	})
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func isLiteralNode(n *sitter.Node) bool {
	switch n.Kind() {
	case "number", "string", "true", "false", "null", "undefined", "template_string":
		return n.Kind() != "template_string" || n.NamedChildCount() == 0
	}
	return false
}

// firstArg returns the first argument of a call, skipping comments that sit
// between the parenthesis and the argument.
func firstArg(args *sitter.Node) *sitter.Node {
	if args == nil {
		return nil
	}
	for i := uint(0); i < args.NamedChildCount(); i++ {
		if c := args.NamedChild(i); c.Kind() != "comment" {
			return c
		}
	}
	return nil
}

// instanceWritten reports that the record a read returned is also the receiver
// of an instance write in the handler. That write is an authorization
// candidate of its own and carries the claim on the record.
func instanceWritten(m *sourceModule, handler, read *sitter.Node) bool {
	parent := read.Parent()
	for parent != nil && (parent.Kind() == "await_expression" || parent.Kind() == "parenthesized_expression" || parent.Kind() == "as_expression") {
		parent = parent.Parent()
	}
	if parent == nil || parent.Kind() != "variable_declarator" {
		return false
	}
	id := parent.ChildByFieldName("name")
	if id == nil || id.Kind() != "identifier" {
		return false
	}
	written := false
	walkCalls(handler, func(call *sitter.Node) {
		fn := call.ChildByFieldName("function")
		if fn == nil || fn.Kind() != "member_expression" {
			return
		}
		if obj := fn.ChildByFieldName("object"); obj != nil && obj.Kind() == "identifier" && obj.Utf8Text(m.src) == id.Utf8Text(m.src) {
			if _, ok := instanceWrites[memberName(m, fn)]; ok {
				written = true
			}
		}
	})
	return written
}
