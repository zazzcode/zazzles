package langjs

import (
	"sort"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
)

// Reads of an owned record (hardening 3 D-7). A candidate with the read facet
// is recorded when all hold:
//
//   - the operation is a Sequelize findOne, findByPk or findAll
//     (https://sequelize.org/docs/v6/core-concepts/model-querying-finders/) or a
//     Mongoose findById or findOne (https://mongoosejs.com/docs/queries.html),
//     and the entry sends the result, or a value derived from it, in a response;
//   - a key of the selector carries a request value, by the rule of the write
//     producer (authorization.go);
//   - the model is owned: a Sequelize belongsTo association
//     (https://sequelize.org/docs/v6/core-concepts/assocs/) or a Mongoose ref
//     path (https://mongoosejs.com/docs/populate.html) links it to a model that
//     holds a credential attribute;
//   - no other key of the selector is a constant.
//
// Another key whose value is not the request's is an ownership_check guard in
// the query_scope form and never suppresses the record. A comparison of a
// member of the result that decides whether the response is sent is a guard
// in the result_comparison form: an ownership_check when the other side is a
// verified token claim, guard_unclassified with a blocker otherwise. A model
// with no association to an account model, a list with no selector and a read
// whose result is not sent are not covered.
var sequelizeReads = map[string]bool{"findOne": true, "findByPk": true, "findAll": true}
var mongooseReads = map[string]bool{"findById": true, "findOne": true}

// tokenClaimMembers are the request members a listed authentication
// middleware fills with the verified token's claims: express-jwt sets
// req.auth ("The decoded JWT payload is available on the request via the auth
// property", express-jwt README), Passport sets req.user
// (https://www.passportjs.org/concepts/authentication/login/), and
// express-openid-connect sets req.oidc (its README, "req.oidc.user").
var tokenClaimMembers = map[string]bool{"auth": true, "user": true, "oidc": true}

type authzRead struct {
	selector    authzSelector
	association analysis.Evidence
	response    *sitter.Node
	// comparisons are the conditions that compare a member of the result and
	// decide whether the response is sent.
	comparisons []resultComparison
}

// resultComparison is one such condition and the side that is not the result.
type resultComparison struct {
	condition, other *sitter.Node
}

// authzReadOf recognizes a read of an owned record whose result the entry sends.
func (s *moduleSet) authzReadOf(m *sourceModule, handler, call *sitter.Node, p handlerParams) (authzRead, bool) {
	fn, args := call.ChildByFieldName("function"), call.ChildByFieldName("arguments")
	if fn == nil || args == nil || fn.Kind() != "member_expression" || firstArg(args) == nil {
		return authzRead{}, false
	}
	obj := fn.ChildByFieldName("object")
	if obj == nil || obj.Kind() != "identifier" {
		return authzRead{}, false
	}
	name, method := obj.Utf8Text(m.src), memberName(m, fn)
	if shadowed(call, name, m.src) {
		return authzRead{}, false
	}
	id := s.modelIdentity(m, name, 0)
	association, owned := s.ownedModels()[id]
	if !owned {
		return authzRead{}, false
	}
	var sel authzSelector
	switch {
	case strings.HasPrefix(id, "sequelize:") && method == "findByPk", strings.HasPrefix(id, "mongoose:") && method == "findById":
		sel = authzSelector{subject: "model:" + name, operation: "read", call: call, pairs: map[string]*sitter.Node{"primary key": firstArg(args)}, order: []string{"primary key"}}
	case strings.HasPrefix(id, "sequelize:") && sequelizeReads[method]:
		o := unwrapTS(firstArg(args))
		if o == nil || o.Kind() != "object" {
			return authzRead{}, false
		}
		w := property(o, "where", m.src)
		if w == nil {
			return authzRead{}, false
		}
		sel = selectorFrom(m, "model:"+name, "read", call, w)
	case strings.HasPrefix(id, "mongoose:") && mongooseReads[method]:
		sel = selectorFrom(m, "model:"+name, "read", call, firstArg(args))
	default:
		return authzRead{}, false
	}
	if len(sel.order) == 0 {
		return authzRead{}, false
	}
	response, comparisons := sentResult(m, handler, call, p)
	if response == nil {
		return authzRead{}, false
	}
	return authzRead{selector: sel, association: association, response: response, comparisons: comparisons}, true
}

// sentResult returns the response call that sends the result of a read, or a
// constant derived from it: `const row = await Model.find…(…)` followed by
// res.json(row), or Model.find…(…).then(row => res.json(row)). It also returns
// the comparisons of the result that decide whether that response is sent.
func sentResult(m *sourceModule, handler, call *sitter.Node, p handlerParams) (*sitter.Node, []resultComparison) {
	var name string
	var scope *sitter.Node
	parent := call.Parent()
	for parent != nil && (parent.Kind() == "await_expression" || parent.Kind() == "parenthesized_expression" || parent.Kind() == "as_expression") {
		parent = parent.Parent()
	}
	switch {
	case parent != nil && parent.Kind() == "variable_declarator":
		if id := parent.ChildByFieldName("name"); id != nil && id.Kind() == "identifier" {
			name, scope = id.Utf8Text(m.src), handler.ChildByFieldName("body")
		}
	case parent != nil && parent.Kind() == "member_expression" && memberName(m, parent) == "then":
		then := parent.Parent()
		if then == nil || then.Kind() != "call_expression" {
			return nil, nil
		}
		callback := firstArg(then.ChildByFieldName("arguments"))
		if callback == nil || !isFunction(callback) {
			return nil, nil
		}
		if params, ok := functionParameters(callback, m.src); ok && len(params) == 1 {
			name, scope = params[0].name, callback.ChildByFieldName("body")
		}
	}
	if name == "" || scope == nil {
		return nil, nil
	}
	names := map[string]bool{name: true}
	var derive func(*sitter.Node)
	derive = func(x *sitter.Node) {
		if x.Kind() == "variable_declarator" {
			id, value := x.ChildByFieldName("name"), x.ChildByFieldName("value")
			if id != nil && id.Kind() == "identifier" && value != nil && value.StartByte() > call.EndByte() && mentionsName(m, value, names) {
				names[id.Utf8Text(m.src)] = true
			}
		}
		for i := uint(0); i < x.NamedChildCount(); i++ {
			derive(x.NamedChild(i))
		}
	}
	derive(scope)
	var sent *sitter.Node
	walkCalls(scope, func(c *sitter.Node) {
		if sent != nil || c.StartByte() < call.EndByte() {
			return
		}
		fn, args := c.ChildByFieldName("function"), c.ChildByFieldName("arguments")
		if fn == nil || args == nil || fn.Kind() != "member_expression" || !responseMethods[memberName(m, fn)] {
			return
		}
		if root := chainRoot(fn.ChildByFieldName("object"), m.src); !p.response[root] || shadowed(c, root, m.src) && !parameterOfEnclosing(m, c, root) {
			return
		}
		if mentionsName(m, args, names) {
			sent = c
		}
	})
	if sent == nil {
		return nil, nil
	}
	return sent, resultComparisons(m, scope, call, sent, names)
}

// resultComparisons returns the conditions between a read and the response
// that sends its result which compare a member of the result with a value
// that is neither the result nor a literal, and which decide whether the
// response is sent: the response is inside a branch of the condition, or the
// condition has no else branch and its branch leaves the function.
func resultComparisons(m *sourceModule, scope, read, sent *sitter.Node, names map[string]bool) []resultComparison {
	var out []resultComparison
	inside := func(outer, inner *sitter.Node) bool {
		return outer != nil && outer.StartByte() <= inner.StartByte() && inner.EndByte() <= outer.EndByte()
	}
	var walk func(*sitter.Node)
	walk = func(x *sitter.Node) {
		if x == nil || x.StartByte() >= sent.StartByte() || (x != scope && isFunction(x) && !inside(x, sent)) {
			return
		}
		if x.Kind() == "if_statement" && x.StartByte() > read.EndByte() {
			then, otherwise := x.ChildByFieldName("consequence"), x.ChildByFieldName("alternative")
			if inside(then, sent) || inside(otherwise, sent) || otherwise == nil && leavesFunction(then) {
				if other := comparedWithResult(m, x.ChildByFieldName("condition"), names); other != nil {
					out = append(out, resultComparison{condition: x.ChildByFieldName("condition"), other: other})
				}
			}
		}
		for i := uint(0); i < x.NamedChildCount(); i++ {
			walk(x.NamedChild(i))
		}
	}
	walk(scope)
	return out
}

// leavesFunction reports a branch that is, or ends with, a return or a throw.
func leavesFunction(branch *sitter.Node) bool {
	if branch == nil {
		return false
	}
	last := branch
	if branch.Kind() == "statement_block" {
		if branch.NamedChildCount() == 0 {
			return false
		}
		last = branch.NamedChild(branch.NamedChildCount() - 1)
	}
	return last.Kind() == "return_statement" || last.Kind() == "throw_statement"
}

// comparedWithResult returns the other side of the first equality comparison
// under cond in which one side reads a member of the result and the other
// reads neither the result nor only literals.
func comparedWithResult(m *sourceModule, cond *sitter.Node, names map[string]bool) *sitter.Node {
	var found *sitter.Node
	var walk func(*sitter.Node)
	walk = func(x *sitter.Node) {
		if x == nil || found != nil || isFunction(x) {
			return
		}
		if x.Kind() == "binary_expression" {
			switch op := x.ChildByFieldName("operator"); {
			case op == nil:
			case op.Kind() == "===" || op.Kind() == "!==" || op.Kind() == "==" || op.Kind() == "!=":
				left, right := x.ChildByFieldName("left"), x.ChildByFieldName("right")
				for _, side := range [][2]*sitter.Node{{left, right}, {right, left}} {
					if readsMemberOf(m, side[0], names) && !mentionsName(m, side[1], names) && !literalTree(unwrapTS(side[1])) {
						found = side[1]
						return
					}
				}
			}
		}
		for i := uint(0); i < x.NamedChildCount(); i++ {
			walk(x.NamedChild(i))
		}
	}
	walk(cond)
	return found
}

// readsMemberOf reports a member read whose chain starts at one of the names.
func readsMemberOf(m *sourceModule, n *sitter.Node, names map[string]bool) bool {
	found := false
	var walk func(*sitter.Node)
	walk = func(x *sitter.Node) {
		if x == nil || found {
			return
		}
		if x.Kind() == "member_expression" && names[chainRoot(x, m.src)] {
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

// mentionsName reports a read of one of the names under n. A property name and
// a nested function's own parameter of the same name are not reads of it.
func mentionsName(m *sourceModule, n *sitter.Node, names map[string]bool) bool {
	found := false
	var walk func(*sitter.Node)
	walk = func(x *sitter.Node) {
		if x == nil || found {
			return
		}
		switch x.Kind() {
		case "identifier", "shorthand_property_identifier":
			found = names[x.Utf8Text(m.src)]
			return
		case "property_identifier":
			return
		}
		for i := uint(0); i < x.NamedChildCount(); i++ {
			walk(x.NamedChild(i))
		}
	}
	walk(n)
	return found
}

// ownedModels maps the identity of every owned model to the evidence of the
// association that makes it owned.
func (s *moduleSet) ownedModels() map[string]analysis.Evidence {
	if s.owned != nil {
		return s.owned
	}
	s.owned = map[string]analysis.Evidence{}
	files := make([]string, 0, len(s.modules))
	for file := range s.modules {
		files = append(files, file)
	}
	sort.Strings(files)
	type labeled struct {
		module *sourceModule
		name   string
	}
	labels := map[string]labeled{}
	for _, file := range files {
		m := s.modules[file]
		for _, name := range topVariableNames(m) {
			if id := s.modelIdentity(m, name, 0); strings.HasPrefix(id, "mongoose:") {
				if _, seen := labels[id]; !seen {
					labels[id] = labeled{m, name}
				}
			}
		}
	}
	for _, file := range files {
		m := s.modules[file]
		// Sequelize: Owned.belongsTo(Account, …).
		walkCalls(m.tree.RootNode(), func(call *sitter.Node) {
			fn, args := call.ChildByFieldName("function"), call.ChildByFieldName("arguments")
			if fn == nil || args == nil || fn.Kind() != "member_expression" || memberName(m, fn) != "belongsTo" {
				return
			}
			owner, target := fn.ChildByFieldName("object"), unwrapTS(firstArg(args))
			if owner == nil || target == nil || owner.Kind() != "identifier" || target.Kind() != "identifier" {
				return
			}
			if shadowed(call, owner.Utf8Text(m.src), m.src) || shadowed(call, target.Utf8Text(m.src), m.src) {
				return
			}
			id := s.modelIdentity(m, owner.Utf8Text(m.src), 0)
			if !strings.HasPrefix(id, "sequelize:") || !strings.HasPrefix(s.modelIdentity(m, target.Utf8Text(m.src), 0), "sequelize:") {
				return
			}
			if _, seen := s.owned[id]; !seen && s.holdsCredential(m, target.Utf8Text(m.src)) {
				s.owned[id] = m.evidence("owner_association", call)
			}
		})
	}
	// Mongoose: a schema path with ref: '<Account model>'.
	ids := make([]string, 0, len(labels))
	for id := range labels {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		l := labels[id]
		info, ok := s.modelAttributes(l.module, l.name)
		if !ok {
			continue
		}
		for _, a := range info.attrs {
			spec := unwrapTS(a.node.ChildByFieldName("value"))
			if spec == nil || spec.Kind() != "object" {
				continue
			}
			ref, ok := stringLiteral(property(spec, "ref", info.module.src), info.module.src)
			if !ok {
				continue
			}
			if target, known := labels["mongoose:"+ref]; known && s.holdsCredential(target.module, target.name) {
				if _, seen := s.owned[id]; !seen {
					s.owned[id] = info.module.evidence("owner_association", a.node)
				}
			}
		}
	}
	return s.owned
}

// holdsCredential reports a model with an attribute the account census named
// a credential (account.go).
func (s *moduleSet) holdsCredential(m *sourceModule, name string) bool {
	info, ok := s.modelAttributes(m, name)
	if !ok {
		return false
	}
	for _, a := range info.attrs {
		if s.credentialAttrs[a.name] {
			return true
		}
	}
	return false
}

func topVariableNames(m *sourceModule) []string {
	var names []string
	root := m.tree.RootNode()
	for i := uint(0); i < root.NamedChildCount(); i++ {
		n := root.NamedChild(i)
		if n.Kind() == "export_statement" {
			n = n.ChildByFieldName("declaration")
		}
		if n == nil || (n.Kind() != "lexical_declaration" && n.Kind() != "variable_declaration") {
			continue
		}
		for j := uint(0); j < n.NamedChildCount(); j++ {
			if id := n.NamedChild(j).ChildByFieldName("name"); id != nil && id.Kind() == "identifier" {
				names = append(names, id.Utf8Text(m.src))
			}
		}
	}
	return names
}

// verifiedClaim reports a selector value read from a request member that a
// listed authentication middleware on the entry's chain fills from the
// verified token. The caller does not choose such a value.
func verifiedClaim(m *sourceModule, src *sitter.Node, p handlerParams, access analysis.EntryAccess) bool {
	if access.Authentication != analysis.AccessRequired || src == nil {
		return false
	}
	chain, ok := memberChain(unwrapTS(src), m.src)
	if !ok {
		return false
	}
	if p.request != "" {
		return len(chain) >= 2 && chain[0] == p.request && tokenClaimMembers[chain[1]]
	}
	// A destructured request parameter binds the member under a local name:
	// ({ auth }), ({ auth: claims }) or ({ auth: { id } }).
	member, _, _ := strings.Cut(p.projections[chain[0]], ".")
	return tokenClaimMembers[member]
}

func (s *moduleSet) recordAuthorizationRead(out *analysis.AnalysisReport, e analysis.EntryPoint, m *sourceModule, p handlerParams, overwritten map[string]analysis.Evidence, read authzRead) {
	sel := read.selector
	access, _ := expressEntryAccess(e)
	var source *sitter.Node
	var guards []analysis.AuthorizationGuard
	blockers := []analysis.Gap{}
	for _, key := range sel.order {
		v := sel.pairs[key]
		if lit := unwrapTS(v); lit == nil || isLiteralNode(lit) {
			return // a constant narrows the read to rows the application chose
		}
		src, ok := s.requestKeyed(m, v, p, overwritten)
		if ok && !verifiedClaim(m, src, p, access) {
			if source == nil {
				source = src
			}
			continue
		}
		ev := m.evidence("guard_test", v)
		if raw := s.requestValue(m, v, p, 0); raw != nil && raw.Kind() == "member_expression" {
			if over, found := overwritten[memberName(m, raw)]; found {
				ev = over
			}
		}
		guards = append(guards, analysis.AuthorizationGuard{Kind: analysis.GuardOwnership, Form: "query_scope", Evidence: ev})
	}
	if source == nil {
		return
	}
	for _, c := range read.comparisons {
		g := analysis.AuthorizationGuard{Kind: analysis.GuardUnclassified, Form: "result_comparison", Evidence: m.evidence("guard_test", c.condition)}
		if verifiedClaim(m, s.requestValue(m, c.other, p, 0), p, access) {
			g.Kind = analysis.GuardOwnership
		} else {
			// What the result is compared with is not established, so the scanner
			// does not say what kind of check this is and the claim stays in Review.
			g.Gaps = []analysis.Gap{{Kind: analysis.GuardUnclassified, Detail: "a comparison of the record decides whether it is sent; the value it is compared with has no modeled kind", At: g.Evidence.Span}}
			blockers = append(blockers, g.Gaps...)
		}
		guards = append(guards, g)
	}
	sink := m.evidence(analysis.AuthorizationKind, sel.call)
	subject := m.evidence("subject_selection", source)
	operation := m.evidence("protected_operation", sel.call)
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
		Facets: []string{analysis.FacetObjectLevel, analysis.FacetDataExposure}, SubjectClass: sel.subject, SubjectProvenance: analysis.SubjectRequestSelected,
		Operation:      analysis.StateChange{StorageKey: "js-" + sel.subject, Operation: "read", Span: sink.Span},
		SecurityFields: []analysis.SecurityFieldFact{}, Guards: append([]analysis.AuthorizationGuard{}, guards...), MethodSafe: safe,
	}
	evidence := map[string][]analysis.Evidence{
		"subject_selection": {subject}, "protected_operation": {operation}, "entry_access": accessEvidence,
		"control_flow": flowEvidence, "sink_binding": {asEvidenceKind(sink, "sink_binding")},
		"owner_association": {read.association}, "response_emission": {m.evidence("response_emission", read.response)},
	}
	out.Uses = append(out.Uses, analysis.CandidateUse{
		EntryID: e.ID, Kind: analysis.AuthorizationKind, Sink: sink, Authorization: facts,
		Dependencies: []analysis.Dependency{{Source: asEvidenceKind(subject, "input_source")}},
		APIModel:     analysispacks.AuthorizationContract(analysispacks.NodeAuthorizationOperation),
		Gaps:         []analysis.Gap{}, Assessment: analysis.Assessment{Status: "not_run"},
		Completeness: &analysis.Completeness{
			ClaimKind: "authorization", Required: analysispacks.AuthorizationRoles(),
			Scope:    "One read of an owned record, the keys that select it, the response that sends it, the entry's access and the conditions on its selector.",
			Evidence: evidence, Blockers: blockers, Coverage: []analysis.Gap{},
		},
	})
}
