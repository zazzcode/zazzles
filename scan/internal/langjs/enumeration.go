package langjs

import (
	"regexp"
	"sort"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/parse"
)

// Account enumeration for Express (lane decision D-7): an entry with
// authentication none looks a record up by a request value through a modeled
// finder (a Sequelize finder on a verified model, a Mongoose finder on a
// verified model), and the branches on the result send responses that differ
// in status or body. A lookup that also compares a credential (a key that a
// census credential attribute names, or a digest value) is a login and is
// excluded, as in PHP. A response is recorded as its status and its argument
// text; the scanner reads no meaning into either.
var enumerationFinders = map[string]bool{"findOne": true, "findAll": true, "findByPk": true, "find": true}

type enumerationLookup struct {
	call     *sitter.Node
	result   string
	class    string
	method   string
	criteria []string
	source   *sitter.Node
}

func (s *moduleSet) enumerationCandidates(out *analysis.AnalysisReport) {
	callables := map[string]analysis.Callable{}
	for _, c := range out.Callables {
		callables[c.ID] = c
	}
	bindings := map[string]string{}
	for _, b := range out.DispatchBindings {
		bindings[b.EntryID] = b.CallableID
	}
	entries := append([]analysis.EntryPoint{}, out.Entries...)
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	seen := map[string]bool{}
	for _, e := range entries {
		access, ok := expressEntryAccess(e)
		if !ok || access.Authentication != analysis.AccessNone || e.HTTP.Method == "USE" {
			continue
		}
		def := callables[bindings[e.ID]].Definition.Span
		m := s.modules[def.File]
		if m == nil || def.File == "" {
			continue
		}
		body := parse.NodeAt(m.tree.RootNode(), def.StartByte, def.EndByte)
		if body == nil {
			continue
		}
		fn, body := handlerFunction(body)
		if body == nil || body.Kind() != "statement_block" || fn == nil {
			continue
		}
		params := plainOrDestructuredParameters(fn, m.src)
		if len(params.response) == 0 {
			continue
		}
		walkCalls(body, func(call *sitter.Node) {
			if enclosingFunction(call) != nil && enclosingFunction(call).StartByte() != fn.StartByte() {
				return
			}
			l, ok := s.enumerationLookupOf(m, call, params)
			if !ok || s.isLogin(m, call) {
				return
			}
			key := e.ID + ":" + string(rune(call.StartByte()))
			if seen[key] {
				return
			}
			if s.recordEnumeration(out, e, access, m, body, params, l) {
				seen[key] = true
			}
		})
	}
}

type handlerParams struct {
	containers map[string]bool // request container names: req, or destructured query/body/params
	request    string
	response   map[string]bool
}

func plainOrDestructuredParameters(fn *sitter.Node, src []byte) handlerParams {
	p := handlerParams{containers: map[string]bool{}, response: map[string]bool{}}
	params := fn.ChildByFieldName("parameters")
	if params == nil {
		return p
	}
	for i := uint(0); i < params.NamedChildCount(); i++ {
		n := params.NamedChild(i)
		if n.Kind() == "required_parameter" || n.Kind() == "optional_parameter" {
			n = n.ChildByFieldName("pattern")
		}
		if n == nil {
			continue
		}
		switch {
		case i == 0 && n.Kind() == "identifier":
			p.request = n.Utf8Text(src)
		case i == 0 && n.Kind() == "object_pattern":
			for j := uint(0); j < n.NamedChildCount(); j++ {
				if c := n.NamedChild(j); c.Kind() == "shorthand_property_identifier_pattern" {
					p.containers[c.Utf8Text(src)] = true
				}
			}
		case i == 1 && n.Kind() == "identifier":
			p.response[n.Utf8Text(src)] = true
		}
	}
	return p
}

// requestValue returns the first node under n that reads the request: a member
// chain of the request parameter, a destructured container, or a constant that
// is bound to one.
func (s *moduleSet) requestValue(m *sourceModule, n *sitter.Node, p handlerParams, depth int) *sitter.Node {
	var found *sitter.Node
	var walk func(*sitter.Node)
	walk = func(x *sitter.Node) {
		if x == nil || found != nil {
			return
		}
		switch x.Kind() {
		case "call_expression":
			if s.keyedStoreCall(m, x) {
				return // the call returns what the server stored, not its key
			}
		case "member_expression", "subscript_expression":
			if serverKeyedStore(m, x) {
				// store[key] returns what the server wrote, not the key.
				return
			}
			if root := chainRoot(x, m.src); root != "" {
				if root == p.request || p.containers[root] {
					found = x
					return
				}
			}
		case "identifier":
			if depth == 0 {
				name := x.Utf8Text(m.src)
				if v := unwrapTS(localConst(m, x, name)); v != nil {
					if r := s.requestValue(m, v, p, 1); r != nil {
						found = x
						return
					}
				}
			}
		}
		for i := uint(0); i < x.NamedChildCount(); i++ {
			walk(x.NamedChild(i))
		}
	}
	walk(n)
	return found
}

// localConst returns the initializer of the constant name in the function that
// encloses n.
func localConst(m *sourceModule, n *sitter.Node, name string) *sitter.Node {
	fn := enclosingFunction(n)
	if fn == nil {
		return nil
	}
	var init *sitter.Node
	var walk func(*sitter.Node)
	walk = func(x *sitter.Node) {
		if x == nil || init != nil || (x != fn && isFunction(x)) {
			return
		}
		if x.Kind() == "variable_declarator" {
			if id := x.ChildByFieldName("name"); id != nil && id.Kind() == "identifier" && id.Utf8Text(m.src) == name {
				init = x.ChildByFieldName("value")
				return
			}
		}
		for i := uint(0); i < x.NamedChildCount(); i++ {
			walk(x.NamedChild(i))
		}
	}
	walk(fn)
	return init
}

func (s *moduleSet) enumerationLookupOf(m *sourceModule, call *sitter.Node, p handlerParams) (enumerationLookup, bool) {
	fn, args := call.ChildByFieldName("function"), call.ChildByFieldName("arguments")
	if fn == nil || args == nil || fn.Kind() != "member_expression" || !enumerationFinders[memberName(m, fn)] || firstArg(args) == nil {
		return enumerationLookup{}, false
	}
	obj := fn.ChildByFieldName("object")
	if obj == nil || obj.Kind() != "identifier" || shadowed(call, obj.Utf8Text(m.src), m.src) {
		return enumerationLookup{}, false
	}
	class := ""
	switch id := s.modelIdentity(m, obj.Utf8Text(m.src), 0); {
	case strings.HasPrefix(id, "sequelize:"):
		class = "sequelize"
	case strings.HasPrefix(id, "mongoose:"):
		class = "mongoose"
	default:
		return enumerationLookup{}, false
	}
	// The result is bound by `const x = await finder(...)`.
	parent := call.Parent()
	if parent != nil && parent.Kind() == "await_expression" {
		parent = parent.Parent()
	}
	if parent == nil || parent.Kind() != "variable_declarator" {
		return enumerationLookup{}, false
	}
	id := parent.ChildByFieldName("name")
	src := s.requestValue(m, firstArg(args), p, 0)
	if id == nil || id.Kind() != "identifier" || src == nil {
		return enumerationLookup{}, false
	}
	l := enumerationLookup{call: call, result: id.Utf8Text(m.src), class: class, method: memberName(m, fn), source: src}
	for _, key := range criteriaKeys(m, firstArg(args)) {
		l.criteria = append(l.criteria, key)
	}
	return l, true
}

// criteriaKeys returns the property names of the innermost where object (or
// of the argument object itself).
func criteriaKeys(m *sourceModule, arg *sitter.Node) []string {
	obj := unwrapTS(arg)
	if obj == nil || obj.Kind() != "object" {
		return nil
	}
	if w := property(obj, "where", m.src); w != nil && unwrapTS(w).Kind() == "object" {
		obj = unwrapTS(w)
	}
	var keys []string
	for i := uint(0); i < obj.NamedChildCount(); i++ {
		c := obj.NamedChild(i)
		switch c.Kind() {
		case "pair":
			if k := c.ChildByFieldName("key"); k != nil {
				keys = append(keys, strings.Trim(k.Utf8Text(m.src), `"'`))
			}
		case "shorthand_property_identifier":
			keys = append(keys, c.Utf8Text(m.src))
		}
	}
	return keys
}

// isLogin reports a lookup that compares a credential: a criteria key named by
// a census credential attribute, or a criteria value that is a call of a fast
// digest (directly or through the one helper that returns it).
func (s *moduleSet) isLogin(m *sourceModule, call *sitter.Node) bool {
	args := call.ChildByFieldName("arguments")
	obj := unwrapTS(firstArg(args))
	if obj == nil || obj.Kind() != "object" {
		return false
	}
	if w := property(obj, "where", m.src); w != nil && unwrapTS(w).Kind() == "object" {
		obj = unwrapTS(w)
	}
	for i := uint(0); i < obj.NamedChildCount(); i++ {
		c := obj.NamedChild(i)
		if c.Kind() != "pair" {
			continue
		}
		if k := c.ChildByFieldName("key"); k != nil && s.credentialAttrs[strings.Trim(k.Utf8Text(m.src), `"'`)] {
			return true
		}
		if v := c.ChildByFieldName("value"); v != nil && s.digestValue(m, v) {
			return true
		}
	}
	return false
}

func (s *moduleSet) digestValue(m *sourceModule, v *sitter.Node) bool {
	v = unwrapTS(v)
	if v == nil || v.Kind() != "call_expression" {
		return false
	}
	if _, ok := digestChain(m, v); ok {
		return true
	}
	fn := v.ChildByFieldName("function")
	if fn == nil || (fn.Kind() != "identifier" && fn.Kind() != "member_expression") {
		return false
	}
	target, helper := s.resolve(m, fn.Utf8Text(m.src))
	if target == nil || helper == nil {
		return false
	}
	ret := returnedCall(helper)
	if ret == nil {
		return false
	}
	_, ok := digestChain(target, ret)
	return ok
}

// recordEnumeration builds the candidate when the lookup result is branched on
// and the two sides answer differently.
func (s *moduleSet) recordEnumeration(out *analysis.AnalysisReport, e analysis.EntryPoint, access analysis.EntryAccess, m *sourceModule, body *sitter.Node, p handlerParams, l enumerationLookup) bool {
	decl := l.call.Parent()
	if decl != nil && decl.Kind() == "await_expression" {
		decl = decl.Parent()
	}
	stmt := decl
	for stmt != nil && stmt.Parent() != nil && stmt.Parent().Kind() != "statement_block" {
		stmt = stmt.Parent()
	}
	if stmt == nil || stmt.Parent() == nil {
		return false
	}
	block := stmt.Parent()
	var branch *sitter.Node
	var rest []*sitter.Node
	after := false
	for i := uint(0); i < block.NamedChildCount(); i++ {
		c := block.NamedChild(i)
		if after && branch == nil && c.Kind() == "if_statement" && conditionTests(m, c.ChildByFieldName("condition"), l.result) {
			branch = c
			continue
		}
		if after && branch != nil {
			rest = append(rest, c)
		}
		if c.StartByte() == stmt.StartByte() {
			after = true
		}
	}
	if branch == nil {
		return false
	}
	positive, ok := conditionPolarity(m, branch.ChildByFieldName("condition"), l.result)
	if !ok {
		return false
	}
	thenSide := []*sitter.Node{branch.ChildByFieldName("consequence")}
	elseSide := []*sitter.Node{}
	if alt := branch.ChildByFieldName("alternative"); alt != nil {
		elseSide = append(elseSide, alt)
	} else {
		elseSide = rest
	}
	found, notFound := thenSide, elseSide
	if !positive {
		found, notFound = elseSide, thenSide
	}
	foundResp, notFoundResp := branchResponses(m, found, p), branchResponses(m, notFound, p)
	if sameResponses(foundResp, notFoundResp) {
		return false
	}
	sink := m.evidence(analysis.AccountEnumerationKind, l.call)
	branchAt := m.evidence("result_branch", branch.ChildByFieldName("condition"))
	source := m.evidence("input_source", l.source)
	accessEvidence := append([]analysis.Evidence{}, access.Sources...)
	if len(accessEvidence) == 0 {
		accessEvidence = []analysis.Evidence{e.Location}
	}
	blockers := []analysis.Gap{}
	for _, side := range [][]analysis.BranchResponse{foundResp, notFoundResp} {
		for _, r := range side {
			if r.Kind == analysis.ResponseUnresolved {
				blockers = append(blockers, analysis.Gap{Kind: analysis.ResponseUnresolved, Detail: "A response on one side of the lookup branch is not a recognized response call.", At: r.Span})
				break
			}
		}
	}
	facts := &analysis.EnumerationFacts{
		Lookup:   analysis.EnumerationLookup{Class: l.class, Method: l.method, CriteriaFields: l.criteria, Evidence: sink, Branch: branchAt},
		Found:    foundResp,
		NotFound: notFoundResp, SecurityFields: []analysis.SecurityFieldFact{},
	}
	out.Uses = append(out.Uses, analysis.CandidateUse{
		EntryID: e.ID, Kind: analysis.AccountEnumerationKind, Sink: sink, Enumeration: facts,
		Dependencies: []analysis.Dependency{{Source: source}},
		Gaps:         []analysis.Gap{},
		Assessment:   analysis.Assessment{Status: "not_run"},
		Completeness: &analysis.Completeness{
			ClaimKind: "account_enumeration", Required: []string{"input_source", "account_lookup", "result_branch", "entry_access"},
			Scope: "One account lookup by a request value, the branch on its result and the responses on each side.",
			Evidence: map[string][]analysis.Evidence{
				"input_source": {source}, "account_lookup": {sink}, "result_branch": {branchAt}, "entry_access": accessEvidence,
			},
			Blockers: blockers, Coverage: []analysis.Gap{},
		},
	})
	return true
}

// conditionTests reports whether the condition reads the result variable.
func conditionTests(m *sourceModule, cond *sitter.Node, name string) bool {
	found := false
	var walk func(*sitter.Node)
	walk = func(x *sitter.Node) {
		if x == nil || found {
			return
		}
		if x.Kind() == "identifier" && x.Utf8Text(m.src) == name {
			found = true
			return
		}
		for i := uint(0); i < x.NamedChildCount(); i++ {
			walk(x.NamedChild(i))
		}
	}
	walk(cond)
	return found
}

// conditionPolarity reports whether the consequence runs when the record was
// found. Only the closed forms are read: x, !x, !!x, x != null, x !== null,
// x != undefined, x == null, x === null, x === undefined.
func conditionPolarity(m *sourceModule, cond *sitter.Node, name string) (bool, bool) {
	text := strings.ReplaceAll(strings.Trim(cond.Utf8Text(m.src), "() "), " ", "")
	switch text {
	case name, "!!" + name, name + "!=null", name + "!==null", name + "!=undefined", name + "!==undefined":
		return true, true
	case "!" + name, name + "==null", name + "===null", name + "==undefined", name + "===undefined":
		return false, true
	}
	return false, false
}

// branchResponses collects the response calls of a side, in source order. A
// side with none is a response_unresolved record.
func branchResponses(m *sourceModule, nodes []*sitter.Node, p handlerParams) []analysis.BranchResponse {
	out := []analysis.BranchResponse{}
	var walk func(*sitter.Node)
	walk = func(x *sitter.Node) {
		if x == nil || isFunction(x) {
			return
		}
		if x.Kind() == "call_expression" {
			fn, args := x.ChildByFieldName("function"), x.ChildByFieldName("arguments")
			if fn != nil && fn.Kind() == "member_expression" && p.response[chainRoot(fn, m.src)] {
				text := ""
				if args != nil {
					text = strings.Join(strings.Fields(args.Utf8Text(m.src)), "")
				}
				span := m.evidence("response", x).Span
				switch method := memberName(m, fn); method {
				case "status":
					out = append(out, analysis.BranchResponse{Kind: analysis.ResponseStatus, Literal: strings.Trim(text, "()"), Span: span})
				case "sendStatus":
					out = append(out, analysis.BranchResponse{Kind: analysis.ResponseStatus, Literal: strings.Trim(text, "()"), Span: span})
				case "redirect":
					out = append(out, analysis.BranchResponse{Kind: analysis.ResponseRedirect, Literal: strings.Trim(text, "()"), Span: span})
				case "render":
					out = append(out, analysis.BranchResponse{Kind: analysis.ResponseTemplate, Literal: strings.Trim(text, "()"), Span: span})
				case "json", "send", "end", "jsonp":
					out = append(out, analysis.BranchResponse{Kind: analysis.ResponseBody, Literal: strings.Trim(text, "()"), Span: span})
				}
			}
		}
		for i := uint(0); i < x.NamedChildCount(); i++ {
			walk(x.NamedChild(i))
		}
	}
	for _, n := range nodes {
		walk(n)
	}
	if len(out) == 0 && len(nodes) > 0 {
		span := analysis.Span{}
		if nodes[0] != nil {
			span = m.evidence("response", nodes[0]).Span
		}
		out = append(out, analysis.BranchResponse{Kind: analysis.ResponseUnresolved, Span: span})
	}
	return out
}

func sameResponses(a, b []analysis.BranchResponse) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Kind != b[i].Kind || a[i].Literal != b[i].Literal {
			return false
		}
	}
	return true
}

// serverKeyedStore reports a lookup `store[key]` on a module-level constant
// initialized to an empty object that no code aliases (keyed_store_lookup.go).
func serverKeyedStore(m *sourceModule, n *sitter.Node) bool {
	if n.Kind() != "subscript_expression" {
		return false
	}
	obj := n.ChildByFieldName("object")
	if obj == nil || obj.Kind() != "identifier" || shadowed(n, obj.Utf8Text(m.src), m.src) {
		return false
	}
	name := obj.Utf8Text(m.src)
	return emptyStoreLiteral(m, topVariable(m, name)) && !bindingReassigned(m, name)
}

// handlerFunction returns the request handler function and its block for the
// node a callable definition names: the function itself or its block. A
// factory with no parameters whose whole body returns a function is followed to
// that function.
func handlerFunction(node *sitter.Node) (*sitter.Node, *sitter.Node) {
	fn := node
	if !isFunction(node) && node.Kind() != "function_declaration" {
		fn = node.Parent()
	}
	for depth := 0; fn != nil && depth < 3; depth++ {
		params := fn.ChildByFieldName("parameters")
		if params != nil && params.NamedChildCount() > 0 {
			break
		}
		inner := returnedFunction(fn)
		if inner == nil {
			break
		}
		fn = inner
	}
	if fn == nil {
		return nil, nil
	}
	return fn, fn.ChildByFieldName("body")
}

var thisStoreIndex = regexp.MustCompile(`this\.([A-Za-z_$][\w$]*)\[`)

// keyedStoreCall reports a call of a method of a const object literal whose
// body indexes `this.<store>[...]`, where <store> is a property of that object
// initialized to an empty object (keyed_store_lookup.go): the call returns what
// the server wrote into the store.
func (s *moduleSet) keyedStoreCall(m *sourceModule, call *sitter.Node) bool {
	fn := call.ChildByFieldName("function")
	if fn == nil || (fn.Kind() != "identifier" && fn.Kind() != "member_expression") {
		return false
	}
	target, method := s.resolve(m, fn.Utf8Text(m.src))
	if target == nil || method == nil {
		return false
	}
	obj := method.Parent()
	for i := 0; obj != nil && obj.Kind() != "object" && i < 3; i++ {
		obj = obj.Parent()
	}
	if obj == nil || obj.Kind() != "object" {
		return false
	}
	for _, match := range thisStoreIndex.FindAllStringSubmatch(method.Utf8Text(target.src), -1) {
		if v := property(obj, match[1], target.src); v != nil && emptyStoreLiteral(target, v) {
			return true
		}
	}
	return false
}
