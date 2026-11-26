package langpy

import (
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
	"github.com/zazzcode/zazzles/scan/internal/parse"
)

// SQL text records (specification 21). A call that no contract or other path
// records, and that has an argument whose string is SQL statement text, becomes a
// sql_query_candidate with the contract analysispacks.SQLTextContract. This file
// only reads Python syntax: it reduces one argument to literal pieces and holes
// and asks parse.SQLStatementText. It never changes flow state.

// sqlTextArgument finds the first argument (positional, then keyword) whose
// string is SQL statement text. It returns the argument index, its node, the
// match and whether the text holds a part the scanner cannot read as literal.
func (f *pythonFlow) sqlTextArgument(nodes []*sitter.Node, values []pythonValue, kwNodes []*sitter.Node, kwValues []pythonValue) (int, *sitter.Node, parse.SQLTextMatch, bool) {
	total := len(nodes) + len(kwNodes)
	for i := 0; i < total; i++ {
		var node *sitter.Node
		var v pythonValue
		if i < len(nodes) {
			node, v = nodes[i], values[i]
		} else {
			node, v = kwNodes[i-len(nodes)], kwValues[i-len(nodes)]
		}
		if node == nil {
			continue
		}
		pieces, dynamic := f.sqlPieces(node, 0)
		if len(pieces) == 0 && v.constant {
			pieces = parse.SQLTextLiteral(v.literal)
		}
		match := parse.SQLStatementText(pieces)
		if !match.Matched && v.constant && v.literal != "" {
			if m := parse.SQLStatementText(parse.SQLTextLiteral(v.literal)); m.Matched {
				match, dynamic = m, false
			}
		}
		if match.Matched {
			return i, node, match, dynamic || match.Holes > 0
		}
	}
	return -1, nil, parse.SQLTextMatch{}, false
}

// sqlWrapperNames are the names of calls that only wrap statement text for
// another call: conn.execute(text("...")).
var sqlWrapperNames = map[string]bool{"text": true, "sql": true, "textclause": true, "literal_column": true, "raw": true, "query": true, "composed": true, "literal": true}

// sqlTextWrapperName reports a call whose callee name is one that wraps SQL text.
func (f *pythonFlow) sqlTextWrapperName(fn *sitter.Node) bool {
	if fn == nil {
		return false
	}
	name := strings.ToLower(pyText(f.module, fn))
	if i := strings.LastIndex(name, "."); i >= 0 {
		name = name[i+1:]
	}
	return sqlWrapperNames[name]
}

// sqlTextUnwrap strips parentheses and a keyword-argument name from an argument node.
func sqlTextUnwrap(n *sitter.Node) *sitter.Node {
	for n != nil {
		switch {
		case n.Kind() == "keyword_argument":
			n = n.ChildByFieldName("value")
		case n.Kind() == "parenthesized_expression" && n.NamedChildCount() == 1:
			n = n.NamedChild(0)
		default:
			return n
		}
	}
	return nil
}

// sqlTextWrappedBy returns the call that takes n as an argument, or nil.
func sqlTextWrappedBy(n *sitter.Node) *sitter.Node {
	p := n.Parent()
	for p != nil && (p.Kind() == "keyword_argument" || p.Kind() == "parenthesized_expression") {
		p = p.Parent()
	}
	if p == nil || p.Kind() != "argument_list" {
		return nil
	}
	if c := p.Parent(); c != nil && c.Kind() == "call" {
		return c
	}
	return nil
}

// sqlTextOperationElsewhere decides which of two nested calls is the operation
// when one wraps SQL text for the other, as in conn.execute(text("...")). A
// method call (attribute callee) that takes a wrapper call is the operation and
// the wrapper is not recorded; a plain function call that takes a wrapper call
// (str(db.sql(q))) leaves the record to the wrapper.
func (f *pythonFlow) sqlTextOperationElsewhere(n, fn, textArg *sitter.Node) bool {
	if inner := sqlTextUnwrap(textArg); inner != nil && inner.Kind() == "call" && f.sqlTextWrapperName(inner.ChildByFieldName("function")) && fn.Kind() != "attribute" {
		return true
	}
	if f.sqlTextWrapperName(fn) {
		if outer := sqlTextWrappedBy(n); outer != nil {
			if of := outer.ChildByFieldName("function"); of != nil && of.Kind() == "attribute" {
				return true
			}
		}
	}
	return false
}

// sqlTextRecorded reports a SQL or NoSQL record for the call at span in the
// entry that is being analyzed.
func (f *pythonFlow) sqlTextRecorded(span analysis.Span) bool {
	for _, old := range f.report.Uses {
		if (old.Kind == "sql_query_candidate" || old.Kind == "nosql_query_candidate") && old.EntryID == f.invocation.EntryID &&
			old.Sink.Span.File == span.File && old.Sink.Span.StartByte == span.StartByte && old.Sink.Span.EndByte == span.EndByte {
			return true
		}
	}
	return false
}

// sqlTextRecord runs after every other path of the call has had its turn.
func (f *pythonFlow) sqlTextRecord(n, fn *sitter.Node, nodes []*sitter.Node, values []pythonValue, kwNodes []*sitter.Node, kwValues []pythonValue) {
	if fn == nil {
		return
	}
	// A record needs a dependency in some argument; the great majority of calls
	// have none, and the text test is not run for them.
	reaches := false
	for _, v := range values {
		reaches = reaches || len(v.deps) > 0
	}
	for _, v := range kwValues {
		reaches = reaches || len(v.deps) > 0
	}
	if !reaches {
		return
	}
	idx, node, _, hole := f.sqlTextArgument(nodes, values, kwNodes, kwValues)
	if idx < 0 || f.sqlTextOperationElsewhere(n, fn, node) {
		return
	}
	total := len(nodes) + len(kwNodes)
	argValue := func(i int) pythonValue {
		if i < len(nodes) {
			return values[i]
		}
		return kwValues[i-len(nodes)]
	}
	argNode := func(i int) *sitter.Node {
		if i < len(nodes) {
			return nodes[i]
		}
		return kwNodes[i-len(nodes)]
	}
	textValue := argValue(idx)
	var others pythonValue
	for i := 0; i < total; i++ {
		if i != idx {
			others = pyCombine(others, pythonSlot(argValue(i), parse.SQLTextParametersSlot))
		}
	}
	all := pyCombine(pythonSlot(textValue, parse.SQLTextSlot), others)
	if len(all.deps) == 0 {
		return
	}
	if f.sqlTextRecorded(parse.Span(f.module.file, n)) {
		return
	}
	built := textValue.built || hole
	hasText := len(textValue.deps) > 0
	u := f.addUse("sql_query_candidate", n, all)
	binding := []analysis.Evidence{f.module.evidence("sink_binding", fn)}
	u.Context = append(u.Context, binding...)
	u.APIModel = analysispacks.SQLContract(analysispacks.SQLTextContract)
	if excerpt, ok := parse.SQLTextExcerptEvidence(f.module.src, u.Sink.Span); ok {
		u.Context = append(u.Context, excerpt)
	}
	u.Context = append(u.Context, f.sqlTextSourceExcerpts(u, all)...)
	if built && hasText {
		u.Gaps = append(u.Gaps, f.gap("query_text_interpolated", "Python expression constructs executable SQL text; parameter tuple protects only separate value slots", n))
	}
	for _, d := range all.deps {
		kind := "input_validation_absent"
		if d.protection == "numeric" {
			kind = "validation_type_only"
		}
		u.Gaps = append(u.Gaps, f.gap(kind, "No complete business-policy enforcement established for "+d.container+"."+d.key, n))
	}
	c := &analysis.Completeness{ClaimKind: "injection", Required: []string{"input_source", "sink_binding", "invoked_callable", "control_flow"}, Evidence: map[string][]analysis.Evidence{"sink_binding": binding, "invoked_callable": {f.route.module.evidence("invoked_callable", f.route.fn)}, "control_flow": append([]analysis.Evidence{f.module.evidence("operation", n)}, f.context...)}, Blockers: []analysis.Gap{}, Coverage: append([]analysis.Gap{}, u.Gaps...), Scope: "Bounded Python source-to-operation flow; SQL statement text recognized without a driver contract; SQL text and bound parameters have separate roles."}
	for _, d := range all.deps {
		if d.dep.Source.Kind == "input_source" {
			c.Evidence["input_source"] = append(c.Evidence["input_source"], d.dep.Source)
		}
	}
	c.Evidence["query_text"] = []analysis.Evidence{f.module.evidence("query_text", node)}
	for i := 0; i < total; i++ {
		if i != idx {
			c.Evidence["bound_parameters"] = append(c.Evidence["bound_parameters"], f.module.evidence("bound_parameters", argNode(i)))
		}
	}
	// Blockers are limits on the SQL text and on the values that reach the call;
	// a limit elsewhere in the entry flow is a judged limit (as in sql.go).
	blocking := func(kind string) bool {
		switch kind {
		case "python_parameter_unresolved", "python_value_unresolved", "python_call_unresolved", "python_loop_unresolved", "python_comprehension_unresolved", "python_decorator_unresolved", "work_limit", "dependency_limit", "transfer_limit", "input_helper_unresolved", "python_finally_unresolved":
			return true
		}
		return false
	}
	limits := append(append([]analysis.Gap{}, textValue.gaps...), f.guardGaps(textValue)...)
	for i := 0; i < total; i++ {
		if i != idx {
			v := argValue(i)
			limits = append(append(limits, v.gaps...), f.guardGaps(v)...)
		}
	}
	for _, g := range limits {
		if blocking(g.Kind) {
			c.Blockers = append(c.Blockers, g)
		}
	}
	for _, g := range f.gaps {
		if !blocking(g.Kind) {
			continue
		}
		among := false
		for _, b := range c.Blockers {
			if b.Kind == g.Kind && b.At == g.At {
				among = true
				break
			}
		}
		if !among {
			c.Judged = append(c.Judged, g)
		}
	}
	if built && !hasText {
		c.Blockers = append(c.Blockers, f.gap("query_structure_unresolved", "Dynamic SQL structure/key restrictions are not resolved", n))
	}
	fields := []string{}
	for _, d := range all.deps {
		if d.key != "" {
			fields = parse.AppendUniqueString(fields, d.key)
		}
	}
	u.Check = &analysis.Check{ID: "automatic-python-query", Method: f.route.route.Method, Path: f.route.route.PathPattern, Kind: "sql_query", Fields: fields, Validation: "Assess only requirements established by supplied server code and source-backed form-field policy. A browser form can declare a requirement but does not enforce it on direct HTTP requests. Missing business requirements remain uncertain.", Protection: "Request values must remain data and must not change SQL syntax. Bound values and dynamic identifiers are separate slots."}
	u.Completeness = c
}

// sqlTextSourceExcerpts returns a source excerpt for the source of every
// dependency that no context evidence of the record covers, from the module that
// holds it. The judge reads no file, so the source must travel with the record.
func (f *pythonFlow) sqlTextSourceExcerpts(u *analysis.CandidateUse, all pythonValue) []analysis.Evidence {
	covered := func(sp analysis.Span, extra []analysis.Evidence) bool {
		for _, list := range [][]analysis.Evidence{u.Context, extra} {
			for _, e := range list {
				switch e.Kind {
				case "handler", "invoked_callable", "helper_definition", "selected_callable", "validation_schema", "validation_control", "condition_helper", "referenced_definition", parse.SQLTextSourceExcerptKind:
					if e.Span.File == sp.File && e.Span.StartByte <= sp.StartByte && e.Span.EndByte >= sp.EndByte {
						return true
					}
				}
			}
		}
		return false
	}
	var out []analysis.Evidence
	for _, d := range all.deps {
		sp := d.dep.Source.Span
		if sp.File == "" || sp.EndByte == 0 || covered(sp, out) {
			continue
		}
		mod := f.set.modules[sp.File]
		if mod == nil {
			continue
		}
		if e, ok := parse.SQLTextExcerptEvidence(mod.src, sp); ok {
			out = append(out, e)
		}
	}
	return out
}

func isPyLiteralNode(k string) bool {
	return k == "string" || k == "concatenated_string" || k == "integer" || k == "float" || k == "true" || k == "false" || k == "none"
}

// sqlPieces returns the pieces of the string an expression evaluates to: its
// literal text with a hole for every part that is not literal. dynamic reports a
// part that changes the text but leaves its literal pieces alone (a "%" or
// ".format" operand that is not a literal).
func (f *pythonFlow) sqlPieces(n *sitter.Node, hops int) (pieces []parse.SQLTextPiece, dynamic bool) {
	m := f.module
	hole := []parse.SQLTextPiece{{Hole: true}}
	if n == nil {
		return hole, true
	}
	switch n.Kind() {
	case "string":
		var sb strings.Builder
		flush := func() {
			if sb.Len() > 0 {
				pieces = append(pieces, parse.SQLTextPiece{Text: sb.String()})
				sb.Reset()
			}
		}
		for i := uint(0); i < n.ChildCount(); i++ {
			c := n.Child(i)
			switch c.Kind() {
			case "string_start", "string_end":
			case "interpolation":
				flush()
				pieces = append(pieces, parse.SQLTextPiece{Hole: true})
			default:
				sb.WriteString(pyText(m, c))
			}
		}
		flush()
		return pieces, false
	case "concatenated_string":
		for i := uint(0); i < n.NamedChildCount(); i++ {
			p, d := f.sqlPieces(n.NamedChild(i), hops)
			pieces = append(pieces, p...)
			dynamic = dynamic || d
		}
		return pieces, dynamic
	case "parenthesized_expression":
		if n.NamedChildCount() == 1 {
			return f.sqlPieces(n.NamedChild(0), hops)
		}
	case "binary_operator":
		op := pyText(m, n.ChildByFieldName("operator"))
		l, r := n.ChildByFieldName("left"), n.ChildByFieldName("right")
		if op == "+" {
			lp, ld := f.sqlPieces(l, hops)
			rp, rd := f.sqlPieces(r, hops)
			return append(lp, rp...), ld || rd
		}
		if op == "%" {
			lp, ld := f.sqlPieces(l, hops)
			return lp, ld || r == nil || !isPyLiteralNode(r.Kind())
		}
	case "call":
		fnn := n.ChildByFieldName("function")
		args := pyArgs(n)
		if fnn != nil && fnn.Kind() == "attribute" && pyText(m, fnn.ChildByFieldName("attribute")) == "format" {
			obj := fnn.ChildByFieldName("object")
			if obj != nil && (obj.Kind() == "string" || obj.Kind() == "concatenated_string" || obj.Kind() == "identifier" || obj.Kind() == "parenthesized_expression" || obj.Kind() == "binary_operator") {
				p, d := f.sqlPieces(obj, hops)
				dyn := false
				if a := n.ChildByFieldName("arguments"); a != nil {
					for i := uint(0); i < a.NamedChildCount(); i++ {
						c := a.NamedChild(i)
						if c.Kind() == "keyword_argument" {
							c = c.ChildByFieldName("value")
						}
						if c == nil || !isPyLiteralNode(c.Kind()) {
							dyn = true
						}
					}
				}
				return p, d || dyn
			}
		}
		if f.sqlTextWrapperName(fnn) && len(args) == 1 && n.ChildByFieldName("arguments") != nil && n.ChildByFieldName("arguments").NamedChildCount() == 1 {
			k := args[0].Kind()
			if k == "string" || k == "concatenated_string" || k == "binary_operator" || k == "identifier" || k == "call" || k == "parenthesized_expression" {
				p, d := f.sqlPieces(args[0], hops)
				if !(len(p) == 1 && p[0].Hole) {
					return p, d
				}
			}
		}
	case "identifier":
		if hops >= 2 {
			return hole, true
		}
		return f.sqlIdentifierPieces(n, hops)
	}
	return hole, true
}

func sqlScopeOf(n *sitter.Node) *sitter.Node {
	for p := n.Parent(); p != nil; p = p.Parent() {
		if p.Kind() == "function_definition" || p.Kind() == "module" {
			return p
		}
	}
	return nil
}

// sqlIdentifierPieces follows an identifier to the assignments that precede it in its scope.
func (f *pythonFlow) sqlIdentifierPieces(id *sitter.Node, hops int) ([]parse.SQLTextPiece, bool) {
	name := pyText(f.module, id)
	for scope := sqlScopeOf(id); scope != nil; scope = sqlScopeOf(scope) {
		if p, d, ok := f.sqlAssigned(id, name, scope, hops); ok {
			return p, d
		}
	}
	return []parse.SQLTextPiece{{Hole: true}}, true
}

// sqlAssigned collects assignments of name in one scope. In a function scope only
// assignments before the use count; at module level any top-level assignment counts,
// since a function body runs after the module has loaded.
func (f *pythonFlow) sqlAssigned(id *sitter.Node, name string, scope *sitter.Node, hops int) ([]parse.SQLTextPiece, bool, bool) {
	module := scope.Kind() == "module"
	key := sqlAssignKey{scope.Id(), name}
	all, cached := f.sqlAssign[key]
	if !cached {
		all = f.sqlCollectAssignments(scope, name)
		if f.sqlAssign == nil {
			f.sqlAssign = map[sqlAssignKey][]sqlAssignStep{}
		}
		f.sqlAssign[key] = all
	}
	var steps []sqlAssignStep
	for _, s := range all {
		if module || s.end <= id.StartByte() {
			steps = append(steps, s)
		}
	}
	last := -1
	for i, s := range steps {
		if !s.aug {
			last = i
		}
	}
	if last < 0 {
		return nil, false, false
	}
	var pieces []parse.SQLTextPiece
	dynamic := false
	for _, s := range steps[last:] {
		p, d := f.sqlPieces(s.value, hops+1)
		pieces = append(pieces, p...)
		dynamic = dynamic || d
	}
	return pieces, dynamic, true
}

type sqlAssignKey struct {
	scope uintptr
	name  string
}

// sqlAssignStep is one assignment of a name: its value, whether it is "+=", and
// the byte where the statement ends.
type sqlAssignStep struct {
	value *sitter.Node
	aug   bool
	end   uint
}

// sqlCollectAssignments lists, in source order, the assignments of name directly
// in scope (not in nested functions, classes or lambdas).
func (f *pythonFlow) sqlCollectAssignments(scope *sitter.Node, name string) []sqlAssignStep {
	m := f.module
	var steps []sqlAssignStep
	count := 0
	var walk func(x *sitter.Node)
	walk = func(x *sitter.Node) {
		if x == nil || count > 4000 {
			return
		}
		count++
		switch x.Kind() {
		case "function_definition", "class_definition", "lambda":
			if x.Id() != scope.Id() {
				return
			}
		case "assignment":
			l := x.ChildByFieldName("left")
			if l != nil && l.Kind() == "identifier" && pyText(m, l) == name {
				if r := x.ChildByFieldName("right"); r != nil {
					steps = append(steps, sqlAssignStep{r, false, x.EndByte()})
				}
			}
		case "augmented_assignment":
			l := x.ChildByFieldName("left")
			if l != nil && l.Kind() == "identifier" && pyText(m, l) == name && pyText(m, x.ChildByFieldName("operator")) == "+=" {
				if r := x.ChildByFieldName("right"); r != nil {
					steps = append(steps, sqlAssignStep{r, true, x.EndByte()})
				}
			}
		}
		for i := uint(0); i < x.NamedChildCount(); i++ {
			walk(x.NamedChild(i))
		}
	}
	walk(scope)
	return steps
}
