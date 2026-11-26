package langphp

import (
	"regexp"
	"sort"
	"strconv"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
	"github.com/zazzcode/zazzles/scan/internal/parse"
)

// SQL text records (detection generalization 21). A call that no contract and
// no package-origin path records, and that passes SQL statement text, is
// recorded as a sql_query_candidate with the contract sql-text-v1 when a
// request, stored or session value reaches the call. This file only reads PHP
// syntax: it reduces an argument to literal pieces with holes and asks
// parse.SQLStatementText. It names no driver; the statement structure it knows
// is "a variable assigned from a call that took SQL text, later used as the
// receiver or an argument of a call that carries values".
//
// One record per statement. A statement prepared from text and bound later
// (`$s = $c->prepare($sql); $s->bindParam(..); $s->execute([..])`) gets one
// record, anchored at the first call that carries a value; later calls of the
// same statement add their values to it. A statement a contract tracks is left
// to the contract (it records at execute()).

// sqlTextState is the per-run state of the hook.
type sqlTextState struct {
	assigns    map[string][]sqlTextAssign
	statements map[string]*sqlTextStatement
	absorbed   map[string]bool
}

// sqlTextStatement is one statement's record under construction.
type sqlTextStatement struct {
	useID  string
	module *phpModule
	sink   *sitter.Node
	// text is the statement text value; textInSlot says its dependencies belong
	// to slot sql_text (the text was an argument of the recorded call).
	text       phpValue
	textInSlot bool
	params     phpValue
	// query is the query_text evidence; prepared is extra context evidence.
	query    []analysis.Evidence
	prepared []analysis.Evidence
}

type sqlTextAssign struct {
	end   uint
	op    string
	right *sitter.Node
}

func (s *phpSet) sqlTextStateInit() *sqlTextState {
	if s.sqlText == nil {
		s.sqlText = &sqlTextState{assigns: map[string][]sqlTextAssign{}, statements: map[string]*sqlTextStatement{}, absorbed: map[string]bool{}}
	}
	return s.sqlText
}

var sqlTextVarRe = regexp.MustCompile(`\{\$[^}]*\}|\$\{[^}]*\}|\$[A-Za-z_][A-Za-z0-9_]*(\[[^\]]*\]|->[A-Za-z_]\w*)?`)

func sqlTextPiecesMatch(p []parse.SQLTextPiece) bool {
	return len(p) > 0 && parse.SQLStatementText(p).Matched
}

// sqlTextFromValue collects the literal text a flow value holds; a part the
// flow could not read as text is a hole.
func sqlTextFromValue(v phpValue) [][]parse.SQLTextPiece {
	if len(v.pieces) > 0 {
		out := make([]parse.SQLTextPiece, 0, len(v.pieces))
		for _, p := range v.pieces {
			if p.dynamic {
				out = append(out, parse.SQLTextPiece{Hole: true})
			} else {
				out = append(out, parse.SQLTextPiece{Text: p.text})
			}
		}
		return [][]parse.SQLTextPiece{out}
	}
	if phpConstantText(v) {
		return [][]parse.SQLTextPiece{parse.SQLTextLiteral(v.literals[0].text)}
	}
	if v.prefix != "" {
		return [][]parse.SQLTextPiece{{{Text: v.prefix}, {Hole: true}}}
	}
	if v.template != "" {
		t := phpUnquote(v.template)
		var out []parse.SQLTextPiece
		last := 0
		for _, loc := range sqlTextVarRe.FindAllStringIndex(t, -1) {
			if loc[0] > last {
				out = append(out, parse.SQLTextPiece{Text: t[last:loc[0]]})
			}
			out = append(out, parse.SQLTextPiece{Hole: true})
			last = loc[1]
		}
		if last < len(t) {
			out = append(out, parse.SQLTextPiece{Text: t[last:]})
		}
		return [][]parse.SQLTextPiece{out}
	}
	// A finite alternative set: each candidate is a possible text.
	var out [][]parse.SQLTextPiece
	for _, l := range v.literals {
		out = append(out, parse.SQLTextLiteral(l.text))
	}
	return out
}

func sqlTextValueMatches(v phpValue) bool {
	for _, p := range sqlTextFromValue(v) {
		if sqlTextPiecesMatch(p) {
			return true
		}
	}
	return false
}

func (f *phpFlow) sqlTextAssigns(m *phpModule, scope *sitter.Node, name string) []sqlTextAssign {
	st := f.set.sqlTextStateInit()
	key := m.file + "\x00" + name + "\x00" + sqlTextPos(scope.StartByte()) + "-" + sqlTextPos(scope.EndByte())
	if a, ok := st.assigns[key]; ok {
		return a
	}
	var out []sqlTextAssign
	var walk func(n *sitter.Node)
	walk = func(n *sitter.Node) {
		switch n.Kind() {
		case "function_definition", "method_declaration", "anonymous_function", "arrow_function":
			if n.StartByte() != scope.StartByte() || n.EndByte() != scope.EndByte() {
				return
			}
		case "assignment_expression", "augmented_assignment_expression":
			if l := phpField(n, "left"); l != nil && l.Kind() == "variable_name" && phpText(m, l) == name {
				op := "="
				if n.Kind() == "augmented_assignment_expression" {
					op = ".="
					for i := uint(0); i < n.ChildCount(); i++ {
						if c := n.Child(i); c != nil && !c.IsNamed() {
							op = strings.TrimSpace(c.Utf8Text(m.src))
						}
					}
				}
				out = append(out, sqlTextAssign{end: n.EndByte(), op: op, right: phpField(n, "right")})
			}
		}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			if c := n.NamedChild(i); c != nil {
				walk(c)
			}
		}
	}
	walk(scope)
	sort.SliceStable(out, func(i, j int) bool { return out[i].end < out[j].end })
	st.assigns[key] = out
	return out
}

func sqlTextScopeNode(n *sitter.Node) *sitter.Node {
	for p := n.Parent(); p != nil; p = p.Parent() {
		switch p.Kind() {
		case "function_definition", "method_declaration", "anonymous_function", "arrow_function", "program":
			return p
		}
	}
	return nil
}

// sqlTextSyntax derives the text of an expression from syntax alone: literals,
// interpolation, concatenation, sprintf and the assignments of a variable
// before the call. Anything else is a hole.
func (f *phpFlow) sqlTextSyntax(m *phpModule, n *sitter.Node, before uint, depth int) []parse.SQLTextPiece {
	hole := []parse.SQLTextPiece{{Hole: true}}
	if n == nil || depth > 8 {
		return hole
	}
	switch n.Kind() {
	case "string":
		if t, ok := phpStringLiteral(m, n); ok {
			return parse.SQLTextLiteral(t)
		}
		return hole
	case "encapsed_string":
		var out []parse.SQLTextPiece
		for i := uint(0); i < n.ChildCount(); i++ {
			c := n.Child(i)
			if c == nil {
				continue
			}
			if c.Kind() == "string_content" {
				out = append(out, parse.SQLTextPiece{Text: c.Utf8Text(m.src)})
			} else if c.IsNamed() {
				if c.Kind() == "variable_name" {
					out = append(out, f.sqlTextSyntax(m, c, before, depth+1)...)
				} else {
					out = append(out, parse.SQLTextPiece{Hole: true})
				}
			}
		}
		return out
	case "parenthesized_expression":
		return f.sqlTextSyntax(m, n.NamedChild(0), before, depth+1)
	case "binary_expression":
		op := ""
		for i := uint(0); i < n.ChildCount(); i++ {
			if c := n.Child(i); c != nil && !c.IsNamed() {
				op = strings.TrimSpace(c.Utf8Text(m.src))
			}
		}
		if op == "." {
			return append(f.sqlTextSyntax(m, phpField(n, "left"), before, depth+1), f.sqlTextSyntax(m, phpField(n, "right"), before, depth+1)...)
		}
		return hole
	case "function_call_expression":
		name := strings.ToLower(strings.TrimPrefix(phpText(m, phpField(n, "function")), "\\"))
		if name == "sprintf" || name == "vsprintf" {
			if args := phpArgs(n); len(args) > 0 {
				var res []parse.SQLTextPiece
				for _, p := range f.sqlTextSyntax(m, args[0], before, depth+1) {
					if p.Hole {
						res = append(res, p)
						continue
					}
					text := strings.NewReplacer("%s", "\x00", "%d", "\x00").Replace(p.Text)
					for i, s := range strings.Split(text, "\x00") {
						if i > 0 {
							res = append(res, parse.SQLTextPiece{Hole: true})
						}
						if s != "" {
							res = append(res, parse.SQLTextPiece{Text: s})
						}
					}
				}
				return res
			}
		}
		return hole
	case "variable_name":
		scope := sqlTextScopeNode(n)
		if scope == nil {
			return hole
		}
		var acc []parse.SQLTextPiece
		found := false
		for _, a := range f.sqlTextAssigns(m, scope, phpText(m, n)) {
			if a.end > before || a.right == nil {
				continue
			}
			switch a.op {
			case "=":
				acc = f.sqlTextSyntax(m, a.right, a.end, depth+1)
				found = true
			case ".=":
				acc = append(append([]parse.SQLTextPiece{}, acc...), f.sqlTextSyntax(m, a.right, a.end, depth+1)...)
				found = true
			}
		}
		if !found {
			return hole
		}
		return acc
	}
	return hole
}

// sqlTextArgument reports whether argument i is SQL statement text, from the
// flow value first and from syntax when the value kept no text.
func (f *phpFlow) sqlTextArgument(node *sitter.Node, v phpValue, before uint) bool {
	if sqlTextValueMatches(v) {
		return true
	}
	return sqlTextPiecesMatch(f.sqlTextSyntax(f.module, node, before, 0))
}

func sqlTextPos(b uint) string { return strconv.FormatUint(uint64(b), 10) }

// sqlTextAssignedTo returns the assignment `$name = <call n>` that a call is
// the whole right side of.
func sqlTextAssignedTo(n *sitter.Node) *sitter.Node {
	p := n.Parent()
	if p == nil || p.Kind() != "assignment_expression" {
		return nil
	}
	if r := phpField(p, "right"); r == nil || r.StartByte() != n.StartByte() || r.EndByte() != n.EndByte() {
		return nil
	}
	if l := phpField(p, "left"); l != nil && l.Kind() == "variable_name" {
		return p
	}
	return nil
}

func sqlTextContractRecordKind(kind string) bool {
	return kind == "sql_query_candidate" || kind == "nosql_query_candidate"
}

// sqlTextContractStatement reports a statement a contract records at execute():
// the prepared text was built from values, or a bound value carries a
// dependency.
func sqlTextContractStatement(rv phpValue) bool {
	if rv.binding != "db_statement" || rv.sqlText == nil {
		return false
	}
	if rv.sqlText.built {
		return true
	}
	for _, p := range rv.sqlParams {
		if len(p.deps) > 0 {
			return true
		}
	}
	return false
}

// sqlTextCall is the hook, run after the contract paths of a call. before is
// the number of records when the call began, so a record made inside the call
// (a contract, or a helper the call expanded) is seen.
func (f *phpFlow) sqlTextCall(n *sitter.Node, nodes []*sitter.Node, values []phpValue, result phpValue, before int) {
	if n == nil || f.module == nil || f.report == nil || len(nodes) == 0 || len(values) < len(nodes) {
		return
	}
	anyDeps := false
	for _, v := range values {
		if len(v.deps) > 0 {
			anyDeps = true
			break
		}
	}
	if !anyDeps {
		return
	}
	m := f.module
	for _, old := range f.report.Uses[min(before, len(f.report.Uses)):] {
		if sqlTextContractRecordKind(old.Kind) && old.EntryID == f.invocation.EntryID {
			return
		}
	}
	sink := m.evidence("sql_query_candidate", n)
	for _, old := range f.report.Uses {
		if sqlTextContractRecordKind(old.Kind) && old.EntryID == f.invocation.EntryID && old.Sink.Span == sink.Span {
			return
		}
	}
	st := f.set.sqlTextStateInit()
	callKey := f.invocation.ID + "\x00" + m.file + "\x00" + sqlTextPos(n.StartByte())
	if st.absorbed[callKey] {
		return
	}

	textIdx := -1
	for i, node := range nodes {
		if f.sqlTextArgument(node, values[i], n.StartByte()) {
			textIdx = i
			break
		}
	}
	if textIdx >= 0 {
		if result.binding != "" || result.sqlText != nil {
			// A tracked statement or result: the contract paths own the call.
			return
		}
		params := phpValue{}
		for i, v := range values {
			if i != textIdx {
				params = phpCombine(params, phpSlot(v, parse.SQLTextParametersSlot))
			}
		}
		if len(values[textIdx].deps) == 0 && len(params.deps) == 0 {
			return
		}
		s := &sqlTextStatement{module: m, sink: n, text: values[textIdx], textInSlot: true, params: params, query: []analysis.Evidence{m.evidence("query_text", nodes[textIdx])}}
		st.absorbed[callKey] = true
		f.sqlTextEmit(s)
		if assignment := sqlTextAssignedTo(n); assignment != nil {
			st.statements[f.sqlTextStatementKey(m, phpText(m, phpField(assignment, "left")), assignment.EndByte())] = s
		}
		return
	}

	// Prepared then bound: the call carries values; the statement is a variable
	// that holds the text, as the receiver or as an argument.
	var carriers []*sitter.Node
	method := ""
	var receiver *sitter.Node
	if n.Kind() == "member_call_expression" {
		method = phpText(m, phpField(n, "name"))
		if obj := phpField(n, "object"); obj != nil && obj.Kind() == "variable_name" {
			receiver = obj
			carriers = append(carriers, obj)
		}
	}
	for _, node := range nodes {
		if node.Kind() == "variable_name" {
			carriers = append(carriers, node)
		}
	}
	for _, node := range carriers {
		rv := f.eval(node)
		if node == receiver && rv.binding == "db_statement" && (method == "bindParam" || method == "bindValue") {
			// The contract records the statement at execute().
			continue
		}
		if sqlTextContractStatement(rv) || (rv.sqlText != nil && rv.binding != "db_statement") {
			// A statement a contract tracks (a Doctrine statement, or a prepared
			// one with bound values) is recorded by the contract where it runs.
			continue
		}
		s, key := f.sqlTextResolveStatement(node, n.StartByte(), rv)
		if key == "" {
			continue
		}
		if prior := st.statements[key]; prior != nil {
			s = prior
		}
		params := s.params
		added := false
		for i, v := range values {
			if nodes[i] == node {
				continue
			}
			params = phpCombine(params, phpSlot(v, parse.SQLTextParametersSlot))
			if len(v.deps) > 0 {
				added = true
			}
		}
		if !added {
			continue
		}
		params.gaps = phpMergeGaps(params.gaps, nil)
		s.params = params
		st.absorbed[callKey] = true
		st.statements[key] = s
		if s.useID == "" {
			s.module, s.sink = m, n
		}
		f.sqlTextEmit(s)
		return
	}
}

func (f *phpFlow) sqlTextStatementKey(m *phpModule, name string, end uint) string {
	return f.invocation.ID + "\x00" + m.file + "\x00" + name + "\x00" + sqlTextPos(end)
}

// sqlTextResolveStatement finds the text of the statement a variable holds at a
// call, from the value a contract tracked or from the assignment before the
// call. The key identifies the statement: its variable and the assignment that
// made it. An empty key means the variable holds no SQL statement.
func (f *phpFlow) sqlTextResolveStatement(node *sitter.Node, before uint, rv phpValue) (*sqlTextStatement, string) {
	m := f.module
	scope := sqlTextScopeNode(node)
	name := phpText(m, node)
	var assign *sqlTextAssign
	if scope != nil {
		for _, a := range f.sqlTextAssigns(m, scope, name) {
			if a.end > before {
				continue
			}
			a := a
			assign = nil
			if a.op == "=" && a.right != nil {
				assign = &a
			}
		}
	}
	tracked := rv.binding == "db_statement" && rv.sqlText != nil
	if assign != nil {
		key := f.sqlTextStatementKey(m, name, assign.end)
		if tracked && sqlTextValueMatches(*rv.sqlText) {
			s := &sqlTextStatement{module: m, text: *rv.sqlText, query: append([]analysis.Evidence{}, rv.sqlTextEvidence...), prepared: append([]analysis.Evidence{}, rv.sqlTextEvidence...)}
			if len(s.query) == 0 {
				s.query = []analysis.Evidence{m.evidence("query_text", node)}
			}
			return s, key
		}
		right := assign.right
		switch right.Kind() {
		case "member_call_expression", "scoped_call_expression", "function_call_expression":
			for _, a := range phpArgs(right) {
				if sqlTextPiecesMatch(f.sqlTextSyntax(m, a, assign.end, 0)) {
					return &sqlTextStatement{module: m, query: []analysis.Evidence{m.evidence("query_text", a)}}, key
				}
			}
		}
		return nil, ""
	}
	if tracked && sqlTextValueMatches(*rv.sqlText) {
		scopeStart := uint(0)
		if scope != nil {
			scopeStart = scope.StartByte()
		}
		s := &sqlTextStatement{module: m, text: *rv.sqlText, query: append([]analysis.Evidence{}, rv.sqlTextEvidence...), prepared: append([]analysis.Evidence{}, rv.sqlTextEvidence...)}
		if len(s.query) == 0 {
			s.query = []analysis.Evidence{m.evidence("query_text", node)}
		}
		return s, f.sqlTextStatementKey(m, name, scopeStart)
	}
	return nil, ""
}

// sqlTextEmit builds the record of a statement, or rebuilds it in place when a
// later call added values.
func (f *phpFlow) sqlTextEmit(s *sqlTextStatement) {
	m := s.module
	n := s.sink
	text := s.text
	all := s.params
	if s.textInSlot {
		all = phpCombine(phpSlot(text, parse.SQLTextSlot), s.params)
	}
	if len(all.deps) == 0 {
		return
	}
	sinkEv := m.evidence("sql_query_candidate", n)
	u := f.addUseAt("sql_query_candidate", sinkEv, all)
	idx := len(f.report.Uses) - 1
	if s.useID != "" {
		// A statement's record already exists: replace it where it is, so its place
		// in the report and its id stay.
		for i := len(f.report.Uses) - 2; i >= 0; i-- {
			if f.report.Uses[i].ID == s.useID {
				idx = i
				break
			}
		}
	}
	s.useID = u.ID
	binding := []analysis.Evidence{m.evidence("sink_binding", phpCallee(n))}
	u.Context = append(u.Context, binding...)
	u.APIModel = analysispacks.SQLContract(analysispacks.SQLTextContract)
	if s.textInSlot && text.built {
		u.Gaps = append(u.Gaps, f.gap("query_text_interpolated", "PHP string interpolation constructs executable SQL text", n))
	}
	for _, d := range all.deps {
		kind := "input_validation_absent"
		if d.protection == "numeric" {
			kind = "validation_type_only"
		}
		u.Gaps = append(u.Gaps, f.gap(kind, "No complete business-policy enforcement established for "+d.container+"."+d.key, n))
	}
	c := &analysis.Completeness{ClaimKind: "injection", Required: []string{"input_source", "sink_binding", "invoked_callable", "control_flow"}, Evidence: map[string][]analysis.Evidence{"sink_binding": binding, "invoked_callable": {f.entryEvidence()}, "control_flow": append([]analysis.Evidence{m.evidence("operation", n)}, f.context...)}, Blockers: []analysis.Gap{}, Coverage: append([]analysis.Gap{}, u.Gaps...), Scope: "Bounded PHP source-to-operation flow; SQL text and bound parameters have separate roles."}
	for _, d := range all.deps {
		if d.dep.Source.Kind == "input_source" || d.dep.Source.Kind == "storage_source" {
			c.Evidence["input_source"] = append(c.Evidence["input_source"], d.dep.Source)
		}
	}
	c.Evidence["query_text"] = append([]analysis.Evidence{}, s.query...)
	u.Context = append(u.Context, s.prepared...)
	// Blockers are limits on the SQL text and on the values reaching the call; a
	// limit elsewhere in the flow is a judged limit (specification 20).
	blocking := func(kind string) bool {
		switch kind {
		case "php_parameter_unresolved", "php_value_unresolved", "php_call_unresolved", "php_loop_unresolved", "php_expression_unresolved", "php_global_unresolved", "work_limit", "dependency_limit", "transfer_limit":
			return true
		}
		return false
	}
	for _, g := range append(append([]analysis.Gap{}, text.gaps...), all.gaps...) {
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
	if s.textInSlot && text.built && len(text.deps) == 0 {
		c.Blockers = append(c.Blockers, f.gap("query_structure_unresolved", "Dynamic SQL structure/key restrictions are not resolved", n))
	}
	fields := []string{}
	for _, d := range all.deps {
		if d.key != "" {
			fields = parse.AppendUniqueString(fields, d.key)
		}
	}
	entryPath := ""
	if f.entry.HTTP != nil {
		entryPath = f.entry.HTTP.Path
	}
	u.Check = &analysis.Check{ID: "automatic-php-query", Path: entryPath, Kind: "sql_query", Fields: fields, Validation: "Assess only requirements established by supplied server code and source-backed form-field policy. A browser form can declare a requirement but does not enforce it on direct HTTP requests. Missing business requirements remain uncertain.", Protection: "Request values must remain data and must not change SQL syntax. Bound values and dynamic identifiers are separate slots."}
	var constructed []phpDep
	for _, d := range all.deps {
		if d.dep.SinkSlot == parse.SQLTextSlot {
			constructed = append(constructed, d)
		}
	}
	if stored := phpStoredOnlyBlockers(constructed, u.Sink.Span); len(stored) > 0 {
		c.Blockers = append(c.Blockers, stored...)
		f.set.storedOnly[u.ID] = phpStoredKeys(constructed)
	}
	u.Completeness = c
	f.sqlTextExcerpts(u, m, all)
	if idx != len(f.report.Uses)-1 {
		f.report.Uses[idx] = *u
		f.report.Uses = f.report.Uses[:len(f.report.Uses)-1]
	}
}

// sqlTextExcerpts attaches the source the judge reads: an excerpt of the sink's
// file and, for a file that holds a value's source or the statement text and no
// context evidence covers, an excerpt of that file.
func (f *phpFlow) sqlTextExcerpts(u *analysis.CandidateUse, m *phpModule, all phpValue) {
	attach := func(file string, at analysis.Span, force bool) {
		if !force {
			for _, e := range u.Context {
				if e.Span.File == file && sqlTextJudgeKind(e.Kind) {
					return
				}
			}
		}
		src := m.src
		if file != m.file {
			other := f.set.modules[file]
			if other == nil {
				return
			}
			src = other.src
		}
		if ev, ok := parse.SQLTextExcerptEvidence(src, at); ok {
			u.Context = append(u.Context, ev)
		}
	}
	attach(u.Sink.Span.File, u.Sink.Span, true)
	for _, d := range all.deps {
		if sp := d.dep.Source.Span; sp.File != "" && sp.File != u.Sink.Span.File {
			attach(sp.File, sp, false)
		}
	}
	for _, e := range u.Completeness.Evidence["query_text"] {
		if e.Span.File != "" && e.Span.File != u.Sink.Span.File {
			attach(e.Span.File, e.Span, false)
		}
	}
}

// sqlTextJudgeKind lists the context evidence kinds the judge sends for a SQL
// text record.
func sqlTextJudgeKind(kind string) bool {
	switch kind {
	case "handler", "invoked_callable", "helper_definition", "selected_callable", "validation_schema", "validation_control", "condition_helper", "referenced_definition", parse.SQLTextSourceExcerptKind:
		return true
	}
	return false
}
