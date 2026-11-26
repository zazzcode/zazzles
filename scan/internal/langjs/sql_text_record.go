package langjs

import (
	"strconv"
	"strings"
	"sync"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
	"github.com/zazzcode/zazzles/scan/internal/parse"
)

// SQL statement text records (specification 21).
//
// A call that no contract and no package-origin path records is recorded when
// one of its arguments is SQL statement text and a request, stored or session
// value reaches the call. The hook reads only JavaScript syntax: it reduces an
// argument to literal pieces and holes and asks the shared test
// parse.SQLStatementText. It names no driver, package or method.
//
// Two shapes are recorded:
//   - the text case: a value reaches the text argument; those dependencies are in
//     slot sql_text and the dependencies of the other arguments in sql_parameters;
//   - the bound case: no value reaches the text but one reaches another argument
//     of the call; only slot sql_parameters.
//
// Decision D-1: the records made by "a method named query" with no contract
// (pg, mysql2, mysql, mssql) become these records when their text argument is SQL
// statement text. They are built here as a twin of the old record and adopted by
// the check assembly only when no contract binds the call.

// sqlTextState is the per-scan state of the hook, kept on the module set.
type sqlTextState struct {
	mu    sync.Mutex
	infos map[string]*sqlTextInfo
	memo  map[string]bool
}

// sqlTextInfo is what the check assembly needs about a text record: the argument
// that holds the statement text and the limits that are judged, not blocking.
type sqlTextInfo struct {
	arg int
	// judged are limits of the entry flow outside the text and its values.
	judged []analysis.Gap
	// coverage are notes for the claim: a callback argument's body not being read.
	coverage []analysis.Gap
	// twin, when set, is the record the hook would have made for a call that the
	// flow already recorded as a contract-less SQL candidate (D-1). It replaces
	// that record only when no contract binds the call.
	twin *analysis.CandidateUse
}

func (s *moduleSet) sqlTextStore(id string, info *sqlTextInfo) {
	s.sqlText.mu.Lock()
	defer s.sqlText.mu.Unlock()
	if s.sqlText.infos == nil {
		s.sqlText.infos = map[string]*sqlTextInfo{}
	}
	s.sqlText.infos[id] = info
}

func (s *moduleSet) sqlTextInfoFor(id string) *sqlTextInfo {
	s.sqlText.mu.Lock()
	defer s.sqlText.mu.Unlock()
	return s.sqlText.infos[id]
}

// sqlTextPieces reduces an expression to literal text and holes.
type sqlTextCollector struct {
	src   []byte
	call  uint
	nodes int
}

var sqlTextHole = parse.SQLTextPiece{Hole: true}

func jsUnescape(raw string) string {
	if !strings.Contains(raw, `\`) {
		return raw
	}
	var b strings.Builder
	for i := 0; i < len(raw); i++ {
		if raw[i] != '\\' || i+1 >= len(raw) {
			b.WriteByte(raw[i])
			continue
		}
		i++
		switch raw[i] {
		case 'n', 't', 'r', 'f', 'v':
			b.WriteByte(' ')
		case '\n':
		default:
			b.WriteByte(raw[i])
		}
	}
	return b.String()
}

func (c *sqlTextCollector) pieces(n *sitter.Node, depth int, seen map[string]bool) []parse.SQLTextPiece {
	if n == nil {
		return []parse.SQLTextPiece{sqlTextHole}
	}
	c.nodes++
	if c.nodes > 2000 {
		return []parse.SQLTextPiece{sqlTextHole}
	}
	switch n.Kind() {
	case "string":
		t := n.Utf8Text(c.src)
		if len(t) >= 2 {
			t = t[1 : len(t)-1]
		}
		return parse.SQLTextLiteral(jsUnescape(t))
	case "template_string":
		var out []parse.SQLTextPiece
		for i := uint(0); i < n.ChildCount(); i++ {
			ch := n.Child(i)
			switch ch.Kind() {
			case "template_substitution":
				out = append(out, sqlTextHole)
			case "string_fragment":
				out = append(out, parse.SQLTextPiece{Text: ch.Utf8Text(c.src)})
			case "escape_sequence":
				out = append(out, parse.SQLTextPiece{Text: jsUnescape(ch.Utf8Text(c.src))})
			}
		}
		return out
	case "parenthesized_expression", "await_expression", "as_expression", "non_null_expression", "satisfies_expression":
		if n.NamedChildCount() > 0 {
			return c.pieces(n.NamedChild(0), depth, seen)
		}
	case "binary_expression":
		if op := n.ChildByFieldName("operator"); op != nil && op.Utf8Text(c.src) == "+" {
			return append(c.pieces(n.ChildByFieldName("left"), depth, seen), c.pieces(n.ChildByFieldName("right"), depth, seen)...)
		}
	case "identifier":
		if depth < 3 {
			if p, ok := c.resolve(n, depth, seen); ok {
				return p
			}
		}
	}
	return []parse.SQLTextPiece{sqlTextHole}
}

// resolve follows an identifier to its declarator and the earlier assignments in
// the enclosing function (or module) and joins their pieces.
func (c *sqlTextCollector) resolve(id *sitter.Node, depth int, seen map[string]bool) ([]parse.SQLTextPiece, bool) {
	name := id.Utf8Text(c.src)
	if seen[name] {
		return nil, false
	}
	seen[name] = true
	defer delete(seen, name)
	scope := enclosingFunction(id)
	if scope == nil {
		for p := id; p != nil; p = p.Parent() {
			scope = p
		}
	}
	var out []parse.SQLTextPiece
	found := false
	count := 0
	var walk func(x *sitter.Node)
	walk = func(x *sitter.Node) {
		count++
		if count > 20000 || x.StartByte() >= c.call {
			return
		}
		switch x.Kind() {
		case "variable_declarator":
			if nm := x.ChildByFieldName("name"); nm != nil && nm.Kind() == "identifier" && nm.Utf8Text(c.src) == name {
				if v := x.ChildByFieldName("value"); v != nil {
					out = c.pieces(v, depth+1, seen)
					found = true
				}
			}
		case "assignment_expression":
			if l := x.ChildByFieldName("left"); l != nil && l.Kind() == "identifier" && l.Utf8Text(c.src) == name {
				out = c.pieces(x.ChildByFieldName("right"), depth+1, seen)
				found = true
			}
		case "augmented_assignment_expression":
			if l := x.ChildByFieldName("left"); l != nil && l.Kind() == "identifier" && l.Utf8Text(c.src) == name && found {
				if op := x.ChildByFieldName("operator"); op != nil && op.Utf8Text(c.src) == "+=" {
					out = append(out, c.pieces(x.ChildByFieldName("right"), depth+1, seen)...)
				}
			}
		}
		for i := uint(0); i < x.NamedChildCount(); i++ {
			ch := x.NamedChild(i)
			// do not descend into nested functions other than the scope itself
			switch ch.Kind() {
			case "function_declaration", "function_expression", "arrow_function", "method_definition", "function", "generator_function_declaration":
				continue
			}
			walk(ch)
		}
	}
	walk(scope)
	if !found {
		return nil, false
	}
	return out, true
}

// sqlTextArgument reports whether argument i of call n is SQL statement text.
func (f *flow) sqlTextArgument(n *sitter.Node, i int, a *sitter.Node) bool {
	key := f.module.file + ":" + strconv.Itoa(int(n.StartByte())) + ":" + strconv.Itoa(int(n.EndByte())) + ":" + strconv.Itoa(i)
	f.set.sqlText.mu.Lock()
	hit, ok := f.set.sqlText.memo[key]
	f.set.sqlText.mu.Unlock()
	if !ok {
		c := &sqlTextCollector{src: f.module.src, call: n.StartByte()}
		hit = parse.SQLStatementText(c.pieces(a, 0, map[string]bool{})).Matched
		f.set.sqlText.mu.Lock()
		if f.set.sqlText.memo == nil {
			f.set.sqlText.memo = map[string]bool{}
		}
		f.set.sqlText.memo[key] = hit
		f.set.sqlText.mu.Unlock()
	}
	return hit
}

// sqlTextCoverageKind reports flow gap kinds that stay with the record's own
// gaps (value and validation notes, as for every SQL record). Other limits of the
// entry flow are judged limits.
func sqlTextCoverageKind(kind string) bool {
	switch kind {
	case "middleware_unresolved", "query_text_interpolated", "like_pattern_interpolated", "query_document_unvalidated",
		"sink_must_bind_free_text", "validation_free_text_bound", "sink_binding_unverified", "unknown_value", "unknown_transfer":
		return true
	}
	return strings.HasPrefix(kind, "input_validation_") || strings.HasPrefix(kind, "validation_")
}

// sqlTextBuild builds the record for call n when an argument is SQL statement
// text and a value reaches the call. The ID is left to the caller.
func (f *flow) sqlTextBuild(n, fn, args *sitter.Node, values []value) (analysis.CandidateUse, *sqlTextInfo, bool) {
	none := analysis.CandidateUse{}
	if f.client != nil || f.set == nil || n == nil || args == nil || fn == nil || len(values) == 0 {
		return none, nil, false
	}
	if args.Kind() == "template_string" {
		// A tagged template is not recorded: a driver that binds its substitutions
		// would make every value look like text.
		return none, nil, false
	}
	reaches := false
	for _, v := range values {
		if len(v.deps) > 0 {
			reaches = true
			break
		}
	}
	if !reaches {
		return none, nil, false
	}
	var argNodes []*sitter.Node
	for i := uint(0); i < args.NamedChildCount(); i++ {
		argNodes = append(argNodes, args.NamedChild(i))
	}
	textArg := -1
	for i, a := range argNodes {
		if a.Kind() == "spread_element" {
			break
		}
		if f.sqlTextArgument(n, i, a) {
			textArg = i
			break
		}
	}
	if textArg < 0 {
		return none, nil, false
	}
	var textValues, otherValues []value
	var callbackGaps []analysis.Gap
	for i, v := range values {
		if i < len(argNodes) && isFunction(argNodes[i]) {
			// A callback argument is not a value that reaches the call; its body
			// not being traversed is a note, not a blocker.
			kept := []analysis.Gap{}
			for _, g := range v.gaps {
				if g.Kind == "unsupported_callback" {
					callbackGaps = append(callbackGaps, g)
				} else {
					kept = append(kept, g)
				}
			}
			v.gaps = kept
		}
		if i == textArg {
			textValues = append(textValues, v)
		} else {
			otherValues = append(otherValues, v)
		}
	}
	textCase := false
	for _, v := range textValues {
		if len(v.deps) > 0 {
			textCase = true
		}
	}
	combined := value{}
	for _, group := range []struct {
		vs   []value
		slot string
	}{{textValues, analysispacks.SQLTextSlot}, {otherValues, analysispacks.SQLTextParametersSlot}} {
		for _, a := range group.vs {
			a.deps = append([]analysis.Dependency{}, a.deps...)
			for j := range a.deps {
				a.deps[j].SinkSlot = group.slot
			}
			combined = combine(combined, a)
		}
	}
	if len(combined.deps) == 0 {
		return none, nil, false
	}
	var flowGaps, judged []analysis.Gap
	for _, g := range f.gaps {
		if sqlTextCoverageKind(g.Kind) {
			flowGaps = append(flowGaps, g)
		} else {
			judged = append(judged, g)
		}
	}
	gaps := append(append([]analysis.Gap{}, flowGaps...), combined.gaps...)
	if textCase {
		gaps = append(gaps, f.gap("query_text_interpolated", "request-controlled value is built into executable query text", n))
	}
	// The validation notes read the flow's facts; unlike a contract record this one
	// does not mark the field as consumed, so no other record changes.
	for _, field := range requestFields(values) {
		gaps = append(gaps, f.sinkValidationGap(field, textCase, n))
	}
	use := analysis.CandidateUse{EntryID: f.entry.ID, InvocationContextID: f.invocation.ID, Kind: "sql_query_candidate",
		Sink: f.module.evidence("sql_query_candidate", n), Dependencies: combined.deps, Context: append([]analysis.Evidence{}, f.context...), Gaps: gaps,
		APIModel:   analysispacks.SQLContract(analysispacks.SQLTextContract),
		Assessment: analysis.Assessment{Status: "not_run"}}
	return use, &sqlTextInfo{arg: textArg, judged: judged, coverage: callbackGaps}, true
}

// sqlTextRecord records a SQL query candidate for a call that has an argument of
// SQL statement text, when no contract or package path recorded the call.
// Nothing it does changes the flow's value, gaps, facts or existing records.
func (f *flow) sqlTextRecord(n, fn, args *sitter.Node, values []value) {
	if f.client != nil || f.set == nil || n == nil {
		return
	}
	span := parse.Span(f.module.file, n)
	for _, u := range f.uses {
		if (u.Kind == "sql_query_candidate" || u.Kind == "nosql_query_candidate") && u.Sink.Span == span {
			return
		}
	}
	id := "use:" + f.invocation.ID + ":" + f.module.file + ":" + strconv.Itoa(int(n.StartByte())) + ":sql-text"
	for _, u := range f.uses {
		if u.ID == id {
			return
		}
	}
	use, info, ok := f.sqlTextBuild(n, fn, args, values)
	if !ok {
		return
	}
	use.ID = id
	f.uses = append(f.uses, use)
	f.set.sqlTextStore(id, info)
}

// sqlTextTwin keeps, for a call the flow recorded as a contract-less SQL
// candidate (a method named query), the record the text hook would make. The
// check assembly adopts it when no contract binds the call (D-1).
func (f *flow) sqlTextTwin(n, fn, args *sitter.Node, values []value, oldID string) {
	use, info, ok := f.sqlTextBuild(n, fn, args, values)
	if !ok {
		return
	}
	use.ID = oldID
	info.twin = &use
	f.set.sqlTextStore(oldID, info)
}

// sqlTextAdopt replaces the contract-less record's dependencies, gaps and model
// with its text twin's.
func sqlTextAdopt(use *analysis.CandidateUse, info *sqlTextInfo) {
	use.Dependencies = info.twin.Dependencies
	use.Gaps = info.twin.Gaps
	use.APIModel = info.twin.APIModel
}

// sqlTextBinding is the sink binding of a text record: the callee expression.
func (s *moduleSet) sqlTextBinding(use analysis.CandidateUse) []analysis.Evidence {
	m := s.modules[use.Sink.Span.File]
	if m == nil {
		return nil
	}
	call := parse.NodeAt(m.tree.RootNode(), use.Sink.Span.StartByte, use.Sink.Span.EndByte)
	if call == nil || call.Kind() != "call_expression" {
		return nil
	}
	fn := call.ChildByFieldName("function")
	if fn == nil {
		return nil
	}
	return []analysis.Evidence{m.evidence("sink_binding", fn)}
}

// sqlTextEvidenceKinds are the context kinds the judge sends for a text record.
var sqlTextEvidenceKinds = map[string]bool{"handler": true, "invoked_callable": true, "helper_definition": true, "selected_callable": true,
	"validation_schema": true, "validation_control": true, "condition_helper": true, "referenced_definition": true, parse.SQLTextSourceExcerptKind: true}

func sqlTextCovered(context []analysis.Evidence, sp analysis.Span) bool {
	for _, e := range context {
		if sqlTextEvidenceKinds[e.Kind] && e.Span.File == sp.File && e.Span.StartByte <= sp.StartByte && e.Span.EndByte >= sp.EndByte {
			return true
		}
	}
	return false
}

// sqlTextExcerpts attaches the source the judge reads: the file of the call, and
// the file of a dependency's source or transfer that no context evidence covers.
func (s *moduleSet) sqlTextExcerpts(use *analysis.CandidateUse) {
	add := func(sp analysis.Span) {
		if m := s.modules[sp.File]; m != nil {
			if ev, ok := parse.SQLTextExcerptEvidence(m.src, sp); ok {
				use.Context = append(use.Context, ev)
			}
		}
	}
	// The judge reads no file: the sink must lie inside one excerpt of its own file,
	// whatever other evidence also covers it.
	add(use.Sink.Span)
	for _, d := range use.Dependencies {
		for _, e := range append([]analysis.Evidence{d.Source}, d.Transfers...) {
			if e.Span.File != "" && e.Span.File != use.Sink.Span.File && !sqlTextCovered(use.Context, e.Span) {
				add(e.Span)
			}
		}
	}
}

// sqlTextFinish applies the text record's claim rules after the shared claim
// assembly: the SQL text node is evidence, and limits of the entry flow and of
// the handler's control flow are judged limits, in Coverage where the model sees
// them, never blockers. It attaches the source excerpts.
func (s *moduleSet) sqlTextFinish(use *analysis.CandidateUse, info *sqlTextInfo) {
	c := use.Completeness
	if c == nil {
		return
	}
	if m := s.modules[use.Sink.Span.File]; m != nil {
		if call := parse.NodeAt(m.tree.RootNode(), use.Sink.Span.StartByte, use.Sink.Span.EndByte); call != nil {
			if args := call.ChildByFieldName("arguments"); args != nil {
				if node := args.NamedChild(uint(info.arg)); node != nil && args.Kind() != "template_string" {
					c.Evidence["query_text"] = []analysis.Evidence{m.evidence("query_text", node)}
				}
			}
		}
	}
	same := func(list []analysis.Gap, g analysis.Gap) bool {
		for _, o := range list {
			if o.Kind == g.Kind && o.At == g.At {
				return true
			}
		}
		return false
	}
	kept := []analysis.Gap{}
	var judged []analysis.Gap
	for _, g := range c.Blockers {
		if g.Kind == "control_flow_unresolved" || g.Kind == "unsupported_control_flow" || g.Kind == "branch_exit" {
			if !same(judged, g) {
				judged = append(judged, g)
			}
			continue
		}
		kept = append(kept, g)
	}
	for _, g := range info.judged {
		if !same(judged, g) && !same(kept, g) {
			judged = append(judged, g)
		}
	}
	c.Blockers = kept
	for _, g := range info.coverage {
		if !same(c.Coverage, g) {
			c.Coverage = append(c.Coverage, g)
		}
	}
	for _, g := range judged {
		c.Judged = append(c.Judged, g)
		if !same(c.Coverage, g) {
			c.Coverage = append(c.Coverage, g)
		}
	}
	s.sqlTextExcerpts(use)
}

// sqlTextPrepare runs before the shared evidence refinement. "Call receiving
// checked input lacks a definition" about the sink call itself, or about a call
// that encloses it (res.json(await db.run(...))), is not a limit on the values
// that reach the sink; the enclosing one stays visible in Coverage. Left as a
// blocker it would also hide that the middleware chain is supplied.
func sqlTextPrepare(use *analysis.CandidateUse) {
	c := use.Completeness
	if c == nil {
		return
	}
	sink := use.Sink.Span
	kept := []analysis.Gap{}
	for _, g := range c.Blockers {
		if g.Kind == "input_helper_unresolved" && g.At.File == sink.File {
			if g.At == sink {
				continue
			}
			if g.At.StartByte <= sink.StartByte && g.At.EndByte >= sink.EndByte {
				c.Coverage = append(c.Coverage, g)
				continue
			}
		}
		kept = append(kept, g)
	}
	c.Blockers = kept
}
