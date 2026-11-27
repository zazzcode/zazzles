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
	memo  map[string]sqlTextRead
}

// sqlTextInfo is what the check assembly needs about a text record: the argument
// that holds the statement text and the limits that are judged, not blocking.
type sqlTextInfo struct {
	arg int
	// textSpan is the text node: the argument of the call, or for a statement
	// prepared apart the argument of the preparing call.
	textSpan analysis.Span
	// id, when set, replaces the record's id: a prepared statement has one record
	// whatever the call that first carries data.
	id string
	// pieces are the real pieces of the text; placement is their statement shape.
	placement *analysis.Evidence
	// defs are definitions the text was read through (helpers, constants of
	// other scopes and files, the tag function, the preparing statement).
	defs []analysis.Span
	// tag is the tag expression of a tagged template that holds the text.
	tag *analysis.Span
	// tagDef is the definition of the tag function when it is in the scanned
	// source. Without it nothing shows what the tag does with its substitutions.
	tagDef *analysis.Span
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

// sqlTextRead is the memoized reading of one argument.
type sqlTextRead struct {
	hit    bool
	pieces []parse.SQLTextPiece
	defs   []analysis.Span
}

// sqlTextArgument reads argument a of call n as pieces and reports whether it is
// SQL statement text.
func (f *flow) sqlTextArgument(n *sitter.Node, i int, a *sitter.Node) sqlTextRead {
	key := f.module.file + ":" + strconv.Itoa(int(n.StartByte())) + ":" + strconv.Itoa(int(n.EndByte())) + ":" + strconv.Itoa(i)
	f.set.sqlText.mu.Lock()
	r, ok := f.set.sqlText.memo[key]
	f.set.sqlText.mu.Unlock()
	if !ok {
		r = f.sqlTextReadNode(a, n.StartByte())
		f.set.sqlText.mu.Lock()
		if f.set.sqlText.memo == nil {
			f.set.sqlText.memo = map[string]sqlTextRead{}
		}
		f.set.sqlText.memo[key] = r
		f.set.sqlText.mu.Unlock()
	}
	return r
}

func (f *flow) sqlTextReadNode(a *sitter.Node, at uint) sqlTextRead {
	c := newSQLTextCollector(f.set, f.module, at)
	pieces := c.pieces(a, 0, map[string]bool{})
	return sqlTextRead{hit: parse.SQLStatementText(pieces).Matched, pieces: pieces, defs: c.defs}
}

// sqlTextBuild builds the record for call n when an argument is SQL statement
// text and a value reaches the call, or when the call carries a value for a
// statement prepared apart (prepared) or is a tagged template. The ID is left to
// the caller.
func (f *flow) sqlTextBuild(n, fn, args *sitter.Node, values []value, prepared bool) (analysis.CandidateUse, *sqlTextInfo, bool) {
	none := analysis.CandidateUse{}
	if f.client != nil || f.set == nil || n == nil || args == nil || fn == nil || len(values) == 0 {
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
	textArg := -1
	var read sqlTextRead
	var textNode *sitter.Node
	var tagCall *sitter.Node
	var prepDefs []analysis.Span
	if args.Kind() == "template_string" {
		// A tagged template. Its own text is the statement; a template that is an
		// argument of a call is read as that call's text argument instead.
		if p := n.Parent(); p != nil && p.Kind() == "arguments" || !prepared {
			return none, nil, false
		}
		read = f.sqlTextReadNode(n, n.StartByte())
		if !read.hit {
			return none, nil, false
		}
		textNode, tagCall = args, n
		for i := uint(0); i < args.NamedChildCount(); i++ {
			argNodes = append(argNodes, args.NamedChild(i))
		}
	} else {
		for i := uint(0); i < args.NamedChildCount(); i++ {
			argNodes = append(argNodes, args.NamedChild(i))
		}
		for i, a := range argNodes {
			if a.Kind() == "spread_element" {
				break
			}
			if r := f.sqlTextArgument(n, i, a); r.hit {
				textArg, read, textNode = i, r, a
				tagCall = taggedTemplate(a)
				break
			}
		}
		if textArg < 0 {
			if !prepared {
				return none, nil, false
			}
			var ok bool
			textNode, read, prepDefs, ok = f.sqlTextPreparing(n, fn)
			if !ok {
				return none, nil, false
			}
		}
	}
	var textValues, otherValues []value
	var callbackGaps []analysis.Gap
	for i, v := range values {
		if args.Kind() != "template_string" && i < len(argNodes) && isFunction(argNodes[i]) {
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
		if i == textArg || args.Kind() == "template_string" {
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
	// For a tagged template the scanner does not say the value is built into the
	// text: the tag may bind it. The judge is told it is a tagged template.
	if textCase && tagCall == nil {
		gaps = append(gaps, f.gap("query_text_interpolated", "request-controlled value is built into executable query text", n))
	}
	// The validation notes read the flow's facts; unlike a contract record this one
	// does not mark the field as consumed, so no other record changes.
	for _, field := range requestFields(values) {
		gaps = append(gaps, f.sinkValidationGap(field, textCase && tagCall == nil, n))
	}
	use := analysis.CandidateUse{EntryID: f.entry.ID, InvocationContextID: f.invocation.ID, Kind: "sql_query_candidate",
		Sink: f.module.evidence("sql_query_candidate", n), Dependencies: combined.deps, Context: append([]analysis.Evidence{}, f.context...), Gaps: gaps,
		APIModel:   analysispacks.SQLContract(analysispacks.SQLTextContract),
		Assessment: analysis.Assessment{Status: "not_run"}}
	info := &sqlTextInfo{arg: textArg, judged: judged, coverage: callbackGaps}
	if textNode != nil {
		file := f.module.file
		if len(prepDefs) > 0 {
			file = prepDefs[0].File
		}
		info.textSpan = parse.Span(file, textNode)
		if len(prepDefs) > 0 {
			info.textSpan = prepDefs[len(prepDefs)-1]
		}
		if e, ok := parse.SQLTextPlacementEvidence(read.pieces, info.textSpan); ok {
			info.placement = &e
		}
	}
	info.defs = append(info.defs, read.defs...)
	if len(prepDefs) > 0 {
		info.defs = append(info.defs, prepDefs[:len(prepDefs)-1]...)
	}
	if tagCall != nil {
		if tag := tagCall.ChildByFieldName("function"); tag != nil {
			sp := parse.Span(f.module.file, tag)
			info.tag = &sp
		}
		if target, def := f.set.resolveCall(f.module, tagCall); target != nil && def != nil && isCallable(def) {
			sp := parse.Span(target.file, definitionStatement(def))
			info.tagDef = &sp
		}
	}
	return use, info, true
}

// sqlTextPreparing finds, for a method call whose receiver is a name, the call
// that prepared the statement the receiver holds: the receiver was assigned, in
// the same function scope (or at module level, when the text is fully literal),
// from a call with an argument that is SQL statement text. It returns the text
// node, its reading, and spans: the definitions to attach, then the text node's
// span last. Nothing when the preparing call has a record in the entry (it
// carries data) or would be recorded by a contract.
func (f *flow) sqlTextPreparing(n, fn *sitter.Node) (*sitter.Node, sqlTextRead, []analysis.Span, bool) {
	var none sqlTextRead
	if fn.Kind() != "member_expression" {
		return nil, none, nil, false
	}
	recv := fn.ChildByFieldName("object")
	if recv == nil || recv.Kind() != "identifier" {
		return nil, none, nil, false
	}
	name := recv.Utf8Text(f.module.src)
	c := newSQLTextCollector(f.set, f.module, n.StartByte())
	for i, sc := range c.scopes(recv, name) {
		var value, decl *sitter.Node
		walkScope(sc, func(x *sitter.Node) {
			switch x.Kind() {
			case "variable_declarator":
				if nm := x.ChildByFieldName("name"); nm != nil && nm.Kind() == "identifier" && nm.Utf8Text(f.module.src) == name {
					value, decl = x.ChildByFieldName("value"), x
				}
			case "assignment_expression":
				if l := x.ChildByFieldName("left"); l != nil && l.Kind() == "identifier" && l.Utf8Text(f.module.src) == name {
					value, decl = x.ChildByFieldName("right"), x
				}
			}
		})
		if decl == nil {
			if sc.param {
				return nil, none, nil, false
			}
			continue
		}
		// Only a scope that is the function of the call, or the module.
		if sc.node.Kind() != "program" && i > 0 {
			return nil, none, nil, false
		}
		prep := value
		for prep != nil && (prep.Kind() == "await_expression" || prep.Kind() == "parenthesized_expression" || prep.Kind() == "as_expression" || prep.Kind() == "non_null_expression") && prep.NamedChildCount() > 0 {
			prep = prep.NamedChild(0)
		}
		if prep == nil || prep.Kind() != "call_expression" {
			return nil, none, nil, false
		}
		pfn, pargs := prep.ChildByFieldName("function"), prep.ChildByFieldName("arguments")
		if pfn == nil || pargs == nil || pargs.Kind() != "arguments" {
			return nil, none, nil, false
		}
		span := parse.Span(f.module.file, prep)
		for _, u := range f.uses {
			if (u.Kind == "sql_query_candidate" || u.Kind == "nosql_query_candidate") && u.Sink.Span == span {
				return nil, none, nil, false
			}
		}
		if _, _, _, ok := f.set.sqlLibraryCall(f.module, prep); ok {
			return nil, none, nil, false
		}
		if _, ok := sqlJSCall(f.module, pfn); ok {
			return nil, none, nil, false
		}
		if queryKind(pfn.Utf8Text(f.module.src), pargs, f.module.src, nil) != "" {
			return nil, none, nil, false
		}
		for j := uint(0); j < pargs.NamedChildCount(); j++ {
			a := pargs.NamedChild(j)
			if a.Kind() == "spread_element" {
				break
			}
			r := f.sqlTextReadNode(a, prep.StartByte())
			if !r.hit {
				continue
			}
			if sc.node.Kind() == "program" && i > 0 && parse.SQLStatementText(r.pieces).Holes != 0 {
				return nil, none, nil, false
			}
			defs := []analysis.Span{parse.Span(f.module.file, definitionStatement(prep))}
			defs = append(defs, parse.Span(f.module.file, a))
			return a, r, defs, true
		}
		return nil, none, nil, false
	}
	return nil, none, nil, false
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
	use, info, ok := f.sqlTextBuild(n, fn, args, values, true)
	if !ok {
		return
	}
	if info.arg < 0 && args.Kind() != "template_string" {
		// A statement prepared apart: one record per statement object, at the first
		// call that carries data. Later calls on it add their dependencies.
		id = "use:" + f.invocation.ID + ":" + info.textSpan.File + ":" + strconv.Itoa(info.textSpan.StartByte) + ":sql-text-prepared"
		for i := range f.uses {
			if f.uses[i].ID == id {
				for _, d := range use.Dependencies {
					f.uses[i].Dependencies = append(f.uses[i].Dependencies, d)
				}
				for _, g := range use.Gaps {
					dup := false
					for _, o := range f.uses[i].Gaps {
						dup = dup || (o.Kind == g.Kind && o.Detail == g.Detail)
					}
					if !dup {
						f.uses[i].Gaps = append(f.uses[i].Gaps, g)
					}
				}
				return
			}
		}
	}
	use.ID = id
	f.uses = append(f.uses, use)
	f.set.sqlTextStore(id, info)
}

// sqlTextTwin keeps, for a call the flow recorded as a contract-less SQL
// candidate (a method named query), the record the text hook would make. The
// check assembly adopts it when no contract binds the call (D-1).
func (f *flow) sqlTextTwin(n, fn, args *sitter.Node, values []value, oldID string) {
	use, info, ok := f.sqlTextBuild(n, fn, args, values, false)
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
	if info.textSpan.File != "" {
		if m := s.modules[info.textSpan.File]; m != nil {
			if node := parse.NodeAt(m.tree.RootNode(), info.textSpan.StartByte, info.textSpan.EndByte); node != nil {
				c.Evidence["query_text"] = []analysis.Evidence{m.evidence("query_text", node)}
			}
		}
	}
	if info.placement != nil {
		c.Evidence[parse.SQLTextPlacementKind] = []analysis.Evidence{*info.placement}
	}
	if info.tag != nil {
		if m := s.modules[info.tag.File]; m != nil {
			if node := parse.NodeAt(m.tree.RootNode(), info.tag.StartByte, info.tag.EndByte); node != nil {
				c.Evidence["template_tag"] = []analysis.Evidence{m.evidence("template_tag", node)}
			}
		}
		if info.tagDef != nil {
			c.Evidence["template_tag_definition"] = []analysis.Evidence{{Kind: "template_tag_definition", Span: *info.tagDef}}
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
	s.sqlTextDefinitions(use, info)
}

// sqlTextDefinitions attaches the definitions the text was read through when no
// context evidence holds them: a referenced_definition for one in the sink's
// file, a source excerpt of the file for another file.
func (s *moduleSet) sqlTextDefinitions(use *analysis.CandidateUse, info *sqlTextInfo) {
	for _, sp := range info.defs {
		if sp.File == "" || sqlTextCovered(use.Context, sp) {
			continue
		}
		m := s.modules[sp.File]
		if m == nil {
			continue
		}
		if sp.File == use.Sink.Span.File {
			if node := parse.NodeAt(m.tree.RootNode(), sp.StartByte, sp.EndByte); node != nil {
				use.Context = append(use.Context, m.evidence("referenced_definition", node))
			}
			continue
		}
		if ev, ok := parse.SQLTextExcerptEvidence(m.src, sp); ok {
			use.Context = append(use.Context, ev)
		}
	}
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
