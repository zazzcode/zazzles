package parse

import (
	"fmt"
	"sort"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
)

// inputFacts records which request fields were read, passed to some other call,
// or consumed by a query sink. It is shared across helper and callback flows
// for one route so a helper call is not mistaken for a validator.
type inputFacts struct {
	inputs     map[string]analysis.Evidence
	touched    map[string]bool
	middleware map[string]bool
	weak       map[string]bool
	sunk       map[string]bool
	// credentialDest maps container+key to a request value written to a credential-named property.
	credentialDest map[string]credentialDestination
}

func newInputFacts() *inputFacts {
	return &inputFacts{inputs: map[string]analysis.Evidence{}, touched: map[string]bool{}, middleware: map[string]bool{}, weak: map[string]bool{}, sunk: map[string]bool{}, credentialDest: map[string]credentialDestination{}}
}

func (f *flow) rememberInput(source analysis.Evidence) {
	if f.facts == nil || source.Text == "" {
		return
	}
	if _, ok := f.facts.inputs[source.Text]; !ok {
		f.facts.inputs[source.Text] = source
	}
}

func (f *flow) noteInputTouch(values []value, name string) {
	if f.facts == nil {
		return
	}
	weakCall := name == "String" || name == "Number" || strings.HasSuffix(name, ".substring") || strings.HasSuffix(name, ".slice") || strings.Contains(name, "trunc")
	for _, v := range values {
		for _, d := range v.deps {
			if d.Source.Kind != "input_source" {
				continue
			}
			if weakCall {
				f.facts.weak[d.Source.Text] = true
			}
			f.facts.touched[d.Source.Text] = true
		}
	}
}

// noteWeakCondition records a type or length predicate on a request field or on
// a local that still carries that field. Those predicates do not decide the sink.
func (f *flow) noteWeakCondition(n *sitter.Node) {
	if f.facts == nil || n == nil || f.module == nil {
		return
	}
	text := n.Utf8Text(f.module.src)
	if !weakPredicate(text) {
		return
	}
	var walk func(*sitter.Node)
	walk = func(cur *sitter.Node) {
		if cur == nil {
			return
		}
		if cur.Kind() == "identifier" {
			if v, ok := f.env[cur.Utf8Text(f.module.src)]; ok {
				for _, field := range requestFields([]value{v}) {
					f.facts.weak[field] = true
				}
			}
		}
		if f.request != "" && isRequestField(cur, f.module.src, f.request) {
			node := cur
			if field := requestFieldNode(cur, f.module.src, f.request); field != nil {
				node = field
			}
			f.facts.weak[node.Utf8Text(f.module.src)] = true
		}
		for i := uint(0); i < cur.NamedChildCount(); i++ {
			walk(cur.NamedChild(i))
		}
	}
	walk(n)
}

func weakPredicate(text string) bool {
	if strings.Contains(text, ".length") {
		return true
	}
	if strings.Contains(text, "typeof") && (strings.Contains(text, "'string'") || strings.Contains(text, "\"string\"") || strings.Contains(text, "'number'") || strings.Contains(text, "\"number\"")) {
		return true
	}
	return false
}

func (f *flow) structureGaps(kind string, args *sitter.Node, values []value, call *sitter.Node) []analysis.Gap {
	gaps := []analysis.Gap{}
	text := ""
	if args != nil {
		text = args.Utf8Text(f.module.src)
	}
	textDeps := len(values) > 0 && len(values[0].deps) > 0
	structure := false
	switch kind {
	case "sql_query_candidate":
		if textDeps || strings.Contains(text, "Op.like") {
			structure = true
			gaps = append(gaps, f.gap("query_text_interpolated", "request-controlled value is built into executable query text", call))
		}
	case "nosql_query_candidate":
		if strings.Contains(text, "$where") {
			structure = true
			gaps = append(gaps, f.gap("query_text_interpolated", "a value is built into a NoSQL $where string", call))
		} else if requestDeps(values) {
			structure = true
			gaps = append(gaps, f.gap("query_document_unvalidated", "request-controlled value enters a query, update, or insert document without a modeled type constraint", call))
		}
	}
	for _, field := range requestFields(values) {
		if f.facts != nil {
			f.facts.sunk[field] = true
		}
		gaps = append(gaps, f.sinkValidationGap(field, structure, call))
	}
	return gaps
}

// requestFieldNode returns the req.body.name / req.query.name / req.params.name
// member inside a longer chain such as req.body.handle.length.
func requestFieldNode(n *sitter.Node, src []byte, req string) *sitter.Node {
	var found *sitter.Node
	var search func(*sitter.Node)
	search = func(cur *sitter.Node) {
		if cur == nil || found != nil {
			return
		}
		if cur.Kind() != "member_expression" && cur.Kind() != "subscript_expression" {
			return
		}
		obj := cur.ChildByFieldName("object")
		prop := cur.ChildByFieldName("property")
		if obj != nil && prop != nil && (obj.Kind() == "member_expression" || obj.Kind() == "subscript_expression") {
			base := obj.ChildByFieldName("object")
			baseProp := obj.ChildByFieldName("property")
			if base != nil && baseProp != nil && base.Kind() == "identifier" && base.Utf8Text(src) == req {
				switch baseProp.Utf8Text(src) {
				case "body", "payload", "query", "params", "headers", "cookies":
					found = cur
					return
				}
			}
		}
		search(obj)
	}
	search(n)
	return found
}

func (f *flow) sinkValidationGap(field string, structureRisk bool, at *sitter.Node) analysis.Gap {
	// Free text, such as a comment, may legitimately contain any character. Tightening
	// the alphabet would reject valid input. Injection control has to be the sink.
	if freeTextField(field) && structureRisk {
		return f.gap("sink_must_bind_free_text", field+" may contain any character the business allows; bind it in the query, update, or insert instead of building that statement from the string", at)
	}
	if freeTextField(field) {
		return f.gap("validation_free_text_bound", field+" is free text and is not built into query structure; an allow-list is not required for this sink", at)
	}
	if f.facts != nil && f.facts.weak[field] && structureRisk {
		return f.gap("validation_insufficient_for_sink", "the check on "+field+" only constrains type or length. Use the tightest restriction the business allows, and still bind the value at the sink", at)
	}
	if f.facts != nil && f.facts.weak[field] {
		return f.gap("validation_type_only", "the check on "+field+" only constrains type or length. Tighten it further when the business field can be restricted", at)
	}
	return f.validationGap(field, at)
}

func freeTextField(field string) bool {
	parts := strings.Split(field, ".")
	if len(parts) < 3 {
		return false
	}
	switch strings.ToLower(parts[len(parts)-1]) {
	case "comment", "comments", "message", "description", "text", "note", "notes", "content", "review", "feedback", "bio":
		return true
	default:
		return false
	}
}

func (f *flow) validationGap(field string, at *sitter.Node) analysis.Gap {
	if f.facts != nil && f.facts.middleware[field] {
		return f.gap("input_validation_middleware", "applicable middleware reads "+field+"; whether that check keeps the value out of query structure is unresolved", at)
	}
	if f.facts != nil && f.facts.touched[field] {
		return f.gap("input_validation_unresolved", "a call receives "+field+" before the sink, and that call is not a proven validator", at)
	}
	return f.gap("input_validation_absent", field+" reaches a sensitive use with no validator call in the handler or applicable middleware", at)
}

func requestDeps(values []value) bool {
	for _, v := range values {
		if len(requestFields([]value{v})) > 0 {
			return true
		}
	}
	return false
}

func requestFields(values []value) []string {
	seen := map[string]bool{}
	for _, v := range values {
		for _, d := range v.deps {
			if d.Source.Kind == "input_source" && d.Source.Text != "" {
				seen[d.Source.Text] = true
			}
		}
	}
	out := make([]string, 0, len(seen))
	for field := range seen {
		out = append(out, field)
	}
	sort.Strings(out)
	return out
}

func queryKind(name string, args *sitter.Node, src []byte, values []value) string {
	if strings.HasSuffix(name, ".query") {
		return "sql_query_candidate"
	}
	text := ""
	if args != nil {
		text = args.Utf8Text(src)
	}
	if strings.Contains(text, "Op.like") && (strings.Contains(text, "${") || strings.Contains(text, "+")) {
		return "sql_query_candidate"
	}
	if !collectionWrite(name) {
		return ""
	}
	if !strings.Contains(name, "Collection") && !strings.Contains(text, "$where") && !strings.Contains(text, "$set") {
		return ""
	}
	if requestDeps(values) || strings.Contains(text, "$where") {
		return "nosql_query_candidate"
	}
	return ""
}

func collectionWrite(name string) bool {
	for _, suffix := range []string{".find", ".findOne", ".findById", ".update", ".updateOne", ".updateMany", ".insert", ".insertOne", ".insertMany", ".deleteOne", ".deleteMany", ".remove", ".replaceOne"} {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	return false
}

// enterQueryCallback analyzes a nested function only when its text builds a
// query. Other callbacks stay unknown so ordinary array iterators are not sinks.
func (f *flow) enterQueryCallback(n *sitter.Node) {
	if f.depth >= 2 || n == nil {
		return
	}
	text := n.Utf8Text(f.module.src)
	if !strings.Contains(text, "$where") && !strings.Contains(text, "Op.like") && !strings.Contains(text, ".query(") {
		return
	}
	body := n.ChildByFieldName("body")
	if body == nil {
		return
	}
	child := flow{
		module: f.module,
		set:    f.set,
		entry:  f.entry, invocation: f.invocation,
		request: f.request,
		parts:   f.parts,
		env:     copyValues(f.env),
		context: append([]analysis.Evidence{}, f.context...),
		gaps:    append([]analysis.Gap{}, f.gaps...),
		depth:   f.depth + 1,
		helpers: f.helpers,
		facts:   f.facts,
	}
	child.statements(body)
	f.uses = append(f.uses, child.uses...)
}

// finishValidation reports request fields that never reached a query sink.
// Fields consumed by a sink already carry their validation gap on that use.
func (f *flow) finishValidation() {
	if f.facts == nil {
		return
	}
	fields := make([]string, 0, len(f.facts.inputs))
	for field := range f.facts.inputs {
		fields = append(fields, field)
	}
	sort.Strings(fields)
	for _, field := range fields {
		if f.facts.sunk[field] {
			continue
		}
		source := f.facts.inputs[field]
		gap := f.validationGap(field, nil)
		gap.At = source.Span
		if gap.Kind == "input_validation_absent" {
			gap.Detail = field + " is read and no handler or applicable middleware validator handles it"
		}
		f.uses = append(f.uses, analysis.CandidateUse{
			ID:      fmt.Sprintf("input:%s:%s:%d", f.invocation.ID, field, source.Span.StartByte),
			EntryID: f.entry.ID, InvocationContextID: f.invocation.ID,
			Kind:         "input_validation_candidate",
			Sink:         source,
			Dependencies: []analysis.Dependency{{Source: source, Transfers: []analysis.Evidence{}}},
			Context:      append([]analysis.Evidence{}, f.context...),
			Gaps:         append(append([]analysis.Gap{}, f.gaps...), gap),
			Assessment:   analysis.Assessment{Status: "not_run"},
		})
	}
}
