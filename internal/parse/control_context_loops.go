package parse

import (
	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
)

// controlContextAnchored is controlContext with knowledge of where the claim's
// sink is reached from the handler body: anchors are the sink span and the
// handler-level call spans that lead to it (helper_call evidence). Only with
// anchors may a loop statement stop being a control-flow blocker, and only when
// it provably cannot change what the claim reads or decide whether the sink runs:
//   - a loop that starts after every anchor ends cannot affect the sink call;
//   - a loop before an anchor must neither leave the handler (return/throw/
//     labelled jump, which would make it a guard) nor assign any binding declared
//     outside the loop, and must not contain an anchor (the sink would repeat).
//
// Removing the blocker never records a guard: the loop adds no branch edges.
func controlContextAnchored(m *sourceModule, body *sitter.Node, anchors []analysis.Span) ([]analysis.ControlEdge, []analysis.Gap) {
	return controlContextWith(m, body, handlerAnchors(m, body, anchors))
}

// handlerAnchors keeps the spans that lie inside the handler body in its file.
func handlerAnchors(m *sourceModule, body *sitter.Node, anchors []analysis.Span) []analysis.Span {
	var out []analysis.Span
	if body == nil {
		return out
	}
	for _, a := range anchors {
		if a.File == m.file && a.StartByte >= int(body.StartByte()) && a.EndByte <= int(body.EndByte()) {
			out = append(out, a)
		}
	}
	return out
}

// transparentLoop reports whether an otherwise unsupported loop statement may be
// stepped over for the claim whose anchors are given.
func transparentLoop(m *sourceModule, n *sitter.Node, anchors []analysis.Span) bool {
	switch n.Kind() {
	case "for_statement", "for_in_statement", "while_statement", "do_statement":
	default:
		return false
	}
	if len(anchors) == 0 {
		return false
	}
	start, end := int(n.StartByte()), int(n.EndByte())
	maxEnd := 0
	for _, a := range anchors {
		if a.StartByte < end && a.EndByte > start {
			return false // the sink (or the call to it) may run once per iteration
		}
		if a.EndByte > maxEnd {
			maxEnd = a.EndByte
		}
	}
	if start >= maxEnd {
		return true
	}
	return loopIsInert(m, n)
}

// loopIsInert reports a loop that cannot leave the handler early and assigns only
// bindings it declares itself.
func loopIsInert(m *sourceModule, loop *sitter.Node) bool {
	declared := map[string]bool{}
	var declare func(*sitter.Node)
	declare = func(p *sitter.Node) {
		if p == nil {
			return
		}
		switch p.Kind() {
		case "identifier", "shorthand_property_identifier_pattern":
			declared[p.Utf8Text(m.src)] = true
			return
		case "pair_pattern":
			declare(p.ChildByFieldName("value"))
			return
		case "assignment_pattern":
			declare(p.ChildByFieldName("left"))
			return
		case "required_parameter", "optional_parameter":
			declare(p.ChildByFieldName("pattern"))
			return
		}
		for i := uint(0); i < p.NamedChildCount(); i++ {
			declare(p.NamedChild(i))
		}
	}
	inert := true
	var walk func(*sitter.Node, bool)
	walk = func(n *sitter.Node, inFunction bool) {
		if n == nil || !inert {
			return
		}
		switch n.Kind() {
		case "variable_declarator":
			declare(n.ChildByFieldName("name"))
		case "catch_clause":
			declare(n.ChildByFieldName("parameter"))
		case "function_declaration", "function_expression", "arrow_function", "method_definition", "generator_function", "generator_function_declaration":
			declare(n.ChildByFieldName("parameters"))
			declare(n.ChildByFieldName("parameter"))
			inFunction = true
		case "for_in_statement":
			if n.ChildByFieldName("kind") != nil {
				declare(n.ChildByFieldName("left"))
			} else if !declaredTarget(m, n.ChildByFieldName("left"), declared) {
				inert = false
			}
		case "return_statement", "throw_statement":
			if !inFunction {
				inert = false
			}
		case "break_statement", "continue_statement":
			if n.ChildByFieldName("label") != nil {
				inert = false
			}
		case "unary_expression":
			if op := n.ChildByFieldName("operator"); op != nil && op.Kind() == "delete" {
				inert = false
			}
		}
		if inert {
			for i := uint(0); i < n.NamedChildCount(); i++ {
				walk(n.NamedChild(i), inFunction)
			}
		}
	}
	// Declarations may follow their first use textually (var, hoisting); gather
	// them in a first pass so a later assignment check sees the full set.
	walk(loop, false)
	if !inert {
		return false
	}
	var assigns func(*sitter.Node)
	assigns = func(n *sitter.Node) {
		if n == nil || !inert {
			return
		}
		switch n.Kind() {
		case "assignment_expression", "augmented_assignment_expression":
			if !declaredTarget(m, n.ChildByFieldName("left"), declared) {
				inert = false
			}
		case "update_expression":
			if !declaredTarget(m, n.ChildByFieldName("argument"), declared) {
				inert = false
			}
		}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			assigns(n.NamedChild(i))
		}
	}
	assigns(loop)
	return inert
}

// declaredTarget reports whether an assignment target is rooted in a binding the
// loop declares. Destructuring and any other target shape is not.
func declaredTarget(m *sourceModule, t *sitter.Node, declared map[string]bool) bool {
	for t != nil {
		switch t.Kind() {
		case "identifier":
			return declared[t.Utf8Text(m.src)]
		case "member_expression", "subscript_expression":
			t = t.ChildByFieldName("object")
		case "parenthesized_expression", "non_null_expression":
			if t.NamedChildCount() == 0 {
				return false
			}
			t = t.NamedChild(0)
		default:
			return false
		}
	}
	return false
}

// claimAnchors lists the spans through which a claim's sink is reached: the sink
// itself and every helper call recorded on the path to it.
func claimAnchors(u *analysis.CandidateUse) []analysis.Span {
	out := []analysis.Span{u.Sink.Span}
	for _, e := range u.Context {
		if e.Kind == "helper_call" {
			out = append(out, e.Span)
		}
	}
	return out
}
