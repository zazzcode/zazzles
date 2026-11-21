package langjs

import (
	"slices"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/parse"
)

// pollutionLookupGates lists the branch tests on the current path whose
// outcome depends on a call that takes the key operand: `if (!allowed.has(key))
// return`, or `const row = find(key); if (row == null) return`. Such a call can
// reject a prototype key or let it through. Read verified Map membership and
// retain other unresolved tests as guard evidence.
//
// A test on the operand itself and a plain `store[key]` existence test are not
// gates: an inherited key passes both.
func (f *flow) pollutionLookupGates(sink, directKey *sitter.Node, deps []analysis.Dependency, guard pollutionGuard) pollutionGuard {
	var gates pollutionGuard
	add := func(m *sourceModule, cond, key *sitter.Node, branch, holds bool) {
		e := m.evidence("key_guard", cond)
		seen := func(prior analysis.Evidence) bool { return prior.Span == e.Span }
		read := slices.ContainsFunc(guard.evidence, seen)
		if read && guard.kind != "unknown" || slices.ContainsFunc(gates.evidence, seen) {
			return
		}
		names := pollutionOperandNames(m, deps)
		if len(names) == 0 || !pollutionGateTest(m, cond, names) {
			return
		}
		if branch {
			if found, ok := f.set.pollutionMapGuard(m, cond, names, holds, key); ok {
				gates.kind = found.kind
				gates.unknown = gates.unknown || found.unknown
				gates.blocked = append(gates.blocked, found.blocked...)
				for _, proof := range found.evidence {
					if !read || proof.Span != e.Span {
						gates.evidence = append(gates.evidence, proof)
					}
				}
				return
			}
		}
		if read {
			return
		}
		if gates.kind == "" {
			gates.kind = "unknown"
		}
		gates.unknown = true
		gates.evidence = append(gates.evidence, e)
	}
	for _, e := range f.context {
		m := f.set.modules[e.Span.File]
		if m == nil {
			continue
		}
		n := parse.NodeAt(m.tree.RootNode(), e.Span.StartByte, e.Span.EndByte)
		if n == nil {
			continue
		}
		switch {
		case e.Kind == branchTruePrecondition || e.Kind == branchFalsePrecondition:
			add(m, n, directKey, true, e.Kind == branchTruePrecondition)
		case e.Kind == "control_statement" && n.Kind() == "try_statement":
			// A try block is not split into arms. Read the tests in it that leave
			// the function, which the rest of the path has passed.
			pollutionWalk(n.ChildByFieldName("body"), func(branch *sitter.Node) {
				if branch.Kind() == "if_statement" && branch.ChildByFieldName("condition") != nil && pollutionLeaves(branch.ChildByFieldName("consequence")) {
					add(m, branch.ChildByFieldName("condition"), nil, true, false)
				}
			})
		case e.Kind == "helper_call":
			// The call that leads to the write may itself be the guarded operand
			// of `test && call()` or `test ? call() : other`.
			for _, cond := range pollutionExpressionGates(n) {
				add(m, cond, nil, false, false)
			}
		}
	}
	for _, cond := range pollutionExpressionGates(sink) {
		add(f.module, cond, nil, false, false)
	}
	return gates
}

// pollutionExpressionGates lists the tests that select an expression inside its
// statement: the left side of `&&` or `||` when the expression is on the right,
// and the condition of a conditional expression that holds it in an arm.
func pollutionExpressionGates(n *sitter.Node) []*sitter.Node {
	var conds []*sitter.Node
	for child, parent := n, n.Parent(); parent != nil; child, parent = parent, parent.Parent() {
		switch parent.Kind() {
		case "binary_expression":
			op, left := parent.ChildByFieldName("operator"), parent.ChildByFieldName("left")
			if op != nil && left != nil && (op.Kind() == "&&" || op.Kind() == "||") && !sameNode(left, child) {
				conds = append(conds, left)
			}
		case "ternary_expression":
			if cond := parent.ChildByFieldName("condition"); cond != nil && !sameNode(cond, child) {
				conds = append(conds, cond)
			}
		case "parenthesized_expression", "await_expression", "assignment_expression", "arguments", "call_expression",
			"as_expression", "non_null_expression", "satisfies_expression":
		default:
			return conds
		}
	}
	return conds
}

// pollutionLeaves reports a branch that ends by returning or throwing.
func pollutionLeaves(n *sitter.Node) bool {
	if n != nil && n.Kind() == "statement_block" {
		var last *sitter.Node
		for i := uint(0); i < n.NamedChildCount(); i++ {
			if c := n.NamedChild(i); c.Kind() != "comment" {
				last = c
			}
		}
		n = last
	}
	return n != nil && (n.Kind() == "return_statement" || n.Kind() == "throw_statement")
}

// pollutionOperandNames lists how one module spells the operand: the request
// expression and the locals and parameters it was bound to on the way.
func pollutionOperandNames(m *sourceModule, deps []analysis.Dependency) []string {
	var names []string
	add := func(n *sitter.Node) {
		if n = unwrapTS(n); n != nil && n.Kind() == "identifier" && !slices.Contains(names, n.Utf8Text(m.src)) {
			names = append(names, n.Utf8Text(m.src))
		}
	}
	for _, d := range deps {
		if d.Source.Span.File == m.file && !slices.Contains(names, compactText(d.Source.Text)) {
			names = append(names, compactText(d.Source.Text))
		}
		for _, t := range d.Transfers {
			if t.Span.File != m.file || t.Kind != "assignment" && t.Kind != "parameter_binding" {
				continue
			}
			n := parse.NodeAt(m.tree.RootNode(), t.Span.StartByte, t.Span.EndByte)
			if n == nil {
				continue
			}
			switch n.Kind() {
			case "variable_declarator":
				add(n.ChildByFieldName("name"))
			case "assignment_expression":
				add(n.ChildByFieldName("left"))
			case "required_parameter", "optional_parameter":
				add(n.ChildByFieldName("pattern"))
			case "assignment_pattern":
				add(n.ChildByFieldName("left"))
			default:
				add(n)
			}
		}
	}
	return names
}

func compactText(text string) string {
	out := make([]byte, 0, len(text))
	for i := 0; i < len(text); i++ {
		if c := text[i]; c != ' ' && c != '\t' && c != '\n' && c != '\r' {
			out = append(out, c)
		}
	}
	return string(out)
}

// pollutionGateTest reports a condition that contains a call taking the
// operand, or reads a local that was set from such a call.
func pollutionGateTest(m *sourceModule, cond *sitter.Node, names []string) bool {
	if pollutionOperandCall(m, cond, names) {
		return true
	}
	found := false
	pollutionWalk(cond, func(n *sitter.Node) {
		if found || n.Kind() != "identifier" || slices.Contains(names, n.Utf8Text(m.src)) {
			return
		}
		if p := n.Parent(); p != nil && p.Kind() == "member_expression" && sameNode(p.ChildByFieldName("property"), n) {
			return
		}
		name := n.Utf8Text(m.src)
		if pollutionOperandCall(m, localInitializer(m, cond, name), names) {
			found = true
			return
		}
		// `let row; try { row = await find(key) } …` sets the local by assignment.
		fn := cond
		for fn != nil && !isFunction(fn) && fn.Kind() != "function_declaration" && fn.Kind() != "method_definition" {
			fn = fn.Parent()
		}
		if fn == nil {
			return
		}
		pollutionWalk(fn.ChildByFieldName("body"), func(a *sitter.Node) {
			if a.Kind() == "assignment_expression" && a.EndByte() <= cond.StartByte() && pollutionIdentifier(a.ChildByFieldName("left"), m.src) == name &&
				pollutionOperandCall(m, a.ChildByFieldName("right"), names) {
				found = true
			}
		})
	})
	return found
}

// pollutionOperandCall reports a call in the expression that takes the operand
// as an argument. JSON.parse and native string conversions carry the operand
// on and are not tests of it.
func pollutionOperandCall(m *sourceModule, n *sitter.Node, names []string) bool {
	found := false
	pollutionWalk(n, func(call *sitter.Node) {
		if found || call.Kind() != "call_expression" || pollutionJSONParse(m, call) || nativeStringOperation(m, call) {
			return
		}
		args := call.ChildByFieldName("arguments")
		for i := uint(0); args != nil && i < args.NamedChildCount(); i++ {
			if slices.Contains(names, compactPollutionText(pollutionUnwrap(args.NamedChild(i)), m.src)) {
				found = true
			}
		}
	})
	return found
}
