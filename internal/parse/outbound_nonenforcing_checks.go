package parse

import (
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
)

// A regex/match/startsWith check is NON-ENFORCING for an outbound call when the
// source positively shows that its result cannot stop or change the call: the
// check runs after the call, or its only effect is setting a flag/variable
// (an `if` whose branches hold only plain assignments, or a variable read only
// by such branches). Anything not positively classified stays enforcing, so an
// unknown flow never loses a control.

var urlCheckCallMethods = map[string]bool{
	"test": true, "match": true, "startsWith": true, "endsWith": true, "includes": true,
	"indexOf": true, "toLowerCase": true, "toUpperCase": true, "trim": true,
}

// nonEnforcingCheck reports a check call that cannot constrain the sink call.
func nonEnforcingCheck(m *sourceModule, body, sink, check *sitter.Node) bool {
	if m == nil || body == nil || sink == nil || check == nil {
		return false
	}
	if check.StartByte() >= sink.EndByte() {
		return true // evaluated after the outbound call
	}
	if check.StartByte() >= sink.StartByte() {
		return false
	}
	operands := sinkOperandPaths(m, sink)
	if ifStmt, cond := enclosingIfCondition(check); ifStmt != nil {
		return checkOnlyCalls(m, cond) && flagOnlyBranches(m, ifStmt, sink, operands)
	}
	name := assignedFlagName(m, check)
	if name == "" {
		return false
	}
	ok := true
	isDeclaration := func(n *sitter.Node) bool {
		p := n.Parent()
		if p == nil {
			return false
		}
		var target *sitter.Node
		switch p.Kind() {
		case "variable_declarator":
			target = p.ChildByFieldName("name")
		case "assignment_expression":
			target = p.ChildByFieldName("left")
		}
		return target != nil && target.StartByte() == n.StartByte() && target.EndByte() == n.EndByte()
	}
	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		if !ok {
			return
		}
		if n.Kind() == "identifier" && n.Utf8Text(m.src) == name {
			if !isDeclaration(n) {
				ifStmt, cond := enclosingIfCondition(n)
				if ifStmt == nil || !checkOnlyCalls(m, cond) || !flagOnlyBranches(m, ifStmt, sink, operands) {
					ok = false
				}
			}
			return
		}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			visit(n.NamedChild(i))
		}
	}
	visit(body)
	return ok
}

// enclosingIfCondition returns the `if` whose condition contains n.
func enclosingIfCondition(n *sitter.Node) (*sitter.Node, *sitter.Node) {
	child := n
	for p := n.Parent(); p != nil; p = p.Parent() {
		if isFunction(p) {
			return nil, nil
		}
		if p.Kind() == "if_statement" {
			if cond := p.ChildByFieldName("condition"); cond != nil && child.StartByte() == cond.StartByte() && child.EndByte() == cond.EndByte() {
				return p, cond
			}
			return nil, nil
		}
		switch p.Kind() {
		case "parenthesized_expression", "unary_expression", "binary_expression", "non_null_expression", "as_expression", "await_expression":
		default:
			return nil, nil
		}
		child = p
	}
	return nil, nil
}

// checkOnlyCalls reports a condition whose calls are all pure string/regex
// predicates, so evaluating it has no effect besides its truth value.
func checkOnlyCalls(m *sourceModule, cond *sitter.Node) bool {
	pure := true
	walkCalls(cond, func(c *sitter.Node) {
		fn := c.ChildByFieldName("function")
		if fn == nil || fn.Kind() != "member_expression" {
			pure = false
			return
		}
		if prop := fn.ChildByFieldName("property"); prop == nil || !urlCheckCallMethods[prop.Utf8Text(m.src)] {
			pure = false
		}
	})
	return pure
}

// assignedFlagName returns the identifier a check result is stored in
// (`const ok = re.test(u)`, `ok = u.match(re) !== null`).
func assignedFlagName(m *sourceModule, check *sitter.Node) string {
	child := check
	for p := check.Parent(); p != nil; p = p.Parent() {
		switch p.Kind() {
		case "parenthesized_expression", "unary_expression", "binary_expression", "non_null_expression", "as_expression", "await_expression":
			child = p
			continue
		case "variable_declarator":
			if v := p.ChildByFieldName("value"); v != nil && v.StartByte() == child.StartByte() && v.EndByte() == child.EndByte() {
				if id := p.ChildByFieldName("name"); id != nil && id.Kind() == "identifier" {
					return id.Utf8Text(m.src)
				}
			}
		case "assignment_expression":
			if r := p.ChildByFieldName("right"); r != nil && r.StartByte() == child.StartByte() && r.EndByte() == child.EndByte() {
				if l := p.ChildByFieldName("left"); l != nil && l.Kind() == "identifier" {
					return l.Utf8Text(m.src)
				}
			}
		}
		return ""
	}
	return ""
}

// sinkOperandPaths returns the identifiers and member chains the sink's
// arguments read.
func sinkOperandPaths(m *sourceModule, sink *sitter.Node) []string {
	var out []string
	args := sink.ChildByFieldName("arguments")
	if args == nil {
		return out
	}
	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		switch n.Kind() {
		case "identifier":
			out = append(out, n.Utf8Text(m.src))
			return
		case "member_expression":
			out = append(out, n.Utf8Text(m.src))
		}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			visit(n.NamedChild(i))
		}
	}
	visit(args)
	return out
}

// flagOnlyBranches reports an `if` whose branches only assign values that the
// outbound call's operands do not read, never contain the call, and cannot exit.
func flagOnlyBranches(m *sourceModule, ifStmt, sink *sitter.Node, operands []string) bool {
	if sink.StartByte() >= ifStmt.StartByte() && sink.EndByte() <= ifStmt.EndByte() {
		return false
	}
	ok := true
	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		if !ok {
			return
		}
		if isFunction(n) {
			ok = false
			return
		}
		switch n.Kind() {
		case "call_expression", "new_expression", "return_statement", "throw_statement", "break_statement", "continue_statement", "yield_expression", "await_expression", "tagged_template_expression", "delete_expression":
			ok = false
			return
		case "assignment_expression", "augmented_assignment_expression":
			if !unrelatedWrite(m, n.ChildByFieldName("left"), operands) {
				ok = false
				return
			}
		case "update_expression":
			if !unrelatedWrite(m, n.ChildByFieldName("argument"), operands) {
				ok = false
				return
			}
		}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			visit(n.NamedChild(i))
		}
	}
	if c := ifStmt.ChildByFieldName("consequence"); c != nil {
		visit(c)
	}
	if a := ifStmt.ChildByFieldName("alternative"); a != nil {
		visit(a)
	}
	return ok
}

// unrelatedWrite reports a write target that neither equals nor contains nor
// lies inside any path the outbound operand reads.
func unrelatedWrite(m *sourceModule, target *sitter.Node, operands []string) bool {
	if target == nil {
		return false
	}
	switch target.Kind() {
	case "identifier", "member_expression":
	default:
		return false
	}
	t := target.Utf8Text(m.src)
	for _, p := range operands {
		if t == p || strings.HasPrefix(p, t+".") || strings.HasPrefix(t, p+".") {
			return false
		}
	}
	return true
}

// ssrfNonEnforcingChecks returns the check calls of the SSRF handler that are
// positively non-enforcing for u's outbound call, keyed by start byte.
func (s *moduleSet) ssrfNonEnforcingChecks(u *analysis.CandidateUse, c *analysis.Completeness) map[uint]bool {
	out := map[uint]bool{}
	m := s.modules[u.Sink.Span.File]
	if m == nil {
		return out
	}
	sink := nodeAt(m.tree.RootNode(), u.Sink.Span.StartByte, u.Sink.Span.EndByte)
	if sink == nil {
		return out
	}
	for _, h := range c.Evidence["invoked_callable"] {
		if h.Span.File != m.file {
			continue
		}
		body := nodeAt(m.tree.RootNode(), h.Span.StartByte, h.Span.EndByte)
		if body == nil || sink.StartByte() < body.StartByte() || sink.EndByte() > body.EndByte() {
			continue
		}
		walkCalls(body, func(call *sitter.Node) {
			fn := call.ChildByFieldName("function")
			if fn == nil || fn.Kind() != "member_expression" {
				return
			}
			if prop := fn.ChildByFieldName("property"); prop == nil || !urlCheckCallMethods[prop.Utf8Text(m.src)] {
				return
			}
			if nonEnforcingCheck(m, body, sink, call) {
				out[call.StartByte()] = true
			}
		})
	}
	return out
}

// dropNonEnforcingTransfers removes the supported-transfer facts of regex
// captures that are non-enforcing checks for u: they carry nothing into the
// destination and must not be offered to the model as a possible constraint.
func (s *moduleSet) dropNonEnforcingTransfers(u *analysis.CandidateUse, c *analysis.Completeness) {
	skip := s.ssrfNonEnforcingChecks(u, c)
	if len(skip) == 0 {
		return
	}
	m := s.modules[u.Sink.Span.File]
	drop := map[string]bool{}
	for _, h := range c.Evidence["invoked_callable"] {
		if h.Span.File != m.file {
			continue
		}
		body := nodeAt(m.tree.RootNode(), h.Span.StartByte, h.Span.EndByte)
		if body == nil {
			continue
		}
		walkCalls(body, func(call *sitter.Node) {
			if skip[call.StartByte()] {
				drop["supported_transfer: "+m.evidence("regex_capture", call).Text+" at "+m.file] = true
			}
		})
	}
	facts := c.ModelFacts[:0:0]
	for _, f := range c.ModelFacts {
		if !drop[f] {
			facts = append(facts, f)
		}
	}
	c.ModelFacts = facts
}
