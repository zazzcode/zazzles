package parse

import (
	sitter "github.com/tree-sitter/go-tree-sitter"
	"net/url"
	"strings"
)

func practiceMessageUnenforced(m *sourceModule, cb, body *sitter.Node, name string) bool {
	unguarded := false
	l := m.guardLang()
	walkNodes(body, func(n *sitter.Node) {
		if n.Kind() != "member_expression" || n.Utf8Text(m.src) != name+".data" {
			return
		}
		protected := false
		// Replacing the event or its members loses the original sender relation.
		if l.assignedBetween(body, body.StartByte(), n.StartByte(), []string{name}) {
			unguarded = true
			return
		}
		enclosing := l.climb(n, func(g guardSite) {
			if practicePredicate(m, g.Cond, g.Polarity == guardEnforcesWhenTrue, func(left, right *sitter.Node) bool {
				if left.Utf8Text(m.src) != name+".origin" {
					return false
				}
				origin, ok := stringLiteral(practiceLiteral(m, right, 0), m.src)
				if !ok {
					return false
				}
				u, err := url.Parse(origin)
				return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" && u.User == nil && u.Path == "" && u.RawQuery == "" && u.Fragment == "" && !strings.Contains(u.Host, "*")
			}) && !l.assignedBetween(body, g.End, n.StartByte(), []string{name}) {
				protected = true
			}
		})
		if enclosing == nil || enclosing.StartByte() != cb.StartByte() {
			protected = false
		}
		unguarded = unguarded || !protected
	})
	return unguarded
}

// practicePredicate recognizes exact equality enforced by the existing lexical
// guard engine. Conjunction/disjunction are accepted only in the sound polarity.
func practicePredicate(m *sourceModule, n *sitter.Node, truth bool, match func(*sitter.Node, *sitter.Node) bool) bool {
	n = practiceUnwrap(n)
	if n == nil || n.Kind() != "binary_expression" {
		return false
	}
	left, right := n.ChildByFieldName("left"), n.ChildByFieldName("right")
	if left == nil || right == nil {
		return false
	}
	op := strings.TrimSpace(string(m.src[left.EndByte():right.StartByte()]))
	if op == "&&" && truth || op == "||" && !truth {
		return practicePredicate(m, left, truth, match) || practicePredicate(m, right, truth, match)
	}
	return (op == "===" && truth || op == "!==" && !truth) && (match(left, right) || match(right, left))
}

func practiceServerRoleEnforced(m *sourceModule, handler *sitter.Node) bool {
	if handler.Kind() == "export_statement" {
		handler = handler.ChildByFieldName("declaration")
	}
	if handler == nil {
		return false
	}
	body := handler.ChildByFieldName("body")
	if body == nil {
		return false
	}
	relevant, covered := 0, true
	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		if n != body && (isFunction(n) || n.Kind() == "function_declaration") {
			return
		}
		// Every call except obtaining the identity and constructing a rejecting
		// response must be dominated by the role check; a later guard cannot repair
		// an operation that already happened.
		if n.Kind() == "call_expression" || n.Kind() == "return_statement" {
			fn := n.ChildByFieldName("function")
			identity := false
			if fn != nil {
				imp, ok := m.imports[fn.Utf8Text(m.src)]
				identity = ok && (imp.name == "auth" || imp.name == "getServerSession") && !shadowed(n, fn.Utf8Text(m.src), m.src)
			}
			if !identity && !practiceRejectResponse(m, n, body) {
				relevant++
				allowed := false
				m.guardLang().climb(n, func(g guardSite) {
					if practicePredicate(m, g.Cond, g.Polarity == guardEnforcesWhenTrue, func(left, right *sitter.Node) bool {
						role, ok := stringLiteral(right, m.src)
						if !ok || role != "admin" || !strings.HasSuffix(left.Utf8Text(m.src), ".role") {
							return false
						}
						return practiceRoleIdentity(m, left)
					}) {
						allowed = true
					}
				})
				covered = covered && allowed
			}
		}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			visit(n.NamedChild(i))
		}
	}
	visit(body)
	return relevant > 0 && covered
}

func practiceRejectResponse(m *sourceModule, n, body *sitter.Node) bool {
	// Only return/throw branches rejecting a non-admin identity are exempt from
	// the operation coverage check. Merely returning an arbitrary response is not.
	returned := n
	if n.Kind() == "call_expression" {
		returned = n.Parent()
	}
	if returned == nil || returned.Kind() != "return_statement" {
		return false
	}
	responseOnly := true
	walkCalls(returned, func(call *sitter.Node) {
		fn := call.ChildByFieldName("function")
		if fn == nil || fn.Utf8Text(m.src) != "Response.json" && fn.Utf8Text(m.src) != "NextResponse.json" {
			responseOnly = false
		} else if fn.Utf8Text(m.src) == "Response.json" {
			responseOnly = responseOnly && !topLevelBinding(m, "Response") && !shadowed(call, "Response", m.src)
		} else {
			imp, ok := m.imports["NextResponse"]
			responseOnly = responseOnly && ok && imp.module == "next/server" && imp.name == "NextResponse" && !shadowed(call, "NextResponse", m.src)
		}
	})
	if !responseOnly {
		return false
	}
	// The rejection must actually deny access, not return the same data with a
	// successful status from the non-admin branch.
	if returned.NamedChildCount() != 1 {
		return false
	}
	response := returned.NamedChild(0)
	args := response.ChildByFieldName("arguments")
	if args == nil || args.NamedChildCount() < 2 {
		return false
	}
	status := property(args.NamedChild(1), "status", m.src)
	if status == nil || status.Utf8Text(m.src) != "401" && status.Utf8Text(m.src) != "403" {
		return false
	}
	for p := n; p != nil && p.StartByte() >= body.StartByte(); p = p.Parent() {
		if p.Kind() != "if_statement" {
			continue
		}
		consequence := p.ChildByFieldName("consequence")
		if consequence == nil || n.StartByte() < consequence.StartByte() || n.EndByte() > consequence.EndByte() || !m.jsAlwaysExits(consequence) {
			continue
		}
		return practicePredicate(m, p.ChildByFieldName("condition"), false, func(left, right *sitter.Node) bool {
			role, ok := stringLiteral(right, m.src)
			return ok && role == "admin" && strings.HasSuffix(left.Utf8Text(m.src), ".role") && practiceRoleIdentity(m, left)
		})
	}
	return false
}

func practiceRoleIdentity(m *sourceModule, n *sitter.Node) bool {
	kind := practiceContextKind(m, n, 0)
	if kind != "next-auth:getServerSession" && kind != "next-auth/next:getServerSession" {
		return false
	}
	use := n
	for n = practiceUnwrap(n); n != nil && n.Kind() == "member_expression"; n = practiceUnwrap(n.ChildByFieldName("object")) {
	}
	return n != nil && (n.Kind() != "identifier" || practiceObjectUnescaped(m, n, use))
}
