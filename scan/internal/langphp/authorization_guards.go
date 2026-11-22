package langphp

import (
	"strconv"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

// dominatingGuards lists the checks that dominate n. A check that does not
// exit is not a guard. The scanner does not decide that a guard is enough.
func (f *phpFlow) dominatingGuards(n *sitter.Node, subject *phpAuthz) []analysis.AuthorizationGuard {
	var out []analysis.AuthorizationGuard
	if subject != nil && subject.queryScope && subject.finder != nil {
		out = append(out, analysis.AuthorizationGuard{
			Kind: analysis.GuardOwnership, Form: "query_scope", Evidence: f.evidenceFor(subject.finder),
		})
	}
	if n == nil {
		return out
	}
	seen := map[string]bool{}
	add := func(cond *sitter.Node) {
		if cond == nil {
			return
		}
		g := f.classifyGuard(cond, subject, 0)
		key := g.Kind + ":" + g.Evidence.Span.File + ":" + strconv.Itoa(g.Evidence.Span.StartByte)
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, g)
	}
	for node := n; node != nil; node = node.Parent() {
		parent := node.Parent()
		if parent == nil || parent.Kind() == "method_declaration" || parent.Kind() == "function_definition" {
			break
		}
		switch parent.Kind() {
		case "if_statement":
			cond := phpField(parent, "condition")
			if phpNodeWithin(phpField(parent, "body"), node) {
				if alt := phpField(parent, "alternative"); alt != nil && f.authzExits(alt) {
					add(cond)
				}
			}
		case "else_clause", "else_if_clause":
			ifStmt := parent.Parent()
			if ifStmt != nil && f.authzExits(phpField(ifStmt, "body")) {
				add(phpField(ifStmt, "condition"))
			}
		case "compound_statement", "program":
			for i := uint(0); i < parent.NamedChildCount(); i++ {
				s := parent.NamedChild(i)
				if s == nil || s.StartByte() >= node.StartByte() {
					break
				}
				if s.Kind() == "if_statement" && phpField(s, "alternative") == nil && f.authzExits(phpField(s, "body")) {
					add(phpField(s, "condition"))
				}
				if s.Kind() == "expression_statement" {
					if call := f.priorGuardCall(s); call != nil {
						add(call)
					}
				}
			}
		}
	}
	return out
}

func (f *phpFlow) classifyGuard(n *sitter.Node, subject *phpAuthz, depth int) analysis.AuthorizationGuard {
	n = f.unwrapGuard(n)
	if n == nil {
		return f.unclassified(n)
	}
	if f.isPrivateCall(n) {
		if depth >= 1 {
			return f.unclassified(n)
		}
		inner := f.privateGuardBody(n)
		if inner == nil {
			return f.unclassified(n)
		}
		return f.classifyGuard(inner, subject, depth+1)
	}
	if g, ok := f.addressGuard(n); ok {
		return g
	}
	if f.isRoleGuard(n) {
		return analysis.AuthorizationGuard{Kind: analysis.GuardRole, Evidence: f.evidenceFor(n)}
	}
	if f.isOwnershipGuard(n) {
		return analysis.AuthorizationGuard{Kind: analysis.GuardOwnership, Evidence: f.evidenceFor(n)}
	}
	if f.isSecretGuard(n) {
		return analysis.AuthorizationGuard{Kind: analysis.GuardSecret, Evidence: f.evidenceFor(n)}
	}
	if f.isAuthenticatedGuard(n) {
		return analysis.AuthorizationGuard{Kind: analysis.GuardAuthenticated, Evidence: f.evidenceFor(n)}
	}
	return f.unclassified(n)
}

func (f *phpFlow) unclassified(n *sitter.Node) analysis.AuthorizationGuard {
	return analysis.AuthorizationGuard{
		Kind: analysis.GuardUnclassified, Evidence: f.evidenceFor(n),
		Gaps: []analysis.Gap{{Kind: "guard_unclassified", Detail: "dominating check has no modeled kind", At: f.evidenceFor(n).Span}},
	}
}

func (f *phpFlow) evidenceFor(n *sitter.Node) analysis.Evidence {
	if n == nil {
		return analysis.Evidence{}
	}
	m := f.module
	if f.entryModule != nil && f.class != nil && f.class.module != nil && f.class.module != f.module {
		if phpNodeWithin(f.class.node, n) {
			m = f.class.module
		}
	}
	return m.evidence("authorization_guard", n)
}

func (f *phpFlow) unwrapGuard(n *sitter.Node) *sitter.Node {
	for n != nil {
		switch n.Kind() {
		case "parenthesized_expression":
			n = n.NamedChild(0)
		case "unary_op_expression":
			if phpOperator(f.module, n) != "!" {
				return n
			}
			if n.NamedChildCount() == 0 {
				return n
			}
			n = n.NamedChild(0)
		default:
			return n
		}
	}
	return n
}

func (f *phpFlow) addressGuard(n *sitter.Node) (analysis.AuthorizationGuard, bool) {
	n = f.unwrapGuard(n)
	if n == nil {
		return analysis.AuthorizationGuard{}, false
	}
	var src string
	var lits []string
	var ok bool
	switch n.Kind() {
	case "function_call_expression":
		name := strings.TrimPrefix(f.callName(n), "\\")
		args := phpArgs(n)
		switch name {
		case "in_array":
			if len(args) >= 2 {
				src, ok = f.addressExpr(args[0])
				lits = f.stringLiterals(args[1])
			}
		case "str_starts_with":
			if len(args) >= 2 {
				src, ok = f.addressExpr(args[0])
				if lit, yes := phpStringLiteral(f.module, args[1]); yes {
					lits = []string{lit}
				}
			}
		case "preg_match":
			if len(args) >= 2 {
				src, ok = f.addressExpr(args[1])
				if lit, yes := phpStringLiteral(f.module, args[0]); yes {
					lits = []string{lit}
				}
			}
		}
	case "scoped_call_expression":
		if strings.EqualFold(phpText(f.module, phpField(n, "name")), "checkIp") {
			args := phpArgs(n)
			if len(args) >= 2 {
				src, ok = f.addressExpr(args[0])
				lits = f.stringLiterals(args[1])
				if len(lits) == 0 {
					if lit, yes := phpStringLiteral(f.module, args[1]); yes {
						lits = []string{lit}
					}
				}
			}
		}
	case "binary_expression":
		switch phpOperator(f.module, n) {
		case "===", "==", "!==", "!=":
			left, right := phpField(n, "left"), phpField(n, "right")
			if s, yes := f.addressExpr(left); yes {
				src, ok = s, true
				if lit, yes := phpStringLiteral(f.module, right); yes {
					lits = []string{lit}
				}
			} else if s, yes := f.addressExpr(right); yes {
				src, ok = s, true
				if lit, yes := phpStringLiteral(f.module, left); yes {
					lits = []string{lit}
				}
			}
		}
	}
	if !ok || src == "" || len(lits) == 0 {
		return analysis.AuthorizationGuard{}, false
	}
	g := analysis.AuthorizationGuard{
		Kind: analysis.GuardAddress, AddressSource: src, Literals: lits, Evidence: f.evidenceFor(n),
	}
	for _, lit := range lits {
		g.LiteralClass = append(g.LiteralClass, addressLiteralClass(lit))
	}
	if src == analysis.AddressFrameworkIP {
		g.AddressTrust = &analysis.AddressTrust{Status: "unread"}
		g.Gaps = []analysis.Gap{{
			Kind: "address_trust_configuration_unread", Detail: "framework client IP trust is not read", At: g.Evidence.Span,
		}}
	}
	return g, true
}

func (f *phpFlow) addressExpr(n *sitter.Node) (string, bool) {
	n = f.unwrapGuard(n)
	if n == nil {
		return "", false
	}
	switch n.Kind() {
	case "member_call_expression":
		name := strings.ToLower(phpText(f.module, phpField(n, "name")))
		switch name {
		case "getclientip", "getclientips":
			return analysis.AddressFrameworkIP, true
		case "get":
			key := ""
			if args := phpArgs(n); len(args) > 0 {
				key, _ = phpStringLiteral(f.module, args[0])
			}
			obj := phpField(n, "object")
			field := ""
			if obj != nil && (obj.Kind() == "member_access_expression" || obj.Kind() == "nullsafe_member_access_expression") {
				field = strings.ToLower(phpText(f.module, phpField(obj, "name")))
			}
			return addressKey(field, key)
		}
	case "subscript_expression":
		base := phpField(n, "variable")
		if base == nil && n.NamedChildCount() > 0 {
			base = n.NamedChild(0)
		}
		if phpVarName(f.module, base) != "_SERVER" {
			return "", false
		}
		key := ""
		if i := phpField(n, "index"); i != nil {
			key, _ = phpStringLiteral(f.module, i)
		} else if n.NamedChildCount() > 1 {
			key, _ = phpStringLiteral(f.module, n.NamedChild(1))
		}
		return addressKey("server", key)
	}
	return "", false
}

func addressKey(field, key string) (string, bool) {
	k := strings.ToUpper(strings.ReplaceAll(key, "-", "_"))
	switch field {
	case "server", "":
		switch k {
		case "REMOTE_ADDR":
			return analysis.AddressPeer, true
		case "HTTP_X_FORWARDED_FOR", "HTTP_CLIENT_IP", "HTTP_X_REAL_IP", "HTTP_FORWARDED":
			return analysis.AddressForwardedHeader, true
		}
	case "headers":
		switch k {
		case "X_FORWARDED_FOR", "CLIENT_IP", "X_REAL_IP", "FORWARDED", "HTTP_X_FORWARDED_FOR", "HTTP_CLIENT_IP", "HTTP_X_REAL_IP", "HTTP_FORWARDED":
			return analysis.AddressForwardedHeader, true
		}
	}
	return "", false
}

func addressLiteralClass(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "127.0.0.1", "::1", "0:0:0:0:0:0:0:1":
		return "loopback"
	}
	if strings.HasPrefix(s, "127.") {
		return "loopback"
	}
	if strings.HasPrefix(s, "10.") || strings.HasPrefix(s, "192.168.") {
		return "private"
	}
	low := strings.ToLower(s)
	if strings.HasPrefix(low, "fc") || strings.HasPrefix(low, "fd") {
		return "private"
	}
	if strings.HasPrefix(s, "172.") {
		parts := strings.Split(s, ".")
		if len(parts) >= 2 {
			n, err := strconv.Atoi(parts[1])
			if err == nil && n >= 16 && n <= 31 {
				return "private"
			}
		}
	}
	return "public"
}

func (f *phpFlow) stringLiterals(n *sitter.Node) []string {
	var out []string
	phpWalk(n, func(c *sitter.Node) {
		if lit, ok := phpStringLiteral(f.module, c); ok {
			out = append(out, lit)
		}
	})
	return out
}

func (f *phpFlow) isRoleGuard(n *sitter.Node) bool {
	if n == nil || n.Kind() != "member_call_expression" {
		return false
	}
	if !strings.EqualFold(phpText(f.module, phpField(n, "name")), "isGranted") {
		return false
	}
	args := phpArgs(n)
	if len(args) == 0 {
		return false
	}
	lit, ok := phpStringLiteral(f.module, args[0])
	return ok && (strings.HasPrefix(lit, "ROLE_") || strings.HasPrefix(lit, "IS_AUTHENTICATED"))
}

func (f *phpFlow) isAuthenticatedGuard(n *sitter.Node) bool {
	if n == nil {
		return false
	}
	if f.mentionsSession(n) {
		return true
	}
	if n.Kind() == "member_call_expression" && strings.EqualFold(phpText(f.module, phpField(n, "name")), "getUser") {
		return true
	}
	if n.Kind() != "binary_expression" {
		return false
	}
	switch phpOperator(f.module, n) {
	case "===", "==", "!==", "!=":
	default:
		return false
	}
	left, right := phpField(n, "left"), phpField(n, "right")
	return (f.mentionsGetUser(left) && f.isNull(right)) || (f.mentionsGetUser(right) && f.isNull(left))
}

func (f *phpFlow) isNull(n *sitter.Node) bool {
	return n != nil && (n.Kind() == "null" || strings.EqualFold(phpText(f.module, n), "null"))
}

func (f *phpFlow) mentionsGetUser(n *sitter.Node) bool {
	found := false
	phpWalk(n, func(c *sitter.Node) {
		if c.Kind() == "member_call_expression" && strings.EqualFold(phpText(f.module, phpField(c, "name")), "getUser") {
			found = true
		}
	})
	return found
}

func (f *phpFlow) mentionsSession(n *sitter.Node) bool {
	found := false
	phpWalk(n, func(c *sitter.Node) {
		if c.Kind() == "subscript_expression" {
			base := phpField(c, "variable")
			if base == nil {
				base = c.NamedChild(0)
			}
			if phpVarName(f.module, base) == "_SESSION" || phpText(f.module, base) == "$_SESSION" {
				found = true
			}
		}
	})
	return found
}

func (f *phpFlow) isOwnershipGuard(n *sitter.Node) bool {
	if n == nil || n.Kind() != "binary_expression" {
		return false
	}
	switch phpOperator(f.module, n) {
	case "===", "==", "!==", "!=":
	default:
		return false
	}
	left, right := phpField(n, "left"), phpField(n, "right")
	if f.mentionsGetUser(left) == f.mentionsGetUser(right) && !(f.identityChain(left) && f.identityChain(right)) {
		return false
	}
	if f.mentionsGetUser(left) || f.mentionsGetUser(right) {
		return true
	}
	return f.identityChain(left) && f.identityChain(right)
}

func (f *phpFlow) identityChain(n *sitter.Node) bool {
	if n == nil {
		return false
	}
	switch n.Kind() {
	case "member_call_expression":
		name := strings.ToLower(phpText(f.module, phpField(n, "name")))
		if name != "getid" && name != "getowner" {
			return false
		}
		return true
	default:
		return false
	}
}

func (f *phpFlow) isSecretGuard(n *sitter.Node) bool {
	if n == nil || n.Kind() != "binary_expression" {
		return false
	}
	switch phpOperator(f.module, n) {
	case "===", "==", "!==", "!=":
	default:
		return false
	}
	left, right := phpField(n, "left"), phpField(n, "right")
	getter, other := (*sitter.Node)(nil), (*sitter.Node)(nil)
	if f.storedGetter(left) {
		getter, other = left, right
	} else if f.storedGetter(right) {
		getter, other = right, left
	} else {
		return false
	}
	if !f.requestSide(other) {
		return false
	}
	return !f.writesComparedField(getter, other)
}

func (f *phpFlow) storedGetter(n *sitter.Node) bool {
	if n == nil || n.Kind() != "member_call_expression" {
		return false
	}
	name := phpText(f.module, phpField(n, "name"))
	if !strings.HasPrefix(strings.ToLower(name), "get") {
		return false
	}
	switch strings.ToLower(name) {
	case "getid", "getuser", "getowner", "getclientip", "getclientips":
		return false
	}
	return true
}

func (f *phpFlow) requestSide(n *sitter.Node) bool {
	if n == nil {
		return false
	}
	if n.Kind() == "variable_name" {
		return true
	}
	if n.Kind() == "member_call_expression" && strings.EqualFold(phpText(f.module, phpField(n, "name")), "get") {
		return true
	}
	return false
}

func (f *phpFlow) writesComparedField(getter, value *sitter.Node) bool {
	field := strings.TrimPrefix(phpText(f.module, phpField(getter, "name")), "get")
	val := ""
	if value != nil && value.Kind() == "variable_name" {
		val = phpVarName(f.module, value)
	}
	method := enclosingMethod(getter)
	if method == nil || field == "" || val == "" {
		return false
	}
	written := false
	phpWalk(phpField(method, "body"), func(n *sitter.Node) {
		if n.Kind() != "member_call_expression" {
			return
		}
		name := phpText(f.module, phpField(n, "name"))
		if !strings.EqualFold(name, "set"+field) {
			return
		}
		args := phpArgs(n)
		if len(args) > 0 && phpVarName(f.module, args[0]) == val {
			written = true
		}
	})
	return written
}

func (f *phpFlow) isPrivateCall(n *sitter.Node) bool {
	if n == nil || n.Kind() != "member_call_expression" || f.class == nil {
		return false
	}
	obj := phpField(n, "object")
	if phpVarName(f.module, obj) != "this" {
		return false
	}
	fn := phpOwnMethod(f.class, phpText(f.module, phpField(n, "name")))
	return fn != nil && phpMethodPrivate(f.class.module, fn)
}

func (f *phpFlow) privateGuardBody(call *sitter.Node) *sitter.Node {
	fn := phpOwnMethod(f.class, phpText(f.module, phpField(call, "name")))
	body := phpField(fn, "body")
	if body == nil {
		return nil
	}
	for i := uint(0); i < body.NamedChildCount(); i++ {
		s := body.NamedChild(i)
		switch s.Kind() {
		case "return_statement":
			if s.NamedChildCount() > 0 {
				return s.NamedChild(0)
			}
		case "if_statement":
			if f.authzExits(phpField(s, "body")) || f.authzExits(phpField(s, "alternative")) {
				return phpField(s, "condition")
			}
		case "expression_statement":
			c := s.NamedChild(0)
			if c != nil && c.Kind() == "member_call_expression" {
				return c
			}
		}
	}
	return nil
}

func (f *phpFlow) priorGuardCall(stmt *sitter.Node) *sitter.Node {
	c := stmt.NamedChild(0)
	if c != nil && f.isPrivateCall(c) {
		return c
	}
	return nil
}

func phpMethodPrivate(m *phpModule, fn *sitter.Node) bool {
	for i := uint(0); i < fn.NamedChildCount(); i++ {
		c := fn.NamedChild(i)
		if c.Kind() == "visibility_modifier" && strings.EqualFold(phpText(m, c), "private") {
			return true
		}
	}
	return false
}

func (f *phpFlow) authzExits(body *sitter.Node) bool {
	if body == nil {
		return false
	}
	if body.Kind() == "else_clause" || body.Kind() == "else_if_clause" {
		if b := phpField(body, "body"); b != nil {
			return f.authzExits(b)
		}
		if body.NamedChildCount() > 0 {
			return f.authzExits(body.NamedChild(0))
		}
	}
	if phpSkips(body) {
		return true
	}
	last := body
	if body.Kind() == "compound_statement" {
		if body.NamedChildCount() == 0 {
			return false
		}
		last = body.NamedChild(body.NamedChildCount() - 1)
	}
	switch last.Kind() {
	case "exit_statement":
		return true
	case "expression_statement":
		c := last.NamedChild(0)
		if c != nil && c.Kind() == "function_call_expression" {
			name := strings.ToLower(strings.TrimPrefix(f.callName(c), "\\"))
			return name == "exit" || name == "die"
		}
	}
	return false
}

func phpNodeWithin(parent, child *sitter.Node) bool {
	if parent == nil || child == nil {
		return false
	}
	return child.StartByte() >= parent.StartByte() && child.EndByte() <= parent.EndByte()
}

func enclosingMethod(n *sitter.Node) *sitter.Node {
	for n != nil {
		if n.Kind() == "method_declaration" || n.Kind() == "function_definition" {
			return n
		}
		n = n.Parent()
	}
	return nil
}
