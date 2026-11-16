package parse

import (
	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
)

// PGlite (@electric-sql/pglite) is embedded Postgres. A receiver is a PGlite
// client only when its provenance reaches `new PGlite()` or `PGlite.create()`
// of the imported or required class: through a single local declaration, an
// awaited value, `.catch`/`.finally`, a resolved helper whose every return is a
// client, or a `globalThis` cache whose every assignment is a client.

const pgliteModule = "@electric-sql/pglite"

// pgliteCall classifies db.query / db.exec on a verified client.
func (s *moduleSet) pgliteCall(m *sourceModule, call *sitter.Node, name, method string) []analysis.Evidence {
	if method != "query" && method != "exec" {
		return nil
	}
	decl := s.singleDeclaration(m, call, name)
	if decl == nil {
		return nil
	}
	return s.pgliteSource(m, decl.ChildByFieldName("value"), 0)
}

// singleDeclaration returns the only declarator of name in the innermost
// enclosing function (or module) that declares it, when it is never reassigned.
func (s *moduleSet) singleDeclaration(m *sourceModule, at *sitter.Node, name string) *sitter.Node {
	scope := m.tree.RootNode()
	for p := at.Parent(); p != nil; p = p.Parent() {
		if isFunction(p) || p.Kind() == "function_declaration" {
			if d := declarationIn(p, name, m.src); d != nil {
				scope = p
				break
			}
		}
	}
	var decl *sitter.Node
	count := 0
	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		if n.Kind() == "variable_declarator" {
			if id := n.ChildByFieldName("name"); id != nil && id.Kind() == "identifier" && id.Utf8Text(m.src) == name {
				count++
				decl = n
			}
		}
		if n.Kind() == "assignment_expression" {
			if l := n.ChildByFieldName("left"); l != nil && l.Utf8Text(m.src) == name {
				count += 2
			}
		}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			visit(n.NamedChild(i))
		}
	}
	visit(scope)
	if count != 1 {
		return nil
	}
	return decl
}

func (s *moduleSet) pgliteSource(m *sourceModule, v *sitter.Node, depth int) []analysis.Evidence {
	v = unwrapTS(v)
	if v == nil || depth > 6 {
		return nil
	}
	for v.Kind() == "await_expression" || v.Kind() == "parenthesized_expression" {
		if v.NamedChildCount() != 1 {
			return nil
		}
		v = unwrapTS(v.NamedChild(0))
	}
	switch v.Kind() {
	case "new_expression":
		if c := v.ChildByFieldName("constructor"); c != nil && s.pgliteClass(m, c) {
			return []analysis.Evidence{m.evidence("sink_binding", v)}
		}
	case "identifier":
		if d := s.singleDeclaration(m, v, v.Utf8Text(m.src)); d != nil {
			return s.pgliteSource(m, d.ChildByFieldName("value"), depth+1)
		}
	case "member_expression":
		if obj := v.ChildByFieldName("object"); obj != nil && obj.Utf8Text(m.src) == "globalThis" && !topLevelBinding(m, "globalThis") {
			return s.pgliteGlobal(m, v.Utf8Text(m.src), depth)
		}
	case "call_expression":
		fn := v.ChildByFieldName("function")
		if fn == nil {
			return nil
		}
		if fn.Kind() == "member_expression" {
			obj, prop := fn.ChildByFieldName("object"), fn.ChildByFieldName("property")
			if obj != nil && prop != nil {
				switch prop.Utf8Text(m.src) {
				case "create":
					if s.pgliteClass(m, obj) {
						return []analysis.Evidence{m.evidence("sink_binding", v)}
					}
				case "catch", "finally":
					return s.pgliteSource(m, obj, depth+1)
				}
			}
		}
		hm, helper := s.resolveCall(m, v)
		if hm == nil || helper == nil || !supportedCallee(helper) {
			return nil
		}
		body := helper.ChildByFieldName("body")
		if body == nil {
			return nil
		}
		if body.Kind() != "statement_block" {
			return s.pgliteSource(hm, body, depth+1)
		}
		var out []analysis.Evidence
		ok, returns := true, 0
		var visit func(*sitter.Node)
		visit = func(c *sitter.Node) {
			if !ok || isFunction(c) {
				return
			}
			if c.Kind() == "return_statement" {
				returns++
				if c.NamedChildCount() != 1 {
					ok = false
					return
				}
				b := s.pgliteSource(hm, c.NamedChild(0), depth+1)
				if b == nil {
					ok = false
					return
				}
				out = append(out, b...)
				return
			}
			for i := uint(0); i < c.NamedChildCount(); i++ {
				visit(c.NamedChild(i))
			}
		}
		visit(body)
		if ok && returns > 0 {
			return append([]analysis.Evidence{hm.evidence("sink_binding", helper)}, out...)
		}
	}
	return nil
}

// pgliteGlobal verifies a globalThis cache: every assignment to it in the
// module stores a client (deletion is allowed).
func (s *moduleSet) pgliteGlobal(m *sourceModule, target string, depth int) []analysis.Evidence {
	var out []analysis.Evidence
	ok, assigned := true, 0
	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		if !ok {
			return
		}
		if n.Kind() == "assignment_expression" || n.Kind() == "augmented_assignment_expression" {
			if l := n.ChildByFieldName("left"); l != nil && l.Utf8Text(m.src) == target {
				assigned++
				b := s.pgliteSource(m, n.ChildByFieldName("right"), depth+1)
				if n.Kind() != "assignment_expression" || b == nil {
					ok = false
					return
				}
				out = append(out, b...)
			}
		}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			visit(n.NamedChild(i))
		}
	}
	visit(m.tree.RootNode())
	if !ok || assigned == 0 {
		return nil
	}
	return out
}

// pgliteClass reports the PGlite class imported or required from the package.
func (s *moduleSet) pgliteClass(m *sourceModule, n *sitter.Node) bool {
	if n == nil || n.Kind() != "identifier" || shadowed(n, n.Utf8Text(m.src), m.src) {
		return false
	}
	imp, ok := m.imports[n.Utf8Text(m.src)]
	return ok && imp.module == pgliteModule && imp.name == "PGlite"
}

// pgliteFactory reports a call that returns a verified PGlite client from a
// resolved helper (such as a cached getDatabase()). Its body is setup code, not
// request flow, so the caller treats the result as an opaque client.
func (s *moduleSet) pgliteFactory(m *sourceModule, call *sitter.Node) bool {
	hm, helper := s.resolveCall(m, call)
	return hm != nil && helper != nil && hm != m && s.pgliteSource(m, call, 0) != nil
}
