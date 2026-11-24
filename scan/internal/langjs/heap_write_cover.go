package langjs

import (
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/parse"
)

// literalWriteBesideOperand reports an unsupported_write gap that leaves the
// claim's operand intact (hardening 3 D-4). Both must hold:
//
//   - the write assigns a literal to a member chain rooted at a parameter of an
//     enclosing function (the request or response object);
//   - no dependency of the operand reads the written chain, a member of it or an
//     object that holds it, at or after the write. A read is compared after its
//     constant aliases are expanded, and a read whose root is a local built from
//     anything but a member chain may alias the written object, so it keeps the
//     gap a blocker.
//
// The ssrf, path and code families call this from their gapCovered hooks. The
// pollution family reads these gaps as its evidence (pollution_writes.go) and
// the query families have their own rule; neither calls it.
func (s *moduleSet) literalWriteBesideOperand(u *analysis.CandidateUse, g analysis.Gap) bool {
	if g.Kind != "unsupported_write" || g.At.File != u.Sink.Span.File {
		return false
	}
	m := s.modules[g.At.File]
	if m == nil {
		return false
	}
	root := m.tree.RootNode()
	write := parse.NodeAt(root, g.At.StartByte, g.At.EndByte)
	if write == nil || write.Kind() != "assignment_expression" || !literalNode(unwrapTS(write.ChildByFieldName("right"))) {
		return false
	}
	scope := enclosingFunction(write)
	if scope == nil {
		return false
	}
	for p := write.Parent(); p != nil && p != scope; p = p.Parent() {
		switch p.Kind() {
		case "for_statement", "for_in_statement", "while_statement", "do_statement":
			return false // a later iteration can read the member before this write again
		}
	}
	written, ok := memberChain(unwrapTS(write.ChildByFieldName("left")), m.src)
	if !ok || len(written) < 2 || !parameterOfEnclosing(m, write, written[0]) || singleDeclaration(written[0], scope, m.src) != nil {
		return false
	}
	for _, d := range u.Dependencies {
		for _, e := range append(append([]analysis.Evidence{d.Source}, d.Transfers...), u.Sink) {
			if e.Span.File != g.At.File {
				return false // the value passes through code this rule does not read
			}
			if e.Span.EndByte <= g.At.EndByte {
				continue // read before the write
			}
			n := parse.NodeAt(root, e.Span.StartByte, e.Span.EndByte)
			if n != nil && e.Span == u.Sink.Span && n.Kind() == "call_expression" {
				// The operation's operands are its arguments; its receiver (the
				// response object of res.sendFile) is not a value the claim follows.
				n = n.ChildByFieldName("arguments")
			}
			if n == nil || !readsApartFrom(m, n, scope, written, uint(g.At.EndByte)) {
				return false
			}
		}
	}
	return true
}

func literalNode(n *sitter.Node) bool {
	if n == nil {
		return false
	}
	switch n.Kind() {
	case "string", "number", "true", "false", "null", "undefined":
		return true
	case "template_string":
		return n.NamedChildCount() == 0 || noSubstitution(n)
	}
	return false
}

func noSubstitution(n *sitter.Node) bool {
	for i := uint(0); i < n.NamedChildCount(); i++ {
		if n.NamedChild(i).Kind() == "template_substitution" {
			return false
		}
	}
	return true
}

// memberChain returns the names of a plain member chain (a.b.c). A call, a
// subscript or a computed member is not a plain chain.
func memberChain(n *sitter.Node, src []byte) ([]string, bool) {
	var out []string
	for n != nil {
		switch n.Kind() {
		case "identifier":
			out = append([]string{n.Utf8Text(src)}, out...)
			return out, true
		case "member_expression":
			prop := n.ChildByFieldName("property")
			if prop == nil || prop.Kind() != "property_identifier" {
				return nil, false
			}
			out = append([]string{prop.Utf8Text(src)}, out...)
			n = unwrapTS(n.ChildByFieldName("object"))
		default:
			return nil, false
		}
	}
	return nil, false
}

// readsApartFrom reports that every value read under n, at or after the byte
// offset from, is apart from the written chain.
func readsApartFrom(m *sourceModule, n, scope *sitter.Node, written []string, from uint) bool {
	apart := true
	var walk func(x *sitter.Node, callee bool)
	walk = func(x *sitter.Node, callee bool) {
		if x == nil || !apart || x.EndByte() <= from {
			return
		}
		switch x.Kind() {
		case "identifier", "shorthand_property_identifier":
			if !callee {
				apart = chainApart(m, []string{x.Utf8Text(m.src)}, scope, written, 0)
			}
			return
		case "member_expression":
			if chain, ok := memberChain(x, m.src); ok {
				if callee {
					chain = chain[:len(chain)-1] // the method name is not a read of a value
				}
				apart = len(chain) == 0 || chainApart(m, chain, scope, written, 0)
				return
			}
		case "call_expression":
			walk(x.ChildByFieldName("function"), true)
			walk(x.ChildByFieldName("arguments"), false)
			return
		case "variable_declarator":
			walk(x.ChildByFieldName("value"), false) // the declared name is not a read
			return
		case "pair":
			walk(x.ChildByFieldName("value"), false)
			return
		case "property_identifier", "type_annotation", "type_arguments":
			return
		}
		for i := uint(0); i < x.NamedChildCount(); i++ {
			walk(x.NamedChild(i), false)
		}
	}
	walk(n, false)
	return apart
}

// chainApart expands the constant alias at the root of a read chain and
// compares the result with the written chain. Two chains are apart when their
// roots differ or neither is a prefix of the other.
func chainApart(m *sourceModule, chain []string, scope *sitter.Node, written []string, depth int) bool {
	if depth > 4 {
		return false
	}
	if decl := localDeclarator(chain[0], scope, m.src); decl != nil {
		value := unwrapTS(decl.ChildByFieldName("value"))
		if value != nil && value.Kind() == "await_expression" && value.NamedChildCount() == 1 {
			value = unwrapTS(value.NamedChild(0))
		}
		base, ok := memberChain(value, m.src)
		if !ok {
			return false // built by a call or an expression: it may alias the written object
		}
		if name := decl.ChildByFieldName("name"); name != nil && name.Kind() == "object_pattern" {
			base = append(base, chain[0]) // const { link } = req.body reads req.body.link
		}
		return chainApart(m, append(append([]string{}, base...), chain[1:]...), scope, written, depth+1)
	}
	if chain[0] != written[0] {
		return true
	}
	n := len(chain)
	if len(written) < n {
		n = len(written)
	}
	return strings.Join(chain[:n], ".") != strings.Join(written[:n], ".")
}

// localDeclarator returns the declarator that binds name in scope, by an
// identifier or a shorthand name of an object pattern, or nil when there is
// none. A name with more than one declaration or an assignment returns a
// declarator with no value, which chainApart reads as a possible alias.
func localDeclarator(name string, scope *sitter.Node, src []byte) *sitter.Node {
	var found []*sitter.Node
	assigned := false
	var walk func(*sitter.Node)
	walk = func(c *sitter.Node) {
		switch c.Kind() {
		case "variable_declarator":
			id := c.ChildByFieldName("name")
			if id != nil && id.Kind() == "identifier" && id.Utf8Text(src) == name {
				found = append(found, c)
			}
			if id != nil && id.Kind() == "object_pattern" {
				for i := uint(0); i < id.NamedChildCount(); i++ {
					b := id.NamedChild(i)
					if b.Kind() == "shorthand_property_identifier_pattern" && b.Utf8Text(src) == name {
						found = append(found, c)
					} else if b.Kind() != "shorthand_property_identifier_pattern" && strings.Contains(b.Utf8Text(src), name) {
						assigned = true // a renamed, defaulted or rest binding is not expanded
					}
				}
			}
		case "assignment_expression", "augmented_assignment_expression", "update_expression":
			target := c.ChildByFieldName("left")
			if target == nil {
				target = c.ChildByFieldName("argument")
			}
			if target != nil && target.Utf8Text(src) == name {
				assigned = true
			}
		}
		for i := uint(0); i < c.NamedChildCount(); i++ {
			walk(c.NamedChild(i))
		}
	}
	walk(scope)
	if len(found) == 0 && !assigned {
		return nil
	}
	if len(found) != 1 || assigned {
		return scope // not a declarator: its "value" field is absent, so the read is a possible alias
	}
	return found[0]
}
