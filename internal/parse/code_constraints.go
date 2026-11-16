package parse

import (
	sitter "github.com/tree-sitter/go-tree-sitter"
	"strings"
)

// codeOperandConstraint requires a constraint on the entire operand expression.
// Conversion of one occurrence never protects an unconverted sibling use.
func codeOperandConstraint(m *sourceModule, n *sitter.Node, depth int) string {
	n = unwrapTS(n)
	if n == nil || depth > 4 {
		return ""
	}
	switch n.Kind() {
	case "number":
		return "numeric"
	case "string":
		return "constant"
	case "identifier":
		name := n.Utf8Text(m.src)
		if bindingReassigned(m, name) {
			return ""
		}
		return codeOperandConstraint(m, localInitializer(m, n, name), depth+1)
	case "call_expression":
		fn := n.ChildByFieldName("function")
		if fn == nil {
			return ""
		}
		name := fn.Utf8Text(m.src)
		root := strings.Split(name, ".")[0]
		if shadowed(n, root, m.src) || topLevelBinding(m, root) || bindingReassigned(m, root) {
			return ""
		}
		if name == "Number" || name == "parseInt" || name == "parseFloat" {
			return "numeric"
		}
		if name == "JSON.stringify" {
			return "json_literal"
		}
	case "binary_expression":
		a, b := codeOperandConstraint(m, n.ChildByFieldName("left"), depth+1), codeOperandConstraint(m, n.ChildByFieldName("right"), depth+1)
		if a != "" && b != "" && a != "json_literal" && b != "json_literal" {
			return "numeric"
		}
	case "ternary_expression":
		a, b := codeOperandConstraint(m, n.ChildByFieldName("consequence"), depth+1), codeOperandConstraint(m, n.ChildByFieldName("alternative"), depth+1)
		if a != "" && a == b {
			return a
		}
	case "template_string":
		for i := uint(0); i < n.NamedChildCount(); i++ {
			c := n.NamedChild(i)
			if c.Kind() == "template_substitution" {
				if c.NamedChildCount() != 1 {
					return ""
				}
				kind := codeOperandConstraint(m, c.NamedChild(0), depth+1)
				if kind != "numeric" && kind != "constant" {
					return ""
				}
			}
		}
		return "numeric"
	}
	return ""
}
