package langjs

import (
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
)

// conditionalConstraints describes output alternatives, rather than propagating
// a conversion's guarantee across sibling branches. It does not decide injection.
func conditionalConstraints(m *sourceModule, n *sitter.Node, c *analysis.Completeness) {
	if n == nil || n.Kind() != "ternary_expression" {
		return
	}
	var alternatives []*sitter.Node
	var collect func(*sitter.Node, int) bool
	collect = func(value *sitter.Node, depth int) bool {
		if value == nil || depth > 8 {
			return false
		}
		if value.Kind() == "parenthesized_expression" {
			return collect(value.NamedChild(0), depth+1)
		}
		if value.Kind() == "ternary_expression" {
			return collect(value.ChildByFieldName("consequence"), depth+1) && collect(value.ChildByFieldName("alternative"), depth+1)
		}
		alternatives = append(alternatives, value)
		return true
	}
	if !collect(n, 0) {
		return
	}
	allNumeric := true
	for _, value := range alternatives {
		code := "output_alternative_unconstrained"
		if numericQueryValue(m, value) {
			code = "output_alternative_numeric"
		} else {
			allNumeric = false
		}
		c.ModelFacts = append(c.ModelFacts, code+": "+value.Utf8Text(m.src)+" at "+m.file)
	}
	if allNumeric {
		c.ModelFacts = append(c.ModelFacts, "numeric_output_expression: "+n.Utf8Text(m.src)+" at "+m.file)
	}
}

func numericQueryValue(m *sourceModule, n *sitter.Node) bool {
	if n == nil {
		return false
	}
	switch n.Kind() {
	case "number":
		return !strings.HasSuffix(n.Utf8Text(m.src), "n")
	case "parenthesized_expression":
		return numericQueryValue(m, n.NamedChild(0))
	case "call_expression":
		fn := n.ChildByFieldName("function")
		return fn != nil && fn.Utf8Text(m.src) == "Number" && nativeStringOperation(m, n)
	}
	return false
}
