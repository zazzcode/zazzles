package parse

import (
	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
)

// controlContext exposes branch tests and statement successors rather than
// flattening validation branches into one unconditional list of calls.
func controlContext(m *sourceModule, body *sitter.Node) ([]analysis.ControlEdge, []analysis.Gap) {
	edges := []analysis.ControlEdge{}
	gaps := []analysis.Gap{}
	if body != nil && body.Kind() == "call_expression" {
		return edges, gaps
	} // implicit return of a concise handler
	var statement func(*sitter.Node, *sitter.Node) *sitter.Node
	statement = func(n, next *sitter.Node) *sitter.Node {
		if n == nil {
			return next
		}
		if n.Kind() == "statement_block" {
			head := next
			for i := int(n.NamedChildCount()) - 1; i >= 0; i-- {
				head = statement(n.NamedChild(uint(i)), head)
			}
			return head
		}
		if n.Kind() == "comment" || n.Kind() == "function_declaration" {
			return next
		}
		if n.Kind() == "if_statement" {
			condition := n.ChildByFieldName("condition")
			yes := statement(n.ChildByFieldName("consequence"), next)
			no := statement(n.ChildByFieldName("alternative"), next)
			if condition == nil {
				gaps = append(gaps, analysis.Gap{Kind: "control_flow_unresolved", Detail: "if condition missing", At: spanOf(m.file, n)})
				return n
			}
			for _, branch := range []struct {
				node *sitter.Node
				kind string
			}{{yes, "TRUE_BRANCH"}, {no, "FALSE_BRANCH"}} {
				if branch.node != nil {
					edges = append(edges, analysis.ControlEdge{From: m.evidence("condition", condition), To: m.evidence("statement", branch.node), Kind: branch.kind})
				}
			}
			return condition
		}
		if n.Kind() == "try_statement" && n.ChildByFieldName("finalizer") == nil {
			// A try body runs unconditionally up to a throw, so it does not guard its
			// statements; catch is a separate exceptional successor. finally stays a gap.
			head := statement(n.ChildByFieldName("body"), next)
			if handler := n.ChildByFieldName("handler"); handler != nil {
				if caught := statement(handler.ChildByFieldName("body"), next); caught != nil && head != nil {
					edges = append(edges, analysis.ControlEdge{From: m.evidence("statement", head), To: m.evidence("statement", caught), Kind: "EXCEPTION"})
				}
			}
			return head
		}
		switch n.Kind() {
		case "return_statement", "throw_statement":
			return n
		case "expression_statement", "lexical_declaration", "variable_declaration", "empty_statement":
			if next != nil {
				edges = append(edges, analysis.ControlEdge{From: m.evidence("statement", n), To: m.evidence("statement", next), Kind: "NEXT"})
			}
			return n
		case "else_clause":
			if n.NamedChildCount() > 0 {
				return statement(n.NamedChild(0), next)
			}
			return next
		default:
			gaps = append(gaps, analysis.Gap{Kind: "control_flow_unresolved", Detail: "unsupported control statement: " + n.Kind(), At: spanOf(m.file, n)})
			return n
		}
	}
	statement(body, nil)
	return edges, gaps
}
