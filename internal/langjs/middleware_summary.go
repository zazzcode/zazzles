package langjs

import (
	sitter "github.com/tree-sitter/go-tree-sitter"
	"strings"
)

// headerOnlyMiddleware recognizes a closed grammar: constant header emissions,
// followed by exactly one next() call. It cannot read or write the request,
// authorize, terminate, call helpers, or decide dispatch from external state.
func headerOnlyMiddleware(m *sourceModule, body *sitter.Node) bool {
	if body == nil || body.Parent() == nil || body.Kind() != "statement_block" {
		return false
	}
	params := plainParameters(body.Parent(), m.src)
	if len(params) != 3 || params[0] == params[1] || params[0] == params[2] || params[1] == params[2] || body.NamedChildCount() == 0 {
		return false
	}
	for i := uint(0); i < body.NamedChildCount(); i++ {
		stmt := body.NamedChild(i)
		if stmt.Kind() != "expression_statement" || stmt.NamedChildCount() != 1 {
			return false
		}
		call := stmt.NamedChild(0)
		if call.Kind() != "call_expression" {
			return false
		}
		fn, args := call.ChildByFieldName("function"), call.ChildByFieldName("arguments")
		if fn == nil || args == nil {
			return false
		}
		if i+1 == body.NamedChildCount() {
			return fn.Kind() == "identifier" && fn.Utf8Text(m.src) == params[2] && args.NamedChildCount() == 0
		}
		if fn.Kind() != "member_expression" || args.NamedChildCount() != 2 {
			return false
		}
		obj, prop := fn.ChildByFieldName("object"), fn.ChildByFieldName("property")
		if obj == nil || prop == nil || obj.Kind() != "identifier" || obj.Utf8Text(m.src) != params[1] || prop.Utf8Text(m.src) != "setHeader" {
			return false
		}
		for j := uint(0); j < 2; j++ {
			if _, ok := stringLiteral(args.NamedChild(j), m.src); !ok {
				return false
			}
		}
	}
	return false
}

func stableMiddleware(m *sourceModule, arg *sitter.Node, target *sourceModule, body *sitter.Node) bool {
	if isFunction(arg) {
		return true
	}
	if arg == nil || (arg.Kind() != "identifier" && arg.Kind() != "member_expression") {
		return false
	}
	root := strings.Split(arg.Utf8Text(m.src), ".")[0]
	if shadowed(arg, root, m.src) || !contractBindingStable(m, root, arg) {
		return false
	}
	return stableFunctionBinding(target, body.Parent())
}

func middlewareSummary(m *sourceModule, body *sitter.Node) string {
	var calls []string
	for i := uint(0); i < body.NamedChildCount(); i++ {
		calls = append(calls, body.NamedChild(i).Utf8Text(m.src))
	}
	return "Source-proven middleware body: only these constant response-header calls followed by one next() forwarding call: " + strings.Join(calls, " ")
}
