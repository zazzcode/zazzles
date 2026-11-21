package langjs

import (
	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"strings"
)

func plainParameters(fn *sitter.Node, src []byte) []string {
	p := fn.ChildByFieldName("parameters")
	if p == nil {
		if p = fn.ChildByFieldName("parameter"); p != nil && p.Kind() == "identifier" {
			return []string{p.Utf8Text(src)}
		}
		return nil
	}
	var names []string
	for i := uint(0); i < p.NamedChildCount(); i++ {
		n := p.NamedChild(i)
		if n.Kind() == "required_parameter" {
			if n.ChildByFieldName("value") != nil {
				return nil
			}
			n = n.ChildByFieldName("pattern")
		}
		if n == nil || n.Kind() != "identifier" {
			return nil
		}
		names = append(names, n.Utf8Text(src))
	}
	return names
}

func returnedFunction(fn *sitter.Node) *sitter.Node {
	body := fn.ChildByFieldName("body")
	if body == nil {
		return nil
	}
	if isFunction(body) {
		return body
	}
	if body.Kind() == "statement_block" && body.NamedChildCount() == 1 {
		r := body.NamedChild(0)
		if r.Kind() == "return_statement" && r.NamedChildCount() == 1 && isFunction(r.NamedChild(0)) {
			return r.NamedChild(0)
		}
	}
	return nil
}

// transparentWrapper proves a deliberately small forwarding grammar. Everything
// outside it keeps unresolved dispatch, including request writes and extra calls.
func (s *moduleSet) transparentWrapper(m *sourceModule, call *sitter.Node) (analysis.Evidence, bool) {
	if call == nil || call.Kind() != "call_expression" {
		return analysis.Evidence{}, false
	}
	fn, args := call.ChildByFieldName("function"), call.ChildByFieldName("arguments")
	if fn == nil || args == nil || args.NamedChildCount() != 1 {
		return analysis.Evidence{}, false
	}
	name := fn.Utf8Text(m.src)
	root := strings.Split(name, ".")[0]
	if shadowed(call, root, m.src) || !contractBindingStable(m, root) {
		return analysis.Evidence{}, false
	}
	target, wrapper := s.resolve(m, name)
	if target == nil || wrapper == nil || target.tree.RootNode().HasError() {
		return analysis.Evidence{}, false
	}
	if n := wrapper.ChildByFieldName("name"); n != nil && !contractBindingStable(target, n.Utf8Text(target.src)) {
		return analysis.Evidence{}, false
	}
	// Arrow declarations have their binding on the parent variable declarator.
	if p := wrapper.Parent(); p != nil && p.Kind() == "variable_declarator" {
		if n := p.ChildByFieldName("name"); n != nil && !contractBindingStable(target, n.Utf8Text(target.src)) {
			return analysis.Evidence{}, false
		}
	}
	if asyncFunction(wrapper) {
		return analysis.Evidence{}, false
	}
	outer := plainParameters(wrapper, target.src)
	inner := returnedFunction(wrapper)
	if len(outer) != 1 || inner == nil {
		return analysis.Evidence{}, false
	}
	if name := inner.ChildByFieldName("name"); name != nil && name.Utf8Text(target.src) == outer[0] {
		return analysis.Evidence{}, false
	}
	params := plainParameters(inner, target.src)
	if len(params) != 3 || params[0] == params[1] || params[0] == params[2] || params[1] == params[2] {
		return analysis.Evidence{}, false
	}
	for _, p := range params {
		if p == outer[0] {
			return analysis.Evidence{}, false
		}
	}
	forward := func(n *sitter.Node) bool {
		if n == nil || n.Kind() != "call_expression" {
			return false
		}
		f, a := n.ChildByFieldName("function"), n.ChildByFieldName("arguments")
		if f == nil || f.Kind() != "identifier" || f.Utf8Text(target.src) != outer[0] || a == nil || a.NamedChildCount() != uint(len(params)) {
			return false
		}
		for i, p := range params {
			v := a.NamedChild(uint(i))
			if v.Kind() != "identifier" || v.Utf8Text(target.src) != p {
				return false
			}
		}
		return true
	}
	var expression func(*sitter.Node) bool
	expression = func(n *sitter.Node) bool {
		if n == nil {
			return false
		}
		if forward(n) {
			return true
		}
		if n.Kind() == "unary_expression" && n.NamedChildCount() == 1 && strings.HasPrefix(n.Utf8Text(target.src), "void ") {
			return expression(n.NamedChild(0))
		}
		if n.Kind() != "call_expression" {
			return false
		}
		f, a := n.ChildByFieldName("function"), n.ChildByFieldName("arguments")
		if f == nil || a == nil || a.NamedChildCount() != 1 || f.Kind() != "member_expression" {
			return false
		}
		obj, prop := f.ChildByFieldName("object"), f.ChildByFieldName("property")
		if obj == nil || prop == nil {
			return false
		}
		switch prop.Utf8Text(target.src) {
		case "resolve":
			return obj.Kind() == "identifier" && obj.Utf8Text(target.src) == "Promise" && !shadowed(n, "Promise", target.src) && contractBindingStable(target, "Promise") && topVariable(target, "Promise") == nil && target.funcs["Promise"] == nil && target.imports["Promise"].module == "" && forward(a.NamedChild(0))
		case "catch":
			v := a.NamedChild(0)
			return v.Kind() == "identifier" && v.Utf8Text(target.src) == params[2] && expression(obj)
		}
		return false
	}
	body := inner.ChildByFieldName("body")
	if body == nil {
		return analysis.Evidence{}, false
	}
	if body.Kind() == "statement_block" {
		if body.NamedChildCount() != 1 {
			return analysis.Evidence{}, false
		}
		body = body.NamedChild(0)
		if (body.Kind() == "expression_statement" || body.Kind() == "return_statement") && body.NamedChildCount() == 1 {
			body = body.NamedChild(0)
		}
	}
	if body.Kind() == "try_statement" {
		if forwardingTry(target, body, params, outer[0], expression) {
			return target.evidence("wrapper_definition", wrapper), true
		}
	}
	if !expression(body) {
		return analysis.Evidence{}, false
	}
	return target.evidence("wrapper_definition", wrapper), true
}

func (s *moduleSet) wrapperEvidence(m *sourceModule, call *sitter.Node) []analysis.Evidence {
	if e, ok := s.transparentWrapper(m, call); ok {
		return []analysis.Evidence{e}
	}
	return nil
}

// forwardingTry permits a synchronous forwarding call with error-only dispatch.
func forwardingTry(m *sourceModule, stmt *sitter.Node, params []string, wrapped string, expression func(*sitter.Node) bool) bool {
	body, handler := stmt.ChildByFieldName("body"), stmt.ChildByFieldName("handler")
	if body == nil || handler == nil || stmt.NamedChildCount() != 2 || body.NamedChildCount() != 1 {
		return false
	}
	call := body.NamedChild(0)
	if (call.Kind() != "return_statement" && call.Kind() != "expression_statement") || call.NamedChildCount() != 1 || !expression(call.NamedChild(0)) {
		return false
	}
	errParam, catchBody := handler.ChildByFieldName("parameter"), handler.ChildByFieldName("body")
	if errParam == nil || errParam.Kind() != "identifier" || catchBody == nil || catchBody.NamedChildCount() != 1 {
		return false
	}
	name := errParam.Utf8Text(m.src)
	if name == wrapped {
		return false
	}
	for _, p := range params {
		if name == p {
			return false
		}
	}
	next := catchBody.NamedChild(0)
	if (next.Kind() != "expression_statement" && next.Kind() != "return_statement") || next.NamedChildCount() != 1 {
		return false
	}
	next = next.NamedChild(0)
	if next.Kind() != "call_expression" {
		return false
	}
	fn, args := next.ChildByFieldName("function"), next.ChildByFieldName("arguments")
	return fn != nil && fn.Kind() == "identifier" && fn.Utf8Text(m.src) == params[2] && args != nil && args.NamedChildCount() == 1 && args.NamedChild(0).Kind() == "identifier" && args.NamedChild(0).Utf8Text(m.src) == name
}

// A literal option to a middleware factory is not a wrapped handler.
func handlerArgument(n *sitter.Node) bool {
	if n == nil {
		return false
	}
	return isFunction(n) || n.Kind() == "identifier" || n.Kind() == "member_expression" || n.Kind() == "call_expression"
}

func stableFunctionBinding(m *sourceModule, fn *sitter.Node) bool {
	if fn == nil {
		return false
	}
	name := fn.ChildByFieldName("name")
	if p := fn.Parent(); p != nil && p.Kind() == "variable_declarator" {
		name = p.ChildByFieldName("name")
	}
	if name == nil {
		return true
	}
	binding := name.Utf8Text(m.src)
	stable := true
	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		if !stable {
			return
		}
		var left *sitter.Node
		switch n.Kind() {
		case "assignment_expression", "augmented_assignment_expression":
			left = n.ChildByFieldName("left")
		case "update_expression":
			left = n.ChildByFieldName("argument")
		}
		if left != nil {
			text := left.Utf8Text(m.src)
			if text == binding || strings.HasPrefix(text, binding+".") || strings.HasPrefix(text, binding+"[") {
				stable = false
				return
			}
		}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			visit(n.NamedChild(i))
		}
	}
	visit(m.tree.RootNode())
	return stable
}

func asyncFunction(fn *sitter.Node) bool {
	for i := uint(0); i < fn.ChildCount(); i++ {
		if fn.Child(i).Kind() == "async" {
			return true
		}
	}
	return false
}
