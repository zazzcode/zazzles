package parse

import sitter "github.com/tree-sitter/go-tree-sitter"

// pathImmediate executes only a syntactically immediate function invocation,
// preserving its lexical request/response bindings. Deferred callbacks stay gaps.
func (f *flow) pathImmediate(call *sitter.Node) (value, bool) {
	if !f.pathOnly || f.depth >= 3 {
		return value{}, false
	}
	fn := call.ChildByFieldName("function")
	for fn != nil && fn.Kind() == "parenthesized_expression" && fn.NamedChildCount() == 1 {
		fn = fn.NamedChild(0)
	}
	if fn == nil || !isFunction(fn) {
		return value{}, false
	}
	params, ok := functionParameters(fn, f.module.src)
	args := call.ChildByFieldName("arguments")
	if !ok || args == nil || args.NamedChildCount() != uint(len(params)) || callHasSpread(call) {
		return value{}, false
	}
	child := *f
	child.depth++
	child.env = map[string]value{}
	for name, v := range f.env {
		child.env[name] = v
	}
	child.uses = nil
	child.returns = nil
	for i, p := range params {
		child.env[p.name] = child.transfer(f.eval(args.NamedChild(uint(i))), "parameter_binding", p.node)
		if child.request == p.name {
			child.request = ""
		}
		if child.response == p.name {
			child.response = ""
		}
	}
	child.context = append(append(child.context[:0:0], f.context...), f.module.evidence("immediate_invocation", call))
	child.statements(fn.ChildByFieldName("body"))
	f.uses = append(f.uses, child.uses...)
	var ret value
	for _, v := range child.returns {
		ret = combine(ret, v)
	}
	return ret, true
}

// pathUnrelatedHelper proves that an unexpanded module-level function receives
// no request-origin value and cannot close over this invocation's local values.
func pathUnrelatedHelper(args []value, helper *sitter.Node) bool {
	for _, v := range args {
		for _, d := range v.deps {
			if requestOrigin(d) {
				return false
			}
		}
	}
	for p := helper.Parent(); p != nil; p = p.Parent() {
		if isFunction(p) || p.Kind() == "function_declaration" {
			return false
		}
	}
	return true
}
