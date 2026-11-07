package parse

import (
	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
	"strconv"
	"strings"
)

func (f *pythonStatic) bind(n *sitter.Node, v *pythonStaticValue) bool {
	if n == nil {
		return false
	}
	if n.Kind() == "identifier" {
		copy := *v
		if len(copy.evidence) == 0 {
			copy.evidence = []analysis.Evidence{f.evidence("constant_binding", n)}
		}
		f.env[pyText(f.module, n)] = &copy
		return true
	}
	if n.Kind() == "pattern_list" || n.Kind() == "tuple_pattern" || n.Kind() == "tuple" {
		if int(n.NamedChildCount()) != len(v.items) {
			return false
		}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			if !f.bind(n.NamedChild(i), v.items[i]) {
				return false
			}
		}
		return true
	}
	return false
}
func (f *pythonStatic) block(n *sitter.Node) bool {
	for i := uint(0); n != nil && i < n.NamedChildCount(); i++ {
		if f.stmt(n.NamedChild(i)) {
			return true
		}
	}
	return false
}
func (f *pythonStatic) stmt(n *sitter.Node) bool {
	if n == nil || !f.tick(n) {
		return false
	}
	f.pos = n.StartByte()
	switch n.Kind() {
	case "expression_statement":
		for i := uint(0); i < n.NamedChildCount(); i++ {
			c := n.NamedChild(i)
			if c.Kind() == "assignment" {
				left := c.ChildByFieldName("left")
				if !f.bind(left, f.eval(c.ChildByFieldName("right"))) {
					root := left
					for root != nil && (root.Kind() == "subscript" || root.Kind() == "attribute") {
						if root.Kind() == "attribute" {
							root = root.ChildByFieldName("object")
						} else {
							root = root.ChildByFieldName("value")
						}
					}
					if root != nil {
						f.taint(f.eval(root), c, "Unsupported registry/member assignment")
					}
				}
			} else {
				f.eval(c)
			}
		}
	case "function_definition":
		f.env[pyText(f.module, n.ChildByFieldName("name"))] = &pythonStaticValue{module: f.module, fn: n, closure: staticEnv(f.env)}
	case "decorated_definition":
		fn := n.ChildByFieldName("definition")
		if fn == nil || fn.Kind() != "function_definition" {
			return false
		}
		f.stmt(fn)
		if f.depth > 0 {
			for i := uint(0); i < n.NamedChildCount(); i++ {
				d := n.NamedChild(i)
				if d.Kind() == "decorator" && d.NamedChildCount() > 0 {
					f.registration(d.NamedChild(0), fn, d)
				}
			}
		}
	case "return_statement":
		if n.NamedChildCount() > 0 {
			f.returned = f.eval(n.NamedChild(0))
		} else {
			f.returned = staticText("None")
		}
		return true
	case "for_statement":
		values := f.eval(n.ChildByFieldName("right"))
		items, ok := staticItems(values)
		if !ok {
			return false
		}
		for i, v := range items {
			if i >= 128 {
				f.gap(n, "Finite generation limit (128/site) reached; remainder unexpanded")
				break
			}
			if !f.bind(n.ChildByFieldName("left"), v) {
				f.gap(n, "Unresolved finite iteration binding")
				break
			}
			before := len(f.provenance)
			f.provenance = append(f.provenance, f.evidence("generation_loop", n))
			f.provenance = append(f.provenance, v.evidence...)
			stopped := f.block(n.ChildByFieldName("body"))
			f.provenance = f.provenance[:before]
			if stopped {
				return true
			}
		}
	case "try_statement":
		return f.block(n.ChildByFieldName("body"))
	case "if_statement":
		v := f.eval(n.ChildByFieldName("condition"))
		if !v.known {
			return false
		}
		if staticTruth(v) {
			return f.block(n.ChildByFieldName("consequence"))
		}
		alt := n.ChildByFieldName("alternative")
		if alt != nil {
			return f.block(pyBody(alt))
		}
	}
	return false
}

func (f *pythonStatic) invoke(call *sitter.Node, v *pythonStaticValue, args []*pythonStaticValue) *pythonStaticValue {
	if v.fn == nil || v.module == nil {
		return staticUnknown()
	}
	key := v.module.file + ":" + strconv.Itoa(int(v.fn.StartByte()))
	if f.depth >= 8 || f.stack[key] {
		f.gap(call, "Finite factory/registry depth (8) or recursion limit")
		return staticUnknown()
	}
	f.stack[key] = true
	defer delete(f.stack, key)
	h := *f
	h.module = v.module
	h.env = staticEnv(v.closure)
	h.depth++
	h.returned = nil
	h.provenance = append(append([]analysis.Evidence{}, f.provenance...), f.evidence("factory_call", call), v.module.evidence("factory_definition", v.fn))
	params := v.fn.ChildByFieldName("parameters")
	if params != nil && int(params.NamedChildCount()) != len(args) {
		return staticUnknown()
	}
	for i, arg := range args {
		copy := *arg
		copy.evidence = append(append([]analysis.Evidence{}, arg.evidence...), v.module.evidence("factory_parameter", params.NamedChild(uint(i))), f.evidence("factory_argument", call))
		if !h.bind(params.NamedChild(uint(i)), &copy) {
			return staticUnknown()
		}
	}
	h.block(v.fn.ChildByFieldName("body"))
	if h.returned != nil {
		copy := *h.returned
		copy.evidence = append(append([]analysis.Evidence{}, copy.evidence...), f.evidence("static_call_binding", call), v.module.evidence("static_definition", v.fn))
		return &copy
	}
	return staticUnknown()
}

func (f *pythonStatic) call(n *sitter.Node) *pythonStaticValue {
	fn := n.ChildByFieldName("function")
	name := pyText(f.module, fn)
	q := f.set.qualified(f.module, name)
	root := strings.Split(name, ".")[0]
	if _, shadow := f.env[root]; shadow {
		q = ""
	}
	if f.set.staticInvalid[f.module.file+":"+root] {
		q = ""
	}
	if name == "getattr" {
		if _, shadow := f.env[name]; !shadow {
			q = "getattr"
		}
	}
	nodes := pyArgs(n)
	args := make([]*pythonStaticValue, len(nodes))
	for i, a := range nodes {
		args[i] = f.eval(a)
	}
	if v, ok := f.adapterCall(n, q, fn, args); ok {
		return v
	}
	if fn != nil && fn.Kind() == "attribute" {
		method := pyText(f.module, fn.ChildByFieldName("attribute"))
		if method == "add_url_rule" {
			if len(args) > 2 && args[2].fn != nil {
				f.registration(n, args[2].fn, n)
			}
			return staticUnknown()
		}
		base := f.eval(fn.ChildByFieldName("object"))
		if v, ok := f.method(n, base, method, args); ok {
			copy := *v
			copy.evidence = append(append([]analysis.Evidence{}, copy.evidence...), base.evidence...)
			for _, a := range args {
				copy.evidence = append(copy.evidence, a.evidence...)
			}
			copy.evidence = append(copy.evidence, f.evidence("static_naming_operation", n))
			return &copy
		}
		if base.fields != nil || base.items != nil {
			f.taint(base, n, "Unsupported registry/member method: "+method)
		}
	}
	if v, ok := f.libraryCall(n, q, args); ok {
		copy := *v
		copy.evidence = append([]analysis.Evidence{}, copy.evidence...)
		for _, a := range args {
			copy.evidence = append(copy.evidence, a.evidence...)
		}
		copy.evidence = append(copy.evidence, f.evidence("static_source_operation", n))
		return &copy
	}
	callee := f.eval(fn)
	if callee.fn != nil {
		return f.invoke(n, callee, args)
	}
	for _, arg := range args {
		f.taint(arg, n, "Unresolved call may mutate finite registry data")
	}
	return staticUnknown()
}

func (f *pythonFlow) staticCallable(call *sitter.Node) *pythonBoundCallable {
	count := 0
	routes := []pythonRoute{}
	h := &pythonStatic{set: f.set, module: f.module, env: map[string]*pythonStaticValue{}, stack: map[string]bool{}, work: &count, routes: &routes}
	for k, v := range f.env {
		if v.constant {
			h.env[k] = staticText(v.literal)
		} else {
			h.env[k] = staticUnknown()
		}
	}
	v := h.eval(call)
	if v.fn != nil && v.module != nil {
		evidence := []analysis.Evidence{f.module.evidence("callable_selection", call), v.module.evidence("selected_callable", v.fn)}
		target, key := f.set.resolve(f.module, pyText(f.module, call.ChildByFieldName("function")), 0)
		if target != nil && target.funcs[key] != nil {
			evidence = append(evidence, target.evidence("selection_definition", target.funcs[key]))
		}
		return &pythonBoundCallable{module: v.module, fn: v.fn, evidence: evidence}
	}
	return nil
}

func (f *pythonFlow) constantCondition(n *sitter.Node) (bool, bool) {
	if outcome, known := f.methodCondition(n); known {
		return outcome, true
	}
	if n == nil {
		return false, false
	}
	// Only literal/closure comparisons and their Boolean combinations are folded.
	// Calls, request predicates and unknown bindings retain the existing may-paths.
	var allowed func(*sitter.Node) bool
	allowed = func(n *sitter.Node) bool {
		if n == nil {
			return false
		}
		switch n.Kind() {
		case "identifier":
			v, ok := f.env[pyText(f.module, n)]
			return ok && v.constant
		case "string", "true", "false", "integer":
			return true
		case "comparison_operator", "boolean_operator", "not_operator":
			for i := uint(0); i < n.NamedChildCount(); i++ {
				if !allowed(n.NamedChild(i)) {
					return false
				}
			}
			return true
		}
		return false
	}
	if !allowed(n) {
		return false, false
	}
	count := 0
	h := &pythonStatic{set: f.set, module: f.module, env: map[string]*pythonStaticValue{}, stack: map[string]bool{}, work: &count}
	for k, v := range f.env {
		if v.constant {
			h.env[k] = staticText(v.literal)
		}
	}
	v := h.eval(n)
	return staticTruth(v), v.known
}

func (f *pythonStatic) taint(v *pythonStaticValue, n *sitter.Node, detail string) {
	if v.tainted != nil {
		*v.tainted = true
		f.gap(n, detail)
	}
}
