package parse

import (
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
)

// Finite selections are registration constraints, separate from taint and
// protection. A proof belongs to one invocation and never folds normal flow.
type pythonFiniteValue struct {
	value      *pythonStaticValue
	invocation string
}
type pythonSelectorBinding struct {
	selector       *pythonBoundCallable
	arguments      []string
	target         *pythonBoundCallable
	registry       *pythonStaticValue
	registryModule *pythonModule
	registryName   string
}

func (f *pythonFlow) finiteEnvironment() map[string]*pythonStaticValue {
	env := map[string]*pythonStaticValue{}
	binding := f.route.selector
	if binding == nil {
		return env
	}
	for name, v := range f.env {
		switch {
		case v.finite != nil && v.finite.invocation == f.invocation.ID:
			env[name] = v.finite.value
		case v.binding == "flask_request" && f.route.route.Framework == "wsgi":
			env[name] = &pythonStaticValue{known: true, fields: map[string]*pythonStaticValue{"PATH_INFO": staticText(f.route.route.PathPattern)}}
		default:
			env[name] = staticUnknown()
		}
	}
	for name := range f.module.imports {
		if f.set.staticInvalid[f.module.file+":"+name] {
			continue
		}
		m, key := f.set.resolve(f.module, name, 0)
		if m == binding.registryModule && key == binding.registryName {
			if _, local := f.env[name]; !local {
				env[name] = binding.registry
			}
		}
	}
	if f.module == binding.registryModule && !f.set.staticInvalid[f.module.file+":"+binding.registryName] {
		if _, local := f.env[binding.registryName]; !local {
			env[binding.registryName] = binding.registry
		}
	}
	return env
}
func (f *pythonFlow) proveFinite(n *sitter.Node) *pythonStaticValue {
	if f.route.selector == nil || f.module.unsafeWitnessBindings() {
		return nil
	}
	if !pythonFiniteExpression(f.module, n) {
		return f.proveFiniteHelper(n)
	}
	count := 0
	h := &pythonStatic{set: f.set, module: f.module, env: f.finiteEnvironment(), stack: map[string]bool{}, work: &count, proof: true}
	v := h.eval(n)
	if v == nil || (!v.known && v.fn == nil && v.module == nil) || v.tainted != nil && *v.tainted {
		return nil
	}
	return v
}
func pythonFiniteExpression(m *pythonModule, n *sitter.Node) bool {
	if n == nil {
		return false
	}
	switch n.Kind() {
	case "identifier", "string", "integer", "true", "false", "none", "string_start", "string_end", "string_content":
		return true
	case "call":
		fn := n.ChildByFieldName("function")
		if fn == nil {
			return false
		}
		if fn.Kind() == "identifier" {
			// getattrs are validated against the exact registered target later.
			imp := m.imports[pyText(m, fn)]
			if pyText(m, fn) != "getattr" && !(imp.module == "importlib" && imp.name == "import_module") {
				return false
			}
		} else if fn.Kind() == "attribute" {
			switch pyText(m, fn.ChildByFieldName("attribute")) {
			case "split", "format", "replace", "keys", "startswith", "endswith", "import_module":
			default:
				return false
			}
			if !pythonFiniteExpression(m, fn.ChildByFieldName("object")) {
				return false
			}
		} else {
			return false
		}
		args := n.ChildByFieldName("arguments")
		for i := uint(0); args != nil && i < args.NamedChildCount(); i++ {
			if !pythonFiniteExpression(m, args.NamedChild(i)) {
				return false
			}
		}
		return true
	case "subscript", "attribute", "list_comprehension", "for_in_clause", "if_clause", "comparison_operator", "boolean_operator", "not_operator", "binary_operator", "list", "tuple", "expression_list", "parenthesized_expression":
		for i := uint(0); i < n.NamedChildCount(); i++ {
			if !pythonFiniteExpression(m, n.NamedChild(i)) {
				return false
			}
		}
		return true
	}
	return false
}
func (f *pythonFlow) selectorMatches(target *pythonBoundCallable, args []pythonValue) bool {
	b := f.route.selector
	if b == nil || target.module != b.selector.module || target.fn.Id() != b.selector.fn.Id() || len(args) != len(b.arguments) {
		return false
	}
	if target.module.bindingIndex().dynamic || f.set.staticInvalid[target.module.file+":"+pyText(target.module, target.fn.ChildByFieldName("name"))] {
		return false
	}
	for i, v := range args {
		if v.finite == nil || v.finite.invocation != f.invocation.ID || !v.finite.value.known || !v.finite.value.proofString || v.finite.value.text != b.arguments[i] {
			return false
		}
		for _, d := range v.deps {
			if d.container != "environ" || d.key != "PATH_INFO" {
				return false
			}
		}
	}
	return true
}
func (f *pythonFlow) provenImportPlan(call *sitter.Node, target *pythonBoundCallable, args []pythonValue, p *pythonWitnessPlan) bool {
	if !f.selectionActive || f.route.selector == nil || p.effectful {
		return false
	}
	count := 0
	h := &pythonStatic{set: f.set, module: f.module, env: f.finiteEnvironment(), stack: map[string]bool{}, work: &count, proof: true}
	staticArgs := make([]*pythonStaticValue, len(args))
	for i, v := range args {
		if v.finite == nil || v.finite.invocation != f.invocation.ID || !v.finite.value.known || !v.finite.value.proofString {
			return false
		}
		staticArgs[i] = v.finite.value
		for _, d := range v.deps {
			if d.container != "environ" || d.key != "PATH_INFO" {
				return false
			}
		}
	}
	value := h.invoke(call, &pythonStaticValue{module: target.module, fn: target.fn}, staticArgs)
	return value != nil && value.module == f.route.selector.target.module && value.fn == nil && value.known
}
func (f *pythonFlow) finiteCall(n *sitter.Node, name, q string, values []pythonValue, all pythonValue) (pythonValue, bool) {
	if !f.selectionActive || f.route.selector == nil {
		return pythonValue{}, false
	}
	if f.module.unsafeWitnessBindings() {
		return pythonValue{}, false
	}
	if q != "importlib.import_module" && !(name == "getattr" && f.builtin("getattr")) {
		return pythonValue{}, false
	}
	if !f.set.stableWitnessReference(f.module, name) {
		return pythonValue{}, false
	}
	proof := f.proveFinite(n)
	if proof == nil {
		return pythonValue{}, false
	}
	b := f.route.selector
	if q == "importlib.import_module" {
		if proof.module != b.target.module || proof.fn != nil {
			return pythonValue{}, false
		}
	} else if proof.module != b.target.module || proof.fn == nil || proof.fn.Id() != b.target.fn.Id() {
		return pythonValue{}, false
	}
	// Keep every request-origin dependency and native call transfer. The proof
	// establishes a finite dispatch target; it does not validate any input.
	v := pyTransfer(pyProtect(all, "unknown"), f.module.evidence("call_argument_dependency", n))
	v.finite = &pythonFiniteValue{proof, f.invocation.ID}
	if proof.fn == nil {
		v.binding = "source_module"
	}
	return v, true
}

// cloneFiniteRegistry freezes registration enumeration facts before flow starts.
func cloneFiniteRegistry(v *pythonStaticValue) *pythonStaticValue {
	budget := 4096
	seen := map[*pythonStaticValue]*pythonStaticValue{}
	active := map[*pythonStaticValue]bool{}
	var clone func(*pythonStaticValue, int) *pythonStaticValue
	clone = func(v *pythonStaticValue, depth int) *pythonStaticValue {
		if v == nil || depth >= 64 || budget <= 0 || active[v] {
			return nil
		}
		if c := seen[v]; c != nil {
			return c
		}
		if len(v.items)+len(v.fields) > budget || v.closure != nil || v.class != nil || v.instance != nil || v.fn != nil || v.module != nil || v.receiver || v.kind != "" || v.routes != nil || v.route != nil {
			return nil
		}
		budget--
		active[v] = true
		defer delete(active, v)
		c := *v
		c.tainted = new(bool)
		if v.tainted != nil {
			*c.tainted = *v.tainted
		}
		c.evidence = append([]analysis.Evidence{}, v.evidence...)
		if v.keyStrings != nil {
			c.keyStrings = map[string]bool{}
			for k, kind := range v.keyStrings {
				c.keyStrings[k] = kind
			}
		}
		if v.keys != nil {
			c.keys = map[string][]analysis.Evidence{}
			for k, ev := range v.keys {
				c.keys[k] = append([]analysis.Evidence{}, ev...)
			}
		}
		if v.items != nil {
			c.items = make([]*pythonStaticValue, len(v.items))
			for i, x := range v.items {
				c.items[i] = clone(x, depth+1)
				if c.items[i] == nil {
					return nil
				}
			}
		}
		if v.fields != nil {
			c.fields = map[string]*pythonStaticValue{}
			for k, x := range v.fields {
				c.fields[k] = clone(x, depth+1)
				if c.fields[k] == nil {
					return nil
				}
			}
		}
		seen[v] = &c
		return &c
	}
	return clone(v, 0)
}

func (f *pythonFlow) proveFiniteHelper(n *sitter.Node) *pythonStaticValue {
	if n == nil || n.Kind() != "call" {
		return nil
	}
	name := pyText(f.module, n.ChildByFieldName("function"))
	root := strings.Split(name, ".")[0]
	if _, shadow := f.env[root]; shadow || !f.set.stableWitnessReference(f.module, name) {
		return nil
	}
	target, key := f.set.resolve(f.module, name, 0)
	if target == nil || target.funcs[key] == nil || f.set.staticInvalid[target.file+":"+key] {
		return nil
	}
	p := f.set.witnessPlan(target, target.funcs[key])
	if p.reason != "" || p.effectful || p.building || p.requiresSelection && !f.selectionActive {
		return nil
	}
	args := pyArgs(n)
	if len(args) != len(p.params) {
		return nil
	}
	count := 0
	h := &pythonStatic{set: f.set, module: f.module, env: f.finiteEnvironment(), stack: map[string]bool{}, work: &count, proof: true}
	values := make([]*pythonStaticValue, len(args))
	for i, arg := range args {
		if !pythonFiniteExpression(f.module, arg) {
			return nil
		}
		values[i] = h.eval(arg)
		if !values[i].known {
			return nil
		}
	}
	value := h.invoke(n, &pythonStaticValue{module: target, fn: target.funcs[key]}, values)
	if value == nil || !value.known {
		return nil
	}
	if p.requiresSelection && value.module != f.route.selector.target.module {
		return nil
	}
	return value
}

// New witness/proof resolution is deliberately stricter than the legacy call
// engine. Keep this cache separate so old discovery and container effects do
// not change when reflection or deletion appears elsewhere in a module.
func (m *pythonModule) unsafeWitnessBindings() bool {
	if m.witnessBindingsUnsafe != nil {
		return *m.witnessBindingsUnsafe
	}
	unsafe := m.bindingIndex().dynamic
	aliases := map[string]bool{}
	for name, imp := range m.imports {
		// Framework acquisition proxies are values, not imported namespaces. Their
		// native input models establish the source when a projected value is passed.
		if (imp.module == "flask" || imp.module == "quart" || imp.module == "bottle") && (imp.name == "request" || imp.name == "session") {
			continue
		}
		aliases[name] = true
	}
	for round := 0; round < 8; round++ {
		changed := false
		pyWalk(m.tree.RootNode(), func(n *sitter.Node) {
			if n.Kind() != "assignment" {
				return
			}
			left, right := n.ChildByFieldName("left"), n.ChildByFieldName("right")
			if left == nil || left.Kind() != "identifier" || right == nil || (right.Kind() != "identifier" && right.Kind() != "attribute") {
				return
			}
			root := strings.Split(pyText(m, right), ".")[0]
			name := pyText(m, left)
			if aliases[root] && !aliases[name] {
				aliases[name] = true
				changed = true
			}
		})
		if !changed {
			break
		}
		if round == 7 {
			unsafe = true
		}
	}

	pyWalk(m.tree.RootNode(), func(n *sitter.Node) {
		if n.Kind() == "delete_statement" {
			unsafe = true
		}
		if n.Kind() == "call" {
			for _, arg := range pyArgs(n) {
				pyWalk(arg, func(part *sitter.Node) {
					if part.Kind() == "identifier" && aliases[pyText(m, part)] {
						current := part
						for parent := current.Parent(); parent != nil && (parent.Kind() == "attribute" || parent.Kind() == "call"); parent = current.Parent() {
							if parent.Kind() == "call" {
								if fn := parent.ChildByFieldName("function"); fn != nil && fn.Id() == current.Id() {
									return
								}
								break
							}
							current = parent
						}
						unsafe = true
					}
				})
			}
			name := pyText(m, n.ChildByFieldName("function"))
			if name == "setattr" || name == "delattr" || strings.HasSuffix(name, ".setattr") || strings.HasSuffix(name, ".delattr") {
				unsafe = true
			}
			if imp := m.imports[name]; imp.module == "builtins" && (imp.name == "setattr" || imp.name == "delattr") {
				unsafe = true
			}
		}
	})
	m.witnessBindingsUnsafe = &unsafe
	return unsafe
}
func (s *pythonSet) stableWitnessReference(m *pythonModule, name string) bool {
	root := strings.Split(name, ".")[0]
	if m.unsafeWitnessBindings() || s.staticInvalid[m.file+":"+root] {
		return false
	}
	target, key := s.resolve(m, name, 0)
	return target == nil || !target.unsafeWitnessBindings() && !s.staticInvalid[target.file+":"+key] && !s.staticInvalid[target.file+":"+strings.Split(key, ".")[0]]
}

func joinPythonFinite(a, b *pythonFiniteValue) *pythonFiniteValue {
	if a == nil || b == nil || a.invocation != b.invocation {
		return nil
	}
	if a.value == b.value {
		return a
	}
	av, bv := a.value, b.value
	if av == nil || bv == nil {
		return nil
	}
	if av.known && bv.known && av.proofString && bv.proofString && av.text == bv.text && av.module == nil && bv.module == nil && av.fn == nil && bv.fn == nil && av.fields == nil && bv.fields == nil && av.items == nil && bv.items == nil {
		return a
	}
	return nil
}
