package parse

import (
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
)

// moduleDirective returns the leading directive of a module ("use client" or
// "use server"). A directive that is not the first statement has no effect in
// Next.js and is ignored.
func moduleDirective(m *sourceModule) string {
	root := m.tree.RootNode()
	for i := uint(0); i < root.NamedChildCount(); i++ {
		n := root.NamedChild(i)
		if n.Kind() == "comment" {
			continue
		}
		if n.Kind() == "expression_statement" && n.NamedChildCount() == 1 {
			if text, ok := stringLiteral(n.NamedChild(0), m.src); ok {
				return text
			}
		}
		return ""
	}
	return ""
}

// functionDirective returns the directive that begins a function body.
func functionDirective(fn *sitter.Node, src []byte) string {
	body := fn.ChildByFieldName("body")
	if body == nil || body.Kind() != "statement_block" {
		return ""
	}
	for i := uint(0); i < body.NamedChildCount(); i++ {
		n := body.NamedChild(i)
		if n.Kind() == "comment" {
			continue
		}
		if n.Kind() == "expression_statement" && n.NamedChildCount() == 1 {
			if text, ok := stringLiteral(n.NamedChild(0), src); ok {
				return text
			}
		}
		return ""
	}
	return ""
}

// reactClientModule reports a React client module: a `"use client"` module, or
// one that imports React or a Next.js client API. React 17+ JSX needs no React
// import, so the directive alone is enough.
func reactClientModule(m *sourceModule) bool {
	if moduleDirective(m) == "use client" {
		return true
	}
	for _, imp := range m.imports {
		if imp.module == "react" || imp.module == "next/navigation" || imp.module == "client-only" {
			return true
		}
	}
	return false
}

// reactImport reports a call to a named React hook, imported or as React.x.
func reactHook(m *sourceModule, fn *sitter.Node, names ...string) string {
	if fn == nil {
		return ""
	}
	name := ""
	switch fn.Kind() {
	case "identifier":
		imp, ok := m.imports[fn.Utf8Text(m.src)]
		if !ok || imp.module != "react" {
			return ""
		}
		name = imp.name
	case "member_expression":
		obj, prop := fn.ChildByFieldName("object"), fn.ChildByFieldName("property")
		if obj == nil || prop == nil {
			return ""
		}
		imp, ok := m.imports[obj.Utf8Text(m.src)]
		if !ok || imp.module != "react" {
			return ""
		}
		name = prop.Utf8Text(m.src)
	default:
		return ""
	}
	for _, n := range names {
		if n == name {
			return name
		}
	}
	return ""
}

func nextNavigation(m *sourceModule, fn *sitter.Node) string {
	if fn == nil || fn.Kind() != "identifier" {
		return ""
	}
	imp, ok := m.imports[fn.Utf8Text(m.src)]
	if !ok || imp.module != "next/navigation" {
		return ""
	}
	return imp.name
}

// reactState binds `const [s, setS] = useState(init)` (or useReducer). The
// state reads the flow-insensitive join of its initial value and every value a
// setter receives anywhere in the component; the first component pass collects
// those joins and the second reads them.
func (f *flow) reactState(d, pattern *sitter.Node) bool {
	if f.client == nil || !f.client.react || pattern.Kind() != "array_pattern" {
		return false
	}
	init := unwrapTS(d.ChildByFieldName("value"))
	if init == nil || init.Kind() != "call_expression" {
		return false
	}
	hook := reactHook(f.module, init.ChildByFieldName("function"), "useState", "useReducer", "useActionState", "useOptimistic", "useTransition")
	if hook == "" {
		return false
	}
	src := f.module.src
	var names []string
	for i := uint(0); i < pattern.NamedChildCount(); i++ {
		c := pattern.NamedChild(i)
		if c.Kind() == "identifier" {
			names = append(names, c.Utf8Text(src))
		} else {
			names = append(names, "")
		}
	}
	args := init.ChildByFieldName("arguments")
	initial := value{}
	if hook == "useState" && args != nil && args.NamedChildCount() > 0 {
		a := args.NamedChild(0)
		if isFunction(a) {
			initial = f.reactCallback(a, nil)
		} else {
			initial = f.eval(a)
		}
	}
	if hook == "useReducer" && args != nil && args.NamedChildCount() > 1 {
		initial = f.eval(args.NamedChild(1))
	}
	if f.client.state == nil {
		f.client.state, f.client.setters = map[string]value{}, map[string]string{}
	}
	if len(names) > 0 && names[0] != "" {
		state := names[0]
		v := combine(initial, f.client.state[state])
		f.env[state] = f.transfer(v, "react_state", d)
		if len(names) > 1 && names[1] != "" && hook != "useTransition" {
			f.client.setters[names[1]] = state
			f.env[names[1]] = value{}
		}
		if hook == "useReducer" || hook == "useActionState" {
			// Reducer and action results are not traversed: the state stays unresolved.
			f.env[state] = value{deps: v.deps, gaps: append(v.gaps, f.gap("react_shared_state_unresolved", hook+" state transitions are not modeled", init))}
		}
	}
	return true
}

// reactSetter joins a setter argument into its state.
func (f *flow) reactSetter(n, fn, args *sitter.Node) (value, bool) {
	if f.client == nil || !f.client.react || fn.Kind() != "identifier" || f.client.setters == nil {
		return value{}, false
	}
	state, ok := f.client.setters[fn.Utf8Text(f.module.src)]
	if !ok || args == nil || args.NamedChildCount() == 0 {
		return value{}, ok
	}
	a := args.NamedChild(0)
	var v value
	if isFunction(a) {
		prior := f.env[state]
		v = f.reactCallback(a, &prior)
	} else {
		v = f.eval(a)
	}
	f.client.state[state] = combine(f.client.state[state], f.transfer(v, "react_state_update", n))
	return value{}, true
}

// reactCallback analyzes a nested client function (effect, callback, event
// handler, promise continuation) with the component's current bindings. It
// returns the function's returned values.
func (f *flow) reactCallback(fn *sitter.Node, param0 *value) value {
	if f.depth >= 5 {
		f.gaps = append(f.gaps, f.gap("unsupported_callback", "client callback depth limit reached", fn))
		return value{}
	}
	child := *f
	child.env, child.uses, child.returns = copyValues(f.env), nil, nil
	child.depth++
	if params, ok := functionParameters(fn, f.module.src); ok {
		for i, p := range params {
			child.env[p.name] = value{}
			if i == 0 && param0 != nil {
				child.env[p.name] = child.transfer(*param0, "parameter_binding", p.node)
			}
		}
	}
	child.statements(fn.ChildByFieldName("body"))
	f.uses = append(f.uses, child.uses...)
	out := value{}
	for _, r := range child.returns {
		out = combine(out, r)
	}
	return out
}

// reactCall models React and Next.js client APIs: hooks that produce browser
// sources or DOM refs, router navigation, collection callbacks and verified
// client HTTP helpers. ok=false leaves the call to the shared client model.
func (f *flow) reactCall(n, fn, args *sitter.Node) (value, bool) {
	if f.client == nil || !f.client.react || args == nil {
		return value{}, false
	}
	src := f.module.src
	if fn.Kind() == "identifier" {
		if imp, ok := f.module.imports[fn.Utf8Text(src)]; ok && imp.module == "react-redux" && (imp.name == "useSelector" || imp.name == "useStore") {
			v := f.browserSource(n)
			v.gaps = append(v.gaps, f.gap("react_shared_state_unresolved", "Redux state source; reducer transitions are unresolved", n))
			if args.NamedChildCount() > 0 && isFunction(args.NamedChild(0)) {
				return f.reactCallback(args.NamedChild(0), &v), true
			}
			return v, true
		}
	}
	if f.set.zustandHook(f.module, fn) {
		v := f.browserSource(n)
		v.gaps = append(v.gaps, f.gap("react_shared_state_unresolved", "Zustand state source; updater transitions are unresolved", n))
		if args.NamedChildCount() > 0 && isFunction(args.NamedChild(0)) {
			return f.reactCallback(args.NamedChild(0), &v), true
		}
		return v, true
	}
	if v, ok := f.reactSetter(n, fn, args); ok {
		return v, true
	}
	if fn.Kind() == "identifier" && fn.Utf8Text(src) == "fetch" && browserGlobal(f.module, n, "fetch") && args.NamedChildCount() > 0 && f.set.next != nil && f.set.nextProjectFor(f.module.file) != nil {
		f.set.next.clientRequests = append(f.set.next.clientRequests, clientRequest{module: f.module, call: n, url: args.NamedChild(0), method: f.browserFetchMethod(args), entry: f.entry})
	}
	if fn.Kind() == "identifier" && !shadowed(n, fn.Utf8Text(src), src) {
		switch nextNavigation(f.module, fn) {
		case "useSearchParams":
			v := f.browserSource(n)
			v.urlParams = true
			return v, true
		case "useParams", "usePathname":
			return f.browserSource(n), true
		case "useRouter":
			return value{web: "nextRouter"}, true
		}
		switch reactHook(f.module, fn, "useRef", "useEffect", "useLayoutEffect", "useCallback", "useMemo", "useInsertionEffect") {
		case "useRef":
			if strings.Contains(n.Utf8Text(src), "Element") {
				return value{domNode: true}, true
			}
			return value{}, true
		case "useEffect", "useLayoutEffect", "useInsertionEffect":
			if args.NamedChildCount() > 0 && isFunction(args.NamedChild(0)) {
				f.reactCallback(args.NamedChild(0), nil)
			}
			return value{}, true
		case "useCallback":
			if args.NamedChildCount() > 0 && isFunction(args.NamedChild(0)) {
				f.reactCallback(args.NamedChild(0), nil)
			}
			return value{}, true
		case "useMemo":
			if args.NamedChildCount() > 0 && isFunction(args.NamedChild(0)) {
				return f.reactCallback(args.NamedChild(0), nil), true
			}
			return value{}, true
		}
		if strings.HasPrefix(fn.Utf8Text(src), "use") {
			if imp, ok := f.module.imports[fn.Utf8Text(src)]; ok && imp.module == "react" && (imp.name == "useContext" || imp.name == "useSyncExternalStore") {
				v := f.browserSource(n)
				v.gaps = append(v.gaps, f.gap("react_shared_state_unresolved", "React context/external store state is a browser state source; provider transitions are unresolved", n))
				return v, true
			}
		}
		return value{}, false
	}
	if fn.Kind() != "member_expression" {
		return value{}, false
	}
	obj, prop := fn.ChildByFieldName("object"), fn.ChildByFieldName("property")
	if obj == nil || prop == nil {
		return value{}, false
	}
	method := prop.Utf8Text(src)
	switch method {
	case "forEach", "map", "filter", "find", "some", "every", "flatMap":
		if args.NamedChildCount() > 0 && isFunction(args.NamedChild(0)) {
			receiver := f.eval(obj)
			r := f.reactCallback(args.NamedChild(0), &receiver)
			if method == "map" || method == "flatMap" {
				return f.transfer(r, "collection_map", n), true
			}
			if method == "filter" || method == "find" {
				return f.transfer(receiver, "collection_filter", n), true
			}
			return value{}, true
		}
	case "push", "replace", "prefetch":
		if obj.Kind() == "identifier" {
			if r, ok := f.env[obj.Utf8Text(src)]; ok && r.web == "nextRouter" && args.NamedChildCount() > 0 {
				v := f.eval(args.NamedChild(0))
				if method != "prefetch" && !fixedURLPrefix(f, args.NamedChild(0)) {
					v.gaps = append(v.gaps, f.gap("next_router_javascript_url_policy", "whether the Next.js client router refuses javascript: URLs depends on the installed version", n))
					f.clientRecord(n, v, "url", false, f.module.evidence("render_binding", fn))
				}
				return value{}, true
			}
		}
	}
	if obj.Kind() == "identifier" {
		if httpMethod, ok := f.set.clientAPIHelper(f.module, obj.Utf8Text(src), method); ok && !shadowed(n, obj.Utf8Text(src), src) && args.NamedChildCount() > 0 {
			for i := uint(1); i < args.NamedChildCount(); i++ {
				f.eval(args.NamedChild(i))
			}
			v := f.clientHTTPValue(f.module, n, args.NamedChild(0), httpMethod, nil)
			if f.set.next != nil {
				f.set.recordClientRequest(f, n, args.NamedChild(0), httpMethod)
			}
			return v, true
		}
	}
	return value{}, false
}

// clientAPIHelper verifies `export const api = { get: (endpoint, ...) =>
// request(endpoint, { ...options, method: "GET" }), ... }` where request is a
// local function that calls fetch with a URL built from its first parameter and
// returns parsed response data. It returns the fixed HTTP method of the member.
func (s *moduleSet) clientAPIHelper(m *sourceModule, name, member string) (string, bool) {
	imp, ok := m.imports[name]
	if !ok || imp.name == "*" || imp.name == "default" {
		return "", false
	}
	target, local, _ := s.namedExport(m, imp.module, imp.name, 0)
	if target == nil {
		return "", false
	}
	obj := unwrapTS(topVariable(target, local))
	if obj == nil || obj.Kind() != "object" {
		return "", false
	}
	fn := unwrapTS(property(obj, member, target.src))
	if fn == nil || !isFunction(fn) {
		return "", false
	}
	params, ok := functionParameters(fn, target.src)
	if !ok || len(params) == 0 {
		return "", false
	}
	body := unwrapTS(fn.ChildByFieldName("body"))
	if body == nil || body.Kind() != "call_expression" {
		return "", false
	}
	callee, args := body.ChildByFieldName("function"), body.ChildByFieldName("arguments")
	if callee == nil || callee.Kind() != "identifier" || args == nil || args.NamedChildCount() < 2 || args.NamedChild(0).Utf8Text(target.src) != params[0].name {
		return "", false
	}
	opts := args.NamedChild(1)
	if opts.Kind() != "object" {
		return "", false
	}
	method, ok := stringLiteral(property(opts, "method", target.src), target.src)
	if !ok {
		return "", false
	}
	// The method property must follow every spread, so no option overrides it.
	methodAt, lastSpread := -1, -1
	for i := uint(0); i < opts.NamedChildCount(); i++ {
		c := opts.NamedChild(i)
		if c.Kind() == "spread_element" {
			lastSpread = int(i)
		}
		if k := c.ChildByFieldName("key"); k != nil && k.Utf8Text(target.src) == "method" {
			methodAt = int(i)
		}
	}
	if methodAt < lastSpread {
		return "", false
	}
	request := target.funcs[callee.Utf8Text(target.src)]
	if request == nil {
		return "", false
	}
	rp, ok := functionParameters(request, target.src)
	if !ok || len(rp) == 0 {
		return "", false
	}
	text := request.ChildByFieldName("body").Utf8Text(target.src)
	if !strings.Contains(text, "fetch(") || !strings.Contains(text, ".json()") || !strings.Contains(text, rp[0].name) {
		return "", false
	}
	return strings.ToUpper(method), true
}

// recordClientRequest keeps a same-origin client request for the client-side
// request observations (next_practice.go).
func (s *moduleSet) recordClientRequest(f *flow, call, url *sitter.Node, method string) {
	s.next.clientRequests = append(s.next.clientRequests, clientRequest{module: f.module, call: call, url: url, method: method, entry: f.entry})
}

type clientRequest struct {
	module *sourceModule
	call   *sitter.Node
	url    *sitter.Node
	method string
	value  value
	entry  analysis.EntryPoint
}
