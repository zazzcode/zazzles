package parse

import (
	"regexp"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
)

// staticClass is a class definition with its definition-time closure.
type staticClass struct {
	module  *pythonModule
	node    *sitter.Node
	closure map[string]*pythonStaticValue
	bases   []*pythonStaticValue
}

// classMethods returns the methods visible on a class, subclasses first, and
// the merged definition-time constants (base values overridden by subclasses).
func classMethods(c *staticClass, depth int, methods map[string]*pythonStaticValue, closure map[string]*pythonStaticValue) {
	if c == nil || depth > 8 {
		return
	}
	for _, b := range c.bases {
		classMethods(b.class, depth+1, methods, closure)
	}
	for k, v := range c.closure {
		closure[k] = v
	}
	body := pyBody(c.node)
	for i := uint(0); body != nil && i < body.NamedChildCount(); i++ {
		d := body.NamedChild(i)
		if d.Kind() == "decorated_definition" {
			d = d.ChildByFieldName("definition")
		}
		if d != nil && d.Kind() == "function_definition" {
			name := pyText(c.module, d.ChildByFieldName("name"))
			methods[name] = &pythonStaticValue{module: c.module, fn: d, closure: c.closure}
		}
	}
}

// staticRoute is a bounded framework route definition built by a verified
// route constructor (aiohttp web.get, Django url/re_path). It becomes an entry
// only when a consumer (add_routes, a urlpatterns assignment) registers it.
type staticRoute struct {
	module *pythonModule
	call   *sitter.Node
	fn     *pythonStaticValue
	path   string
	verbs  []string
	kind   string
	// instance identifies the consuming application/URLconf.
	instance string
	// methods are the resource-class methods for a class-based handler.
	methods map[string]*pythonStaticValue
	closure map[string]*pythonStaticValue
}

var djangoAnchors = regexp.MustCompile(`^\^|/\?\$$|\$$`)

// djangoPath turns a simple URLconf regex into a route path; anything with
// groups or alternation is left unresolved by the caller.
func djangoPath(pattern string) (string, bool) {
	if strings.ContainsAny(pattern, "()[]|*+") {
		return "", false
	}
	p := djangoAnchors.ReplaceAllString(pattern, "")
	p = strings.ReplaceAll(p, "?", "")
	return "/" + strings.TrimLeft(p, "/"), true
}

// adapterCall models framework route constructors and receiver methods that
// are not decorator/add_url_rule registrations.
func (f *pythonStatic) adapterCall(n *sitter.Node, q string, fn *sitter.Node, args []*pythonStaticValue) (*pythonStaticValue, bool) {
	m := f.module
	switch q {
	case "aiohttp.web.get", "aiohttp.web.post":
		if len(args) >= 2 && args[0].known && args[1].fn != nil && args[1].module == m {
			verb := "GET"
			if strings.HasSuffix(q, "post") {
				verb = "POST"
			}
			return &pythonStaticValue{known: true, route: &staticRoute{m, n, args[1], args[0].text, []string{verb}, "aiohttp", "", nil, nil}}, true
		}
		return staticUnknown(), true
	case "django.urls.re_path", "django.conf.urls.url", "django.urls.path":
		if len(args) >= 2 && args[0].known && args[1].fn != nil && args[1].module == m {
			path, ok := djangoPath(args[0].text)
			if ok {
				return &pythonStaticValue{known: true, route: &staticRoute{m, n, args[1], path, []string{"GET", "POST"}, "django", "", nil, nil}}, true
			}
			f.gap(n, "Django URL pattern has groups or alternation; route left unexpanded")
		}
		return staticUnknown(), true
	}
	if fn == nil || fn.Kind() != "attribute" {
		return nil, false
	}
	method := pyText(m, fn.ChildByFieldName("attribute"))
	base := f.eval(fn.ChildByFieldName("object"))
	if !base.receiver || base.kind == "" {
		return nil, false
	}
	keyword := func(name string) *pythonStaticValue {
		if node := pyKeywordIn(m, n, name); node != nil {
			return f.eval(node)
		}
		return nil
	}
	switch base.kind + "." + method {
	case "bottle.route":
		if len(args) < 1 || !args[0].known {
			return staticUnknown(), true
		}
		view := keyword("callback")
		if view == nil && len(args) > 2 {
			view = args[2]
		}
		verbs := []string{"GET"}
		if len(args) > 1 && args[1].items != nil {
			verbs = nil
			for _, v := range args[1].items {
				if v.known {
					verbs = append(verbs, strings.ToUpper(v.text))
				}
			}
		}
		if view != nil && view.fn != nil {
			f.registerAdapter(&staticRoute{m, n, view, args[0].text, verbs, "bottle", "", nil, nil})
		}
		return staticUnknown(), true
	case "falcon.add_route":
		if len(args) >= 2 && args[0].known && args[1].instance != nil {
			methods := map[string]*pythonStaticValue{}
			closure := map[string]*pythonStaticValue{}
			classMethods(args[1].instance, 0, methods, closure)
			for _, verb := range []string{"GET", "POST", "PUT", "PATCH", "DELETE"} {
				h := methods["on_"+strings.ToLower(verb)]
				if h == nil {
					continue
				}
				f.registerAdapter(&staticRoute{m, n, h, args[0].text, []string{verb}, "falcon", "", methods, closure})
			}
		}
		return staticUnknown(), true
	case "pyramid.add_route":
		if len(args) >= 2 && args[0].known && args[1].known {
			base.routes[args[0].text] = args[1].text
		}
		return staticUnknown(), true
	case "pyramid.add_view":
		name := keyword("route_name")
		if len(args) >= 1 && args[0].fn != nil && name != nil && name.known {
			if pattern, ok := base.routes[name.text]; ok {
				f.registerAdapter(&staticRoute{m, n, args[0], pattern, []string{"GET", "POST"}, "pyramid", "", nil, nil})
			}
		}
		return staticUnknown(), true
	}
	return nil, false
}

// registerAdapter expands one route definition into an entry registration.
func (f *pythonStatic) registerAdapter(r *staticRoute) {
	if r.fn == nil || r.fn.fn == nil || r.fn.module != r.module {
		return
	}
	path := "/" + strings.TrimLeft(r.path, "/")
	fnNode := r.call.ChildByFieldName("function")
	recv := pythonReceiver{kind: r.kind, evidence: []analysis.Evidence{r.module.evidence("receiver_binding", r.call)}}
	for _, verb := range r.verbs {
		if len(*f.routes) >= 3333 {
			f.gap(r.call, "Derived record scan limit reached; remainder unexpanded")
			return
		}
		reg := pythonRegistration{r.module, r.fn.fn, r.call, r.call, fnNode, recv, "", path, ""}
		route := f.set.routeFromRegistration(reg, r.fn.fn, verb)
		route.generated = true
		route.provenance = pythonMergeEvidence(nil, f.provenance)
		route.closures = map[string]*pythonStaticValue{}
		for k, v := range r.fn.closure {
			if v.known && v.fn == nil && v.module == nil && v.fields == nil && v.items == nil && v.class == nil && v.instance == nil && len(v.evidence) > 0 {
				route.closures[k] = v
			}
		}
		route.methods = map[string]*pythonBoundCallable{}
		for name, mv := range r.methods {
			bound := &pythonBoundCallable{module: mv.module, fn: mv.fn, closure: map[string]pythonValue{}}
			for k, c := range r.closure {
				if c.known && c.fn == nil && c.module == nil && c.fields == nil && c.items == nil && c.class == nil && c.instance == nil {
					bound.closure[k] = pythonValue{literal: c.text, constant: true, evidence: c.evidence}
				}
			}
			route.methods[name] = bound
		}
		for k, c := range r.closure {
			if c.known && c.fn == nil && c.module == nil && c.fields == nil && c.items == nil && c.class == nil && c.instance == nil && len(c.evidence) > 0 {
				route.closures[k] = c
			}
		}
		route.instance = r.instance
		if route.instance == "" {
			route.instance = r.module.file + ":" + r.module.hash + ":" + r.kind
		}
		f.appendRoute(route)
	}
}

// adapterEntries registers route definitions at their consumers: Django
// urlpatterns assignments, aiohttp add_routes calls and Pyramid includes.
func (s *pythonSet) adapterEntries(out *[]pythonRoute, sites map[string]int) {
	seen := map[string]bool{}
	for _, file := range s.files {
		m := s.modules[file]
		if m == nil || m.tree.RootNode().HasError() || testHarnessFile(file) {
			continue
		}
		count := 0
		f := &pythonStatic{set: s, module: m, env: map[string]*pythonStaticValue{}, stack: map[string]bool{}, work: &count, routes: out, sites: sites}
		consume := func(v *pythonStaticValue, at *sitter.Node) {
			items, ok := staticItems(v)
			if !ok {
				return
			}
			for _, item := range items {
				if item.route == nil {
					continue
				}
				key := item.route.path + "|" + item.route.module.file + ":" + itoa(int(item.route.call.StartByte())) + ":" + m.file + ":" + itoa(int(at.StartByte()))
				if seen[key] {
					continue
				}
				seen[key] = true
				f.provenance = []analysis.Evidence{m.evidence("route_consumer", at)}
				rt := *item.route
				rt.instance = m.file + ":" + m.hash + ":" + rt.kind + ":" + itoa(int(at.StartByte()))
				f.registerAdapter(&rt)
			}
		}
		pyWalk(m.tree.RootNode(), func(n *sitter.Node) {
			switch n.Kind() {
			case "assignment":
				left := n.ChildByFieldName("left")
				if left != nil && left.Kind() == "identifier" && pyText(m, left) == "urlpatterns" && n.Parent() != nil && n.Parent().Kind() == "expression_statement" && n.Parent().Parent().Id() == m.tree.RootNode().Id() {
					consume(f.eval(n.ChildByFieldName("right")), n)
				}
			case "call":
				fn := n.ChildByFieldName("function")
				if fn == nil || fn.Kind() != "attribute" {
					return
				}
				switch pyText(m, fn.ChildByFieldName("attribute")) {
				case "add_routes":
					if args := pyArgs(n); len(args) == 1 {
						v := f.eval(args[0])
						// A package attribute may shadow its submodule: from pkg import name
						// binds the variable that pkg's __init__ re-exports, not the module.
						if v.module != nil && v.fn == nil && args[0].Kind() == "identifier" {
							if node := v.module.vars[pyText(m, args[0])]; node != nil {
								h := *f
								h.module = v.module
								h.env = map[string]*pythonStaticValue{}
								v = h.eval(node)
							}
						}
						consume(v, n)
					}
				case "include":
					s.pyramidInclude(m, n, f)
				}
			}
		})
	}
}

func itoa(i int) string {
	const digits = "0123456789"
	if i == 0 {
		return "0"
	}
	var b []byte
	for ; i > 0; i /= 10 {
		b = append([]byte{digits[i%10]}, b...)
	}
	return string(b)
}

// pyramidInclude runs `config.include("pkg.module")`: the module's includeme
// registers routes on a fresh Configurator receiver.
func (s *pythonSet) pyramidInclude(m *pythonModule, call *sitter.Node, f *pythonStatic) {
	args := pyArgs(call)
	if len(args) != 1 {
		return
	}
	module, ok := pyLiteral(m, args[0])
	if !ok {
		return
	}
	target := s.importModule(m, module)
	if target == nil || target.funcs["includeme"] == nil {
		return
	}
	// The receiver must be a verified Configurator context manager or variable.
	obj := pyText(m, call.ChildByFieldName("function").ChildByFieldName("object"))
	verified := false
	pyWalk(m.tree.RootNode(), func(n *sitter.Node) {
		if n.Kind() == "as_pattern" && pyText(m, n.ChildByFieldName("alias")) == obj {
			if c := n.NamedChild(0); c != nil && c.Kind() == "call" && s.qualified(m, pyText(m, c.ChildByFieldName("function"))) == "pyramid.config.Configurator" {
				verified = true
			}
		}
	})
	if !verified {
		return
	}
	config := &pythonStaticValue{receiver: true, kind: "pyramid", routes: map[string]string{}}
	fnValue := &pythonStaticValue{module: target, fn: target.funcs["includeme"], closure: map[string]*pythonStaticValue{}}
	h := *f
	h.module = m
	h.provenance = []analysis.Evidence{m.evidence("route_consumer", call)}
	h.invoke(call, fnValue, []*pythonStaticValue{config})
}

// wsgiEntries registers WSGI callables whose request path selects a callable
// from a finite registry. Each registry item is a separate context with that
// item's callable bound for the path-selected call; the registry, the path
// prefix literal and the selecting function come from source, never from names.
func (s *pythonSet) wsgiEntries(out *[]pythonRoute, sites map[string]int) {
	for _, file := range s.files {
		m := s.modules[file]
		if m == nil || m.tree.RootNode().HasError() || testHarnessFile(file) {
			continue
		}
		for name, fn := range m.funcs {
			params := fn.ChildByFieldName("parameters")
			if params == nil || params.NamedChildCount() != 2 {
				continue
			}
			start := pyText(m, params.NamedChild(1))
			calls := false
			pyWalk(fn.ChildByFieldName("body"), func(n *sitter.Node) {
				if n.Kind() == "call" && pyText(m, n.ChildByFieldName("function")) == start {
					calls = true
				}
			})
			if !calls {
				continue
			}
			s.wsgiRegistry(m, name, fn, out, sites)
		}
	}
}

func (s *pythonSet) wsgiRegistry(m *pythonModule, name string, fn *sitter.Node, out *[]pythonRoute, sites map[string]int) {
	count := 0
	f := &pythonStatic{set: s, module: m, env: map[string]*pythonStaticValue{}, stack: map[string]bool{}, work: &count, routes: out, sites: sites}
	registry := f.lookup("TRIGGER_MAP")
	if registry.fields == nil {
		return
	}
	// The selecting function: an imported two-parameter function that returns a
	// callable when invoked with a registry item.
	var selectors []*pythonStaticValue
	for imported := range m.imports {
		if v := f.lookup(imported); v.fn != nil && v.fn.ChildByFieldName("parameters") != nil && v.fn.ChildByFieldName("parameters").NamedChildCount() == 2 {
			selectors = append(selectors, v)
		}
	}
	// A literal first-segment comparison such as parts[0] != "app" is the path prefix.
	prefix := ""
	pyWalk(fn.Parent(), func(n *sitter.Node) {
		if prefix != "" || n.Kind() != "comparison_operator" || n.NamedChildCount() != 2 {
			return
		}
		a, b := n.NamedChild(0), n.NamedChild(1)
		if a.Kind() == "subscript" && pyText(m, a.ChildByFieldName("subscript")) == "0" {
			if lit, ok := pyLiteral(m, b); ok {
				prefix = lit
			}
		}
	})
	keys, _ := staticItems(registry)
	registration := m.evidence("entry_registration", fn)
	for _, k := range keys {
		triggers, ok := staticItems(registry.fields[k.text])
		if !ok {
			continue
		}
		for _, t := range triggers {
			var bound *pythonBoundCallable
			for _, sel := range selectors {
				h := *f
				h.module = sel.module
				if v := h.invoke(fn, sel, []*pythonStaticValue{staticText(k.text), staticText(t.text)}); v.fn != nil && v.module != nil {
					bound = &pythonBoundCallable{module: v.module, fn: v.fn, evidence: []analysis.Evidence{sel.module.evidence("registry_selector", sel.fn), m.evidence("registry_item", fn)}}
					break
				}
			}
			if bound == nil {
				continue
			}
			path := "/" + strings.Trim(prefix+"/"+k.text+"/"+t.text, "/")
			recv := pythonReceiver{kind: "wsgi", evidence: []analysis.Evidence{m.evidence("receiver_binding", fn)}}
			reg := pythonRegistration{m, fn, fn, fn, fn.ChildByFieldName("name"), recv, "", path, ""}
			route := s.routeFromRegistration(reg, fn, "GET")
			route.generated = true
			route.dispatch = bound
			route.provenance = append([]analysis.Evidence{registration}, k.evidence...)
			route.instance = m.file + ":" + m.hash + ":wsgi"
			route.route.ID += ":" + k.text + ":" + t.text
			if len(*out) < 3333 {
				*out = append(*out, route)
			}
		}
	}
}

// testHarnessFile reports a test module: its application constructions are
// test fixtures, not application registrations of the scanned target.
func testHarnessFile(path string) bool {
	for _, segment := range strings.Split(path, "/") {
		if segment == "tests" || segment == "test" || segment == "__tests__" || strings.HasPrefix(segment, "test_") || strings.HasSuffix(segment, "_test.py") {
			return true
		}
	}
	return false
}
