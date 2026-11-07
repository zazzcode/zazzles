package parse

import (
	"regexp"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
)

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
			return &pythonStaticValue{known: true, route: &staticRoute{m, n, args[1], args[0].text, []string{verb}, "aiohttp", ""}}, true
		}
		return staticUnknown(), true
	case "django.urls.re_path", "django.conf.urls.url", "django.urls.path":
		if len(args) >= 2 && args[0].known && args[1].fn != nil && args[1].module == m {
			path, ok := djangoPath(args[0].text)
			if ok {
				return &pythonStaticValue{known: true, route: &staticRoute{m, n, args[1], path, []string{"GET", "POST"}, "django", ""}}, true
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
			f.registerAdapter(&staticRoute{m, n, view, args[0].text, verbs, "bottle", ""})
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
				f.registerAdapter(&staticRoute{m, n, args[0], pattern, []string{"GET", "POST"}, "pyramid", ""})
			}
		}
		return staticUnknown(), true
	}
	return nil, false
}

// registerAdapter expands one route definition into an entry registration.
func (f *pythonStatic) registerAdapter(r *staticRoute) {
	if r.fn == nil || r.fn.fn == nil || r.fn.module != r.module || f.depth == 0 && r.kind != "aiohttp" && r.kind != "django" {
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
			if v.known && v.fn == nil && v.module == nil && v.fields == nil && v.items == nil {
				route.closures[k] = v
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
		if m == nil || m.tree.RootNode().HasError() {
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
