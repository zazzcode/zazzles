package parse

import (
	"encoding/json"
	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
	"strconv"
	"strings"
)

// staticWorkLimit bounds one module's finite source interpretation.
const staticWorkLimit = 40000

// Static discovery interprets a finite syntax subset over selected source snapshots.
// It never loads Python modules or invokes target code in a Python runtime.
type pythonStaticValue struct {
	text     string
	known    bool
	tainted  *bool
	items    []*pythonStaticValue
	keys     map[string][]analysis.Evidence
	fields   map[string]*pythonStaticValue
	module   *pythonModule
	fn       *sitter.Node
	receiver bool
	// kind names a framework receiver created by a verified constructor.
	kind string
	// routes holds Pyramid route names bound to their patterns.
	routes map[string]string
	// route is a route definition awaiting registration by its consumer.
	route *staticRoute
	// class is a statically defined class; instance an instance of one.
	class, instance *staticClass
	closure         map[string]*pythonStaticValue
	evidence        []analysis.Evidence
}
type pythonStatic struct {
	set        *pythonSet
	module     *pythonModule
	env        map[string]*pythonStaticValue
	stack      map[string]bool
	work       *int
	depth      int
	sites      map[string]int
	routes     *[]pythonRoute
	returned   *pythonStaticValue
	pos        uint // start of the statement being interpreted
	provenance []analysis.Evidence
}

func staticText(text string) *pythonStaticValue { return &pythonStaticValue{text: text, known: true} }
func staticUnknown() *pythonStaticValue         { return &pythonStaticValue{} }
func staticEnv(in map[string]*pythonStaticValue) map[string]*pythonStaticValue {
	out := map[string]*pythonStaticValue{}
	for k, v := range in {
		out[k] = v
	}
	return out
}
func (s *pythonSet) dynamicRouteEntries() []pythonRoute {
	var out []pythonRoute
	sites := map[string]int{}
	for _, file := range s.files {
		m := s.modules[file]
		if m == nil || m.tree.RootNode().HasError() {
			continue
		}
		count := 0
		f := &pythonStatic{set: s, module: m, env: map[string]*pythonStaticValue{}, stack: map[string]bool{}, work: &count, routes: &out, sites: sites}
		f.block(m.tree.RootNode())
	}
	s.adapterEntries(&out, sites)
	s.wsgiEntries(&out, sites)
	return out
}
func (f *pythonStatic) evidence(kind string, n *sitter.Node) analysis.Evidence {
	return f.module.evidence(kind, n)
}
func (f *pythonStatic) gap(n *sitter.Node, detail string) {
	f.set.gaps = append(f.set.gaps, analysis.Gap{Kind: "python_dynamic_unresolved", Detail: detail, At: spanOf(f.module.file, n)})
}
func (f *pythonStatic) tick(n *sitter.Node) bool {
	*f.work++
	if *f.work > staticWorkLimit {
		if *f.work == staticWorkLimit+1 {
			f.gap(n, "Finite source discovery work limit ("+strconv.Itoa(staticWorkLimit)+") reached; remainder unexpanded")
		}
		return false
	}
	return true
}

func (f *pythonStatic) registration(call, handler, location *sitter.Node) {
	if f.depth == 0 {
		return
	}
	fn := call.ChildByFieldName("function")
	if fn == nil || fn.Kind() != "attribute" {
		return
	}
	receiverName := pyText(f.module, fn.ChildByFieldName("object"))
	if !f.lookup(receiverName).receiver {
		f.gap(call, "Generated registration receiver is shadowed, mutable or unbound")
		return
	}
	recv := f.set.receiver(f.module, receiverName, 0)
	if recv.kind != "flask" && recv.kind != "fastapi" && recv.kind != "quart" {
		return
	}
	method := pyText(f.module, fn.ChildByFieldName("attribute"))
	switch method {
	case "get", "post", "put", "patch", "delete", "head", "options", "route", "add_url_rule":
	default:
		return
	}
	nodes := pyArgs(call)
	var pathNode *sitter.Node
	if len(nodes) > 0 {
		pathNode = nodes[0]
	} else {
		pathNode = pyKeywordIn(f.module, call, "path")
	}
	path := f.eval(pathNode)
	if !path.known || !strings.HasPrefix(path.text, "/") {
		f.gap(call, "Generated registration path remains unresolved")
		return
	}
	verbs := []string{strings.ToUpper(method)}
	if method == "add_url_rule" || method == "route" {
		verbs = []string{"GET"}
		if methods := pyKeywordIn(f.module, call, "methods"); methods != nil {
			verbs = nil
			v := f.eval(methods)
			for _, verb := range v.items {
				if verb.known {
					verbs = append(verbs, verb.text)
				}
			}
		}
	}
	prefix, mountGap := f.set.mountPrefix(f.module, receiverName, recv)
	pathText := "/" + strings.TrimLeft(strings.TrimRight(prefix, "/")+"/"+strings.TrimLeft(path.text, "/"), "/")
	site := f.module.file + ":" + strconv.Itoa(int(call.StartByte()))
	if f.sites == nil {
		f.sites = map[string]int{}
	}
	for _, verb := range verbs {
		if f.sites[site] >= 128 {
			if f.sites[site] == 128 {
				f.gap(call, "Derived registration site limit (128) reached; remainder unexpanded")
			}
			f.sites[site]++
			return
		}
		f.sites[site]++
		if len(*f.routes) >= 3333 {
			f.gap(call, "Derived record scan limit (10000) reached")
			return
		}
		definition := handler
		if parent := handler.Parent(); parent != nil && parent.Kind() == "decorated_definition" {
			definition = parent
		}
		reg := pythonRegistration{f.module, definition, location, call, fn, recv, receiverName, pathText, mountGap}
		r := f.set.routeFromRegistration(reg, handler, verb)
		r.generated = true
		r.provenance = pythonMergeEvidence(nil, f.provenance)
		r.closures = map[string]*pythonStaticValue{}
		for k, v := range f.env {
			if v.known && v.fn == nil && v.module == nil && v.fields == nil && v.items == nil {
				r.closures[k] = v
			}
		}
		mounts := f.set.dynamicMounts(f.module, receiverName, recv)
		if len(mounts) == 0 {
			f.appendRoute(r)
		} else {
			for _, mount := range mounts {
				copy := r
				copy.gaps = nil
				copy.provenance = append(append([]analysis.Evidence{}, r.provenance...), mount.evidence)
				copy.instance = mount.owner
				copy.route.ID += ":" + mount.owner
				copy.route.PathPattern = "/" + strings.TrimLeft(strings.TrimRight(mount.prefix, "/")+"/"+strings.TrimLeft(path.text, "/"), "/")
				f.appendRoute(copy)
			}
		}
	}
}

type pythonDynamicMount struct {
	owner, prefix string
	evidence      analysis.Evidence
}

func (s *pythonSet) dynamicMounts(m *pythonModule, name string, recv pythonReceiver) []pythonDynamicMount {
	target, key := s.resolve(m, name, 0)
	if target == nil {
		return nil
	}
	var out []pythonDynamicMount
	for _, file := range s.files {
		mod := s.modules[file]
		if mod == nil {
			continue
		}
		pyWalk(mod.tree.RootNode(), func(n *sitter.Node) {
			if n.Kind() != "call" {
				return
			}
			fn := n.ChildByFieldName("function")
			if fn == nil || fn.Kind() != "attribute" {
				return
			}
			method := pyText(mod, fn.ChildByFieldName("attribute"))
			if method != "register_blueprint" && method != "include_router" {
				return
			}
			args := pyArgs(n)
			if len(args) == 0 {
				return
			}
			tm, tk := s.resolve(mod, pyText(mod, args[0]), 0)
			if tm != target || tk != key {
				return
			}
			receiverName := pyText(mod, fn.ChildByFieldName("object"))
			base := s.receiver(mod, receiverName, 0)
			if base.kind != recv.kind {
				return
			}
			prefix := recv.prefix
			if v := pyKeywordIn(mod, n, "url_prefix"); v != nil {
				var ok bool
				prefix, ok = pyLiteral(mod, v)
				if !ok {
					return
				}
			}
			if v := pyKeywordIn(mod, n, "prefix"); v != nil {
				text, ok := pyLiteral(mod, v)
				if !ok {
					return
				}
				prefix = text + prefix
			}
			out = append(out, pythonDynamicMount{owner: mod.file + ":" + mod.hash + ":" + receiverName, prefix: prefix, evidence: mod.evidence("mount_binding", n)})
		})
	}
	return out
}

// Repeated factory invocations can expose one path with different captures.
// Preserve separate registration contexts instead of colliding or sharing controls.
func (f *pythonStatic) appendRoute(r pythonRoute) {
	if len(*f.routes) >= 3333 {
		f.gap(r.decorator, "Derived record scan limit (10000) reached; remainder unexpanded")
		return
	}
	occurrence := 0
	for _, existing := range *f.routes {
		if existing.route.ID == r.route.ID && existing.instance == r.instance && existing.route.Method == r.route.Method && existing.route.PathPattern == r.route.PathPattern {
			occurrence++
		}
	}
	if occurrence > 0 {
		constants := map[string]string{}
		for k, v := range r.closures {
			constants[k] = v.text
		}
		sites := []analysis.Span{}
		for _, e := range r.provenance {
			if e.Kind == "factory_call" {
				sites = append(sites, e.Span)
			}
		}
		key, _ := json.Marshal(struct {
			Constants  map[string]string
			Sites      []analysis.Span
			Occurrence int
		}{constants, sites, len(*f.routes)})
		r.route.ID += ":" + snapshotID("registration", r.module.evidence("entry_registration", r.decorator), r.route.ID, string(key))
	}
	*f.routes = append(*f.routes, r)
}
