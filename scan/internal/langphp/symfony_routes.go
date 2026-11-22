package langphp

import (
	"cmp"
	"maps"
	"path"
	"slices"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/parse"
	"gopkg.in/yaml.v3"
)

type symfonyRoute struct {
	methods    []string
	path, name string
	class      string
	method     string
	origin     analysis.Evidence
	mechanism  string
	target     *phpClassDecl
	action     *sitter.Node
	gaps       []analysis.Gap
	unresolved bool
}

type symfonyRouteImport struct {
	resource, namespace, kind, prefix, namePrefix string
}

func (p *symfonyProject) routes(s *phpSet) []symfonyRoute {
	var routes []symfonyRoute
	var imports []symfonyRouteImport
	var routingRead bool
	index := s.classIndex()
	for _, file := range slices.Sorted(maps.Keys(p.configs)) {
		if file != path.Join(p.root, "config/routes.yaml") && path.Dir(file) != path.Join(p.root, "config/routes") {
			continue
		}
		routingRead = true
		config := p.configs[file]
		if config.value.Kind != yaml.MappingNode {
			continue
		}
		for i := 0; i+1 < len(config.value.Content); i += 2 {
			key, node := config.value.Content[i], config.value.Content[i+1]
			if imp := symfonyYAMLValue(node, "resource"); imp != nil {
				resource := symfonyYAMLString(imp)
				if imp.Kind == yaml.MappingNode {
					resource = symfonyYAMLString(symfonyYAMLValue(imp, "path"))
				}
				if resource == "" || strings.HasPrefix(resource, "@") || path.IsAbs(resource) {
					continue
				}
				resolved := path.Join(path.Dir(file), resource)
				if !safePHPPath(resolved) || p.root != "." && !strings.HasPrefix(resolved, p.root+"/") {
					continue
				}
				imports = append(imports, symfonyRouteImport{resource: resolved,
					namespace:  symfonyYAMLString(symfonyYAMLValue(imp, "namespace")),
					kind:       symfonyYAMLString(symfonyYAMLValue(node, "type")),
					prefix:     symfonyYAMLString(symfonyYAMLValue(node, "prefix")),
					namePrefix: symfonyYAMLString(symfonyYAMLValue(node, "name_prefix"))})
				continue
			}
			pathNode := symfonyYAMLValue(node, "path")
			controller := symfonyYAMLValue(node, "controller")
			if pathNode == nil || controller == nil {
				continue
			}
			r := symfonyRoute{path: symfonyYAMLString(pathNode), name: key.Value, mechanism: "config_route", origin: symfonyYAMLOrigin(config.source, key)}
			r.methods, r.unresolved = symfonyYAMLMethods(symfonyYAMLValue(node, "methods"))
			if pathNode.Kind != yaml.ScalarNode || pathNode.ShortTag() != "!!str" || r.unresolved {
				r.path = ""
				r.addGap("symfony_route_dynamic", "Route path or methods are not literal", true)
			}
			ref := strings.TrimPrefix(symfonyYAMLString(controller), `\`)
			r.class, r.method, _ = strings.Cut(ref, "::")
			if r.method == "" {
				r.method = "__invoke"
			}
			r.target, r.action = p.routeController(index, r.class, r.method)
			if r.action == nil {
				r.addGap("symfony_controller_unresolved", "Controller does not resolve to a public project method", true)
			}
			routes = append(routes, r)
		}
	}
	for _, file := range s.files {
		m := s.modules[file]
		if m == nil || s.symfonyProjectOf(file) != p || m.tree.RootNode().HasError() {
			continue
		}
		phpWalk(m.tree.RootNode(), func(n *sitter.Node) {
			if n.Kind() != "class_declaration" {
				return
			}
			class := index.qualify(m, phpText(m, phpField(n, "name")), n.StartByte())
			decls := index.byName[strings.ToLower(class)]
			for _, decl := range decls {
				if decl.module == m && decl.node.StartByte() == n.StartByte() {
					routes = append(routes, symfonyClassRoutes(index, decl, imports, routingRead)...)
					break
				}
			}
		})
	}
	slices.SortStableFunc(routes, func(a, b symfonyRoute) int {
		if order := cmp.Compare(a.sourceFile(), b.sourceFile()); order != 0 {
			return order
		}
		if a.action != nil && b.action != nil {
			if order := cmp.Compare(a.action.StartByte(), b.action.StartByte()); order != 0 {
				return order
			}
		}
		if order := cmp.Compare(a.origin.Span.File, b.origin.Span.File); order != 0 {
			return order
		}
		return cmp.Compare(a.origin.Span.StartByte, b.origin.Span.StartByte)
	})
	return routes
}

func (p *symfonyProject) routeController(index *phpClassIndex, class, method string) (*phpClassDecl, *sitter.Node) {
	var prefixes []string
	for prefix := range p.psr4 {
		if strings.HasPrefix(class, prefix) {
			prefixes = append(prefixes, prefix)
		}
	}
	slices.SortFunc(prefixes, func(a, b string) int { return cmp.Compare(len(b), len(a)) })
	decls := index.byName[strings.ToLower(class)]
	if len(prefixes) == 0 {
		return nil, nil
	}
	tail := strings.ReplaceAll(strings.TrimPrefix(class, prefixes[0]), `\`, "/") + ".php"
	var target *phpClassDecl
	var action *sitter.Node
	for _, dir := range p.psr4[prefixes[0]] {
		for _, decl := range decls {
			if decl.module.file != path.Join(dir, tail) || decl.kind != "class" || firstChildOfKind(decl.node, "abstract_modifier") != nil {
				continue
			}
			fn := phpOwnMethod(decl, method)
			if !symfonyPublicMethod(decl.module, fn) {
				continue
			}
			if target != nil && target != decl {
				return nil, nil
			}
			target, action = decl, fn
		}
	}
	return target, action
}

func (r *symfonyRoute) addGap(kind, detail string, unresolved bool) {
	r.gaps = append(r.gaps, analysis.Gap{Kind: kind, Detail: detail, At: r.origin.Span})
	r.unresolved = r.unresolved || unresolved
}

func (r symfonyRoute) sourceFile() string {
	if r.target != nil {
		return r.target.module.file
	}
	return r.origin.Span.File
}

func (r symfonyRoute) httpMethods() []string {
	if len(r.methods) == 0 {
		return []string{""}
	}
	return r.methods
}

func (r symfonyRoute) callableName() string {
	return r.class + "::" + r.method
}

func (r symfonyRoute) register(out *analysis.AnalysisReport, method string) {
	instance := "php:" + r.sourceFile() + ":" + r.origin.SHA256
	if r.target != nil {
		instance = "php:" + r.sourceFile() + ":" + r.target.module.hash + ":" + r.callableName()
	}
	verb := method
	if verb == "" {
		verb = "ANY"
	}
	entry := analysis.EntryPoint{
		ID:   parse.SnapshotID("entry", r.origin, instance, r.mechanism+":"+r.name+":"+method+":"+r.path),
		Kind: "http", Name: strings.TrimSpace(verb + " " + r.path), InstanceID: instance, Location: r.origin,
		HTTP: &analysis.HTTPEntryMetadata{SourcePath: r.sourceFile(), Framework: "symfony", Method: method, Path: r.path},
		Gaps: r.gaps,
	}
	var handler *analysis.Evidence
	if !r.unresolved && r.action != nil {
		evidence := r.target.module.evidence("invoked_callable", r.action)
		handler = &evidence
	}
	parse.RegisterInvocation(out, entry, handler, r.mechanism, nil, r.gaps)
	if handler != nil {
		id := out.DispatchBindings[len(out.DispatchBindings)-1].CallableID
		for i := range out.Callables {
			if out.Callables[i].ID == id {
				out.Callables[i].Name = r.callableName()
				break
			}
		}
	}
}

func symfonyYAMLMethods(node *yaml.Node) ([]string, bool) {
	if node == nil {
		return nil, false
	}
	values := []*yaml.Node{node}
	if node.Kind == yaml.SequenceNode {
		values = node.Content
	}
	var methods []string
	for _, value := range values {
		if value.Kind != yaml.ScalarNode || value.ShortTag() != "!!str" {
			return nil, true
		}
		methods = append(methods, strings.ToUpper(value.Value))
	}
	slices.Sort(methods)
	return slices.Compact(methods), false
}
