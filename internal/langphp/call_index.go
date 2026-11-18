package langphp

import (
	"path"
	"sort"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/parse"
)

type phpCallResolution struct {
	Kind, Reason string
	Target       *phpBoundCallable
	Inputs       []analysis.Span
}
type phpClassTarget struct {
	module *phpModule
	node   *sitter.Node
}

// resolveReference is the neutral config-to-callable boundary. Flow's legacy
// resolver remains authoritative wherever it already resolves a function.
func (s *phpSet) resolveReference(m *phpModule, ref string) phpCallResolution {
	if s.resolutions == nil {
		s.resolutions = map[string]phpCallResolution{}
	}
	key := m.file + ":" + ref
	if r, ok := s.resolutions[key]; ok {
		return r
	}
	r := s.computeReference(m, ref)
	s.resolutions[key] = r
	return r
}
func (s *phpSet) computeReference(m *phpModule, ref string) phpCallResolution {
	if r := s.legacyResolution(m, ref); r.Target != nil {
		return r
	}
	p := s.projectInputs()
	fail := func(reason string) phpCallResolution { return phpCallResolution{Kind: "unresolved", Reason: reason} }
	if p.invalid != "" {
		return fail(p.invalid)
	}
	parts := strings.Split(ref, "::")
	if len(parts) > 2 || parts[0] == "" {
		return fail("dynamic_reference")
	}
	class, method := strings.TrimPrefix(parts[0], "\\"), "__invoke"
	if len(parts) == 2 {
		method = parts[1]
	}
	if method == "" || strings.ContainsAny(class+method, "$()@") {
		return fail("dynamic_reference")
	}
	var inputs []analysis.Span
	kind := "psr4"
	seen := map[string]bool{}
	for {
		service, ok := p.services[class]
		if !ok {
			break
		}
		if seen[class] {
			return fail("service_cycle")
		}
		seen[class] = true
		inputs = append(inputs, service.at)
		kind = "container_service"
		if service.alias != "" {
			class = service.alias
			continue
		}
		class = service.class
		break
	}
	targets := s.psr4Class(class)
	if len(targets) != 1 {
		if len(targets) > 1 {
			return fail("ambiguous_class")
		}
		return fail("missing_class")
	}
	target := targets[0]
	for i := uint(0); i < target.node.NamedChildCount(); i++ {
		if target.node.NamedChild(i).Kind() == "abstract_modifier" {
			return fail("abstract_class")
		}
	}
	for _, r := range p.resources {
		if strings.HasPrefix(class, r.prefix) && strings.HasPrefix(target.module.file, path.Clean(r.dir)+"/") {
			inputs = append(inputs, r.at)
			kind = "container_service"
		}
	}
	inputs = append(inputs, p.composerSpan)
	var methods []*sitter.Node
	body := phpField(target.node, "body")
	for i := uint(0); body != nil && i < body.NamedChildCount(); i++ {
		n := body.NamedChild(i)
		if n.Kind() == "method_declaration" && strings.EqualFold(phpText(target.module, phpField(n, "name")), method) {
			methods = append(methods, n)
		}
	}
	if len(methods) == 1 {
		n := methods[0]
		if phpField(n, "body") == nil {
			return fail("abstract_method")
		}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			child := n.NamedChild(i)
			if child.Kind() == "visibility_modifier" && phpText(target.module, child) != "public" {
				return fail("nonpublic_method")
			}
		}
	}
	if len(methods) != 1 {
		return fail("missing_method")
	}
	inputs = append(inputs, parse.Span(target.module.file, methods[0]))
	return phpCallResolution{Kind: kind, Target: &phpBoundCallable{module: target.module, fn: methods[0]}, Inputs: inputs}
}
func (s *phpSet) psr4Class(class string) []phpClassTarget {
	p := s.projectInputs()
	var prefixes []string
	for prefix := range p.psr4 {
		if strings.HasPrefix(class, prefix) {
			prefixes = append(prefixes, prefix)
		}
	}
	sort.Slice(prefixes, func(i, j int) bool {
		if len(prefixes[i]) != len(prefixes[j]) {
			return len(prefixes[i]) > len(prefixes[j])
		}
		return prefixes[i] < prefixes[j]
	})
	if len(prefixes) == 0 {
		return nil
	}
	prefix := prefixes[0]
	tail := strings.ReplaceAll(strings.TrimPrefix(class, prefix), "\\", "/") + ".php"
	if !safePHPPath(tail) {
		return nil
	}
	var found []phpClassTarget
	seen := map[string]bool{}
	for _, dir := range p.psr4[prefix] {
		file := path.Join(dir, tail)
		if seen[file] {
			continue
		}
		seen[file] = true
		m := s.modules[file]
		if m == nil || m.tree.RootNode().HasError() {
			continue
		}
		var visit func(*sitter.Node, string)
		visit = func(parent *sitter.Node, ns string) {
			for i := uint(0); i < parent.NamedChildCount(); i++ {
				n := parent.NamedChild(i)
				if n.Kind() == "namespace_definition" {
					name := strings.Trim(phpText(m, phpField(n, "name")), "\\")
					if body := phpField(n, "body"); body != nil {
						visit(body, name)
					} else {
						ns = name
					}
				} else if n.Kind() == "class_declaration" {
					name := phpText(m, phpField(n, "name"))
					if ns != "" {
						name = ns + "\\" + name
					}
					if name == class {
						found = append(found, phpClassTarget{m, n})
					}
				}
			}
		}
		visit(m.tree.RootNode(), "")
	}
	return found
}

func (s *phpSet) legacyResolution(m *phpModule, ref string) phpCallResolution {
	if !strings.Contains(ref, "::") {
		if target := s.resolveFunction(m, ref); target != nil {
			kind := "direct"
			if target.module != m {
				kind = "imported"
			}
			return phpCallResolution{Kind: kind, Target: target}
		}
	}
	return phpCallResolution{Kind: "unresolved", Reason: "unknown_function"}
}
