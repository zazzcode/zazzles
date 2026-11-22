package langphp

import (
	"maps"
	"slices"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

func (s *phpSet) analyzeSymfonyEntry(out *analysis.AnalysisReport, p *symfonyProject, r symfonyRoute, method string) {
	r.register(out, method)
	if r.unresolved || r.action == nil {
		return
	}
	entryIndex, invocationIndex := len(out.Entries)-1, len(out.InvocationContexts)-1
	entry, invocation := out.Entries[entryIndex], out.InvocationContexts[invocationIndex]
	access := p.accessFor(s, r, method)
	if r.target != nil {
		access = (&phpFlow{set: s, module: r.target.module, symfony: p}).applyAccessAttributes(access, r.target, r.action)
	}
	out.Entries[entryIndex].Access = &access
	entry.Access = &access
	m := r.target.module
	handler := m.evidence("invoked_callable", r.action)
	work := 0
	f := &phpFlow{
		set: s, module: m, entry: entry, invocation: invocation, report: out,
		env: map[string]phpValue{}, globals: map[string]phpValue{},
		context: []analysis.Evidence{handler, entry.Location}, work: &work, stack: map[string]bool{},
		constants: map[string]string{}, entryModule: m, entryModuleRoot: r.action,
		class: r.target, symfony: p, services: map[string]phpValue{},
	}
	f.env["this"] = f.symfonyServiceObject(r.target, r.action)
	params := phpField(r.action, "parameters")
	for i := uint(0); params != nil && i < params.NamedChildCount(); i++ {
		param := params.NamedChild(i)
		name := phpVarName(m, phpField(param, "name"))
		if name == "" {
			continue
		}
		v := f.symfonyParameter(r.path, param, true)
		f.env[name] = v
		if len(v.deps) == 1 && v.deps[0].dep.Source.Kind == "input_source" {
			dep := v.deps[0]
			f.invocation.Inputs = append(f.invocation.Inputs, analysis.InputBinding{
				Parameter: name, Role: dep.container,
				Origin: analysis.InputOrigin{Kind: "external", Evidence: []analysis.Evidence{dep.dep.Source}},
			})
		}
	}
	f.block(phpField(r.action, "body"))
	out.InvocationContexts[invocationIndex] = f.invocation
	out.Entries[entryIndex].Gaps = phpMergeGaps(out.Entries[entryIndex].Gaps, f.gaps)
}

func (f *phpFlow) symfonyParameter(route string, param *sitter.Node, action bool) phpValue {
	name := phpVarName(f.module, phpField(param, "name"))
	node := phpField(param, "type")
	text := phpText(f.module, node)
	class := ""
	switch strings.TrimPrefix(strings.ToLower(text), "?") {
	case "", "string", "int", "float", "bool", "mixed", "array", "object", "iterable", "callable":
	default:
		if node != nil && !strings.ContainsAny(text, "|&") {
			class = f.set.classIndex().qualify(f.module, strings.TrimPrefix(text, "?"), node.StartByte())
		}
	}
	if strings.EqualFold(class, symfonyRequestClass) {
		return phpValue{binding: "symfony_request", class: symfonyRequestClass}
	}
	if action {
		placeholder := symfonyPlaceholder(route, name)
		if attr := f.symfonyAttribute(f.module, param, `Symfony\Component\HttpKernel\Attribute\MapQueryParameter`); attr != nil {
			if explicit := symfonyAttributeString(f.module, attr, "name"); explicit != "" {
				name = explicit
			}
			return f.symfonyScalarArgument(param, text, f.source(param, "query", "http.query", name))
		}
		if class != "" {
			decl := f.symfonyClass(class)
			if decl != nil {
				if f.symfonyAttribute(f.module, param, `Symfony\Component\HttpKernel\Attribute\MapQueryString`) != nil {
					return f.symfonyDTO(decl, param, "query", "http.query")
				}
				if f.symfonyAttribute(f.module, param, `Symfony\Component\HttpKernel\Attribute\MapRequestPayload`) != nil {
					f.requestPayloadEntity(param, decl)
					return f.symfonyDTO(decl, param, "body", "http.body")
				}
				current := f.symfonyAttribute(f.module, param, `Symfony\Component\Security\Http\Attribute\CurrentUser`) != nil
				mapped := f.symfonyAttribute(f.module, param, `Symfony\Bridge\Doctrine\Attribute\MapEntity`) != nil
				// The entity resolver maps an entity argument from the route's
				// identifier or field placeholders, whatever the argument is named.
				if current || placeholder || mapped || strings.Contains(route, "{") {
					if entity, ok := f.symfonyEntity(decl, param); ok {
						return entity
					}
				}
			}
		}
		if class == "" && placeholder {
			v := f.symfonyScalarArgument(param, text, f.source(param, "attributes", "http.path", name))
			if symfonyDigitsRequirement(route, name) {
				// The router rejects any other text before the action runs.
				v = phpProtect(phpTransfer(v, f.entry.Location), "numeric")
			}
			return v
		}
	}
	if class != "" {
		return f.autowireSymfony(class, param)
	}
	return phpValue{unknown: true, gaps: []analysis.Gap{f.gap("symfony_argument_unresolved", "Unresolved Symfony argument $"+name, param)}}
}

// symfonyScalarArgument applies the declared scalar type of a route or query
// argument: the framework passes an int, float or bool, never request text.
func (f *phpFlow) symfonyScalarArgument(param *sitter.Node, declared string, v phpValue) phpValue {
	switch strings.TrimPrefix(strings.ToLower(declared), "?") {
	case "int", "float":
		return phpProtect(phpTransfer(v, f.module.evidence("typed_conversion", param)), "numeric")
	case "bool":
		return phpProtect(phpTransfer(v, f.module.evidence("typed_conversion", param)), "non_content")
	}
	return v
}

// symfonyPlaceholder matches {name} anywhere in the route, with the optional
// "!" marker, inline <requirement> and ?default the routing syntax allows.
// https://symfony.com/doc/6.4/routing.html#route-parameters
func symfonyPlaceholder(route, name string) bool {
	_, ok := symfonyPlaceholderTail(route, name)
	return ok
}

// symfonyPlaceholderTail returns the text after the placeholder's name, up to
// its closing brace: the inline requirement and default, when present.
func symfonyPlaceholderTail(route, name string) (string, bool) {
	for rest := route; ; {
		open := strings.Index(rest, "{")
		if open < 0 {
			return "", false
		}
		rest = rest[open+1:]
		end := strings.IndexAny(rest, "<?}")
		if end < 0 {
			return "", false
		}
		if strings.TrimPrefix(rest[:end], "!") != name {
			continue
		}
		tail := rest[end:]
		if rest[end] == '<' {
			// A requirement can contain "}" (a quantifier); it ends at ">".
			if stop := strings.Index(tail, ">"); stop >= 0 {
				return tail[:stop+1], true
			}
		}
		if stop := strings.Index(tail, "}"); stop >= 0 {
			return tail[:stop], true
		}
		return "", true
	}
}

// symfonyDigitsRequirement reports an inline requirement that admits digits only.
func symfonyDigitsRequirement(route, name string) bool {
	tail, _ := symfonyPlaceholderTail(route, name)
	switch tail {
	case `<\d+>`, `<[0-9]+>`, `<\d{1,}>`:
		return true
	}
	return false
}

func (f *phpFlow) symfonyAttribute(m *phpModule, declaration *sitter.Node, class string) *sitter.Node {
	var result *sitter.Node
	phpWalk(phpField(declaration, "attributes"), func(attr *sitter.Node) {
		if result == nil && attr.Kind() == "attribute" &&
			strings.EqualFold(f.set.classIndex().qualify(m, phpText(m, attr.NamedChild(0)), attr.StartByte()), class) {
			result = attr
		}
	})
	return result
}

func symfonyAttributeString(m *phpModule, attr *sitter.Node, key string) string {
	args := phpField(attr, "parameters")
	for i := uint(0); args != nil && i < args.NamedChildCount(); i++ {
		arg := args.NamedChild(i)
		if phpText(m, phpField(arg, "name")) == key && arg.NamedChildCount() > 0 {
			value, _ := phpStringLiteral(m, arg.NamedChild(arg.NamedChildCount()-1))
			return value
		}
	}
	return ""
}

func (f *phpFlow) symfonyDTO(decl *phpClassDecl, param *sitter.Node, container, origin string) phpValue {
	f.set.objects++
	v := phpValue{binding: "php_class", class: decl.fqn, classDecl: decl, objectID: f.set.objects, props: map[string]phpValue{}}
	properties := symfonyProperties(decl)
	source := f.clone()
	source.module = decl.module
	for _, field := range slices.Sorted(maps.Keys(properties)) {
		property := properties[field]
		for i := uint(0); i < property.NamedChildCount(); i++ {
			element := property.NamedChild(i)
			if element.Kind() == "property_element" && phpVarName(decl.module, phpField(element, "name")) == field {
				v.props[field] = phpTransfer(source.source(element, container, origin, field), f.module.evidence("argument_to_parameter", param))
				break
			}
		}
	}
	return v
}
