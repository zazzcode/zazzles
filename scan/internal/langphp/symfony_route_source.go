package langphp

import (
	"regexp"
	"slices"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/parse"
)

func symfonyPublicMethod(m *phpModule, n *sitter.Node) bool {
	if n == nil || n.Kind() != "method_declaration" || phpField(n, "body") == nil {
		return false
	}
	modifier := firstChildOfKind(n, "visibility_modifier")
	return modifier == nil || phpText(m, modifier) == "public"
}

func symfonyClassRoutes(index *phpClassIndex, decl *phpClassDecl, imports []symfonyRouteImport, routingRead bool) []symfonyRoute {
	m := decl.module
	prefixes := symfonyRouteDeclarations(index, m, decl.node)
	if len(prefixes) == 0 {
		prefixes = []symfonyRoute{{}}
	}
	var out []symfonyRoute
	body := phpField(decl.node, "body")
	for i := uint(0); i < body.NamedChildCount(); i++ {
		action := body.NamedChild(i)
		if !symfonyPublicMethod(m, action) {
			continue
		}
		for _, route := range symfonyRouteDeclarations(index, m, action) {
			route.class = decl.fqn
			route.method = phpText(m, phpField(action, "name"))
			route.target, route.action = decl, action
			for _, prefix := range prefixes {
				joined := route
				if prefix.unresolved {
					joined.path = ""
					joined.addGap("symfony_route_dynamic", "Class route prefix is not literal", true)
				} else if !route.unresolved {
					joined.path = symfonyJoinRoute(prefix.path, route.path)
					joined.name = prefix.name + route.name
				}
				added := false
				for _, imp := range imports {
					annotation := route.mechanism == "annotation_route"
					if (imp.kind == "attribute" && annotation) || (imp.kind == "annotation" && !annotation) ||
						(imp.kind != "" && imp.kind != "attribute" && imp.kind != "annotation") ||
						(imp.namespace != "" && !strings.HasPrefix(decl.fqn, strings.TrimSuffix(imp.namespace, `\`)+`\`)) ||
						(m.file != imp.resource && !strings.HasPrefix(m.file, imp.resource+"/")) {
						continue
					}
					imported := joined
					if !imported.unresolved {
						imported.path = symfonyJoinRoute(imp.prefix, joined.path)
						imported.name = imp.namePrefix + joined.name
					}
					out = append(out, imported)
					added = true
				}
				if added {
					continue
				}
				if routingRead {
					joined.addGap("symfony_route_not_imported", "Routing configuration does not import this controller", true)
				} else {
					joined.addGap("symfony_config_unread", "No readable routing configuration", false)
				}
				out = append(out, joined)
			}
		}
	}
	return out
}

func symfonyJoinRoute(prefix, suffix string) string {
	if prefix == "" || suffix == "" {
		return prefix + suffix
	}
	return strings.TrimRight(prefix, "/") + "/" + strings.TrimLeft(suffix, "/")
}

func symfonyRouteClass(name string) bool {
	return strings.EqualFold(name, `Symfony\Component\Routing\Attribute\Route`) ||
		strings.EqualFold(name, `Symfony\Component\Routing\Annotation\Route`)
}

func symfonyRouteDeclarations(index *phpClassIndex, m *phpModule, node *sitter.Node) []symfonyRoute {
	var out []symfonyRoute
	phpWalk(phpField(node, "attributes"), func(attr *sitter.Node) {
		if attr.Kind() != "attribute" || !symfonyRouteClass(index.qualify(m, phpText(m, attr.NamedChild(0)), attr.StartByte())) {
			return
		}
		route := symfonyRoute{mechanism: "attribute_route", origin: m.evidence("entry_registration", attr)}
		args := phpField(attr, "parameters")
		dynamic := false
		for i := uint(0); args != nil && i < args.NamedChildCount(); i++ {
			arg := args.NamedChild(i)
			name := phpText(m, phpField(arg, "name"))
			value := arg.NamedChild(arg.NamedChildCount() - 1)
			switch {
			case name == "path" || name == "" && i == 0:
				var ok bool
				route.path, ok = phpStringLiteral(m, value)
				dynamic = dynamic || !ok
			case name == "name":
				route.name, _ = phpStringLiteral(m, value)
			case name == "methods":
				var ok bool
				route.methods, ok = symfonyAttributeMethods(m, value)
				dynamic = dynamic || !ok
			}
		}
		if dynamic {
			route.path = ""
			route.addGap("symfony_route_dynamic", "Route path or methods are not literal", true)
		}
		out = append(out, route)
	})
	doc := node.PrevNamedSibling()
	if doc != nil && doc.Kind() == "comment" && strings.HasPrefix(phpText(m, doc), "/**") {
		out = append(out, symfonyAnnotations(index, m, doc)...)
	}
	return out
}

func symfonyAttributeMethods(m *phpModule, value *sitter.Node) ([]string, bool) {
	if method, ok := phpStringLiteral(m, value); ok {
		return []string{strings.ToUpper(method)}, true
	}
	if value == nil || value.Kind() != "array_creation_expression" {
		return nil, false
	}
	var methods []string
	for i := uint(0); i < value.NamedChildCount(); i++ {
		item := value.NamedChild(i)
		if item.Kind() == "comment" {
			continue
		}
		if item.Kind() != "array_element_initializer" || item.NamedChildCount() != 1 {
			return nil, false
		}
		method, ok := phpStringLiteral(m, item.NamedChild(0))
		if !ok {
			return nil, false
		}
		methods = append(methods, strings.ToUpper(method))
	}
	slices.Sort(methods)
	return slices.Compact(methods), true
}

var symfonyAnnotationName = regexp.MustCompile(`@([A-Za-z_][A-Za-z0-9_]*)\s*\(`)

func symfonyAnnotations(index *phpClassIndex, m *phpModule, doc *sitter.Node) []symfonyRoute {
	source := m.evidence("entry_registration", doc)
	var out []symfonyRoute
	for _, match := range symfonyAnnotationName.FindAllStringSubmatchIndex(source.Text, -1) {
		name := source.Text[match[2]:match[3]]
		if !symfonyRouteClass(index.qualify(m, name, doc.StartByte())) {
			continue
		}
		fields, size := symfonyAnnotationFields(source.Text[match[1]:])
		origin := parse.TextRange(source, match[0], match[1]+size, "entry_registration")
		origin.Span.StartByte += int(doc.StartByte())
		origin.Span.EndByte += int(doc.StartByte())
		origin.Span.StartLine += int(doc.StartPosition().Row)
		origin.Span.EndLine += int(doc.StartPosition().Row)
		origin.ModelText = origin.Text
		route := symfonyRoute{origin: origin, mechanism: "annotation_route"}
		dynamic := size == 0
		for i, field := range fields {
			left, right, named := strings.Cut(field, "=")
			var ok bool
			switch {
			case !named && i == 0:
				route.path, ok = symfonyAnnotationLiteral(left)
				dynamic = dynamic || !ok
			case named && strings.TrimSpace(left) == "path":
				route.path, ok = symfonyAnnotationLiteral(right)
				dynamic = dynamic || !ok
			case named && strings.TrimSpace(left) == "name":
				route.name, _ = symfonyAnnotationLiteral(right)
			case named && strings.TrimSpace(left) == "methods":
				route.methods, ok = symfonyAnnotationMethods(right)
				dynamic = dynamic || !ok
			}
		}
		if dynamic {
			route.path = ""
			route.addGap("symfony_route_dynamic", "Route annotation path or methods are not literal", true)
		}
		out = append(out, route)
	}
	return out
}

func symfonyAnnotationFields(text string) ([]string, int) {
	var fields []string
	var quote byte
	start, nesting := 0, 0
	for i := 0; i < len(text); i++ {
		c := text[i]
		if quote != 0 {
			if c == '\\' {
				i++
			} else if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '"', '\'':
			quote = c
		case '(', '{', '[':
			nesting++
		case ')':
			if nesting == 0 {
				return append(fields, text[start:i]), i + 1
			}
			nesting--
		case '}', ']':
			nesting--
		case ',':
			if nesting == 0 {
				fields = append(fields, text[start:i])
				start = i + 1
			}
		}
	}
	return nil, 0
}

func symfonyAnnotationLiteral(text string) (string, bool) {
	text = strings.TrimSpace(text)
	if len(text) >= 2 && (text[0] == '"' || text[0] == '\'') && text[0] == text[len(text)-1] {
		return text[1 : len(text)-1], true
	}
	return "", false
}

func symfonyAnnotationMethods(text string) ([]string, bool) {
	if method, ok := symfonyAnnotationLiteral(text); ok {
		return []string{strings.ToUpper(method)}, true
	}
	text = strings.TrimSpace(text)
	if !strings.HasPrefix(text, "{") || !strings.HasSuffix(text, "}") {
		return nil, false
	}
	var methods []string
	for _, item := range strings.Split(text[1:len(text)-1], ",") {
		if strings.TrimSpace(item) == "" {
			continue
		}
		method, ok := symfonyAnnotationLiteral(item)
		if !ok {
			return nil, false
		}
		methods = append(methods, strings.ToUpper(method))
	}
	slices.Sort(methods)
	return slices.Compact(methods), true
}
