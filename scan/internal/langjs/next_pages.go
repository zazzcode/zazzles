package langjs

import (
	"path"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/parse"
)

// nextPageEntries registers a Server Component page (`page.tsx` default export)
// as a GET entry with params/searchParams props, and its generateMetadata export
// as a separate stage entry of the same path. Client pages ("use client") run in
// the browser and are analyzed as browser modules instead.
func (s *moduleSet) nextPageEntries(out *analysis.AnalysisReport, m *sourceModule, p *nextProject) {
	segments, base, _, ok := p.appSegments(m.file)
	if !ok || base != "page" || moduleDirective(m) == "use client" {
		return
	}
	pattern, converted, routable := nextRoutePattern(segments)
	if !routable {
		return
	}
	dir := path.Dir(m.file)
	for _, ext := range []string{".ts", ".js", ".tsx", ".jsx", ".mjs"} {
		if s.allowed[dir+"/route"+ext] {
			return // a route/page conflict is reported once, on the route file
		}
	}
	for _, e := range s.nextExports(m, 0) {
		surface := ""
		switch e.name {
		case "default":
			surface = "page"
		case "generateMetadata":
			surface = "page_metadata"
		default:
			continue
		}
		r := analysis.Route{ID: "nextjs-page:" + m.file + ":" + e.name, Method: "GET", PathPattern: pattern, Framework: "nextjs", Registration: parse.Span(m.file, e.decl)}
		s.analyzeNextHandler(out, m, r, e, p, converted, surface, "app")
	}
}

// nextNavigationExit reports a verified next/navigation call that throws a
// framework signal and never returns: redirect, permanentRedirect, notFound,
// forbidden and unauthorized. A local function of the same name is not an exit.
func nextNavigationExit(m *sourceModule, n *sitter.Node) bool {
	n = unwrapTS(n)
	if n == nil {
		return false
	}
	if n.Kind() == "await_expression" && n.NamedChildCount() == 1 {
		n = unwrapTS(n.NamedChild(0))
	}
	if n.Kind() != "call_expression" {
		return false
	}
	fn := n.ChildByFieldName("function")
	if fn == nil || fn.Kind() != "identifier" || shadowed(n, fn.Utf8Text(m.src), m.src) {
		return false
	}
	imp, ok := m.imports[fn.Utf8Text(m.src)]
	if !ok || imp.module != "next/navigation" {
		return false
	}
	switch imp.name {
	case "redirect", "permanentRedirect", "notFound", "forbidden", "unauthorized":
		return true
	}
	return false
}

// serverJSX records server-rendered sinks in a Server Component: raw HTML
// (dangerouslySetInnerHTML, iframe srcDoc) and URL attributes that can carry a
// scheme. JSX text and other attributes are React-encoded and record nothing.
func (f *flow) serverJSX(n *sitter.Node) (value, bool) {
	if f.web == nil || (f.web.surface != "page" && f.web.surface != "page_metadata") || n.Kind() != "jsx_attribute" {
		return value{}, false
	}
	src := f.module.src
	name, expression := n.ChildByFieldName("name"), n.ChildByFieldName("value")
	if name == nil && n.NamedChildCount() > 1 {
		name, expression = n.NamedChild(0), n.NamedChild(1)
	}
	if name == nil || expression == nil || expression.Kind() != "jsx_expression" || expression.NamedChildCount() != 1 {
		return value{}, false
	}
	parent := n.Parent()
	if parent == nil {
		return value{}, false
	}
	tagNode := parent.ChildByFieldName("name")
	if tagNode == nil {
		return value{}, false
	}
	tag := tagNode.Utf8Text(src)
	host := tag != "" && strings.ToLower(tag[:1]) == tag[:1] && !strings.Contains(tag, ".")
	attribute := name.Utf8Text(src)
	arg := expression.NamedChild(0)
	context := ""
	var operand *sitter.Node
	switch {
	case attribute == "dangerouslySetInnerHTML" && arg.Kind() == "object":
		operand, context = property(arg, "__html", src), "html_text"
		if tag == "script" {
			context = "script"
		}
	case host && attribute == "srcDoc":
		operand, context = arg, "html_text"
	case (host && (attribute == "href" || attribute == "src" || attribute == "action" || attribute == "formAction" || attribute == "data")) || (tag == "Link" && attribute == "href") || (tag == "Script" && attribute == "src"):
		operand, context = arg, "url"
	default:
		return value{}, false
	}
	v := f.eval(operand)
	if context == "url" && fixedURLPrefix(f, operand) {
		// A literal prefix fixes the scheme: no javascript: URL is possible.
		return v, true
	}
	f.recordXSS(f.module.evidence("server_render", n), v, context, "text/html", false, []analysis.Evidence{f.module.evidence("render_binding", tagNode)})
	return v, true
}

// fixedURLPrefix reports a URL expression whose start is a non-empty literal or
// a request-independent local followed by "/": the scheme cannot come from data.
func fixedURLPrefix(f *flow, n *sitter.Node) bool {
	n = unwrapTS(n)
	if n == nil {
		return false
	}
	switch n.Kind() {
	case "string":
		return true
	case "template_string":
		if n.NamedChildCount() == 0 {
			return true
		}
		first := n.NamedChild(0)
		if first.Kind() == "string_fragment" {
			return first.Utf8Text(f.module.src) != ""
		}
		if first.Kind() == "template_substitution" && first.NamedChildCount() == 1 && n.NamedChildCount() > 1 {
			next := n.NamedChild(1)
			base := unwrapTS(first.NamedChild(0))
			if next.Kind() == "string_fragment" && strings.HasPrefix(next.Utf8Text(f.module.src), "/") && base.Kind() == "identifier" {
				v, ok := f.env[base.Utf8Text(f.module.src)]
				if ok {
					return len(v.deps) == 0
				}
				return f.set.staticFixedURL(f.module, base, 0)
			}
		}
	case "identifier", "call_expression", "ternary_expression":
		if v, ok := f.env[n.Utf8Text(f.module.src)]; ok && n.Kind() == "identifier" {
			if len(v.deps) == 0 {
				return true
			}
			if def := definitionAt(f.module, n, n.Utf8Text(f.module.src)); def != nil {
				return f.set.staticFixedURL(f.module, def, 0)
			}
			return false
		}
		return f.set.staticFixedURL(f.module, n, 0)
	case "binary_expression":
		if op := n.ChildByFieldName("operator"); op != nil && op.Utf8Text(f.module.src) == "+" {
			return fixedURLPrefix(f, n.ChildByFieldName("left"))
		}
	}
	return false
}

// staticFixedURL reports, without request data flow, an expression that always
// yields a URL with a literal prefix (or no URL): a literal, a constant bound to
// one (also through a named import), a ternary of such values, or a resolved
// helper whose every return is one.
func (s *moduleSet) staticFixedURL(m *sourceModule, n *sitter.Node, depth int) bool {
	n = unwrapTS(n)
	if n == nil || depth > 4 {
		return false
	}
	switch n.Kind() {
	case "string", "null", "undefined":
		return true
	case "template_string":
		if n.NamedChildCount() == 0 {
			return true
		}
		first := n.NamedChild(0)
		if first.Kind() == "string_fragment" {
			return first.Utf8Text(m.src) != ""
		}
		if first.Kind() == "template_substitution" && first.NamedChildCount() == 1 && n.NamedChildCount() > 1 {
			if next := n.NamedChild(1); next.Kind() == "string_fragment" && strings.HasPrefix(next.Utf8Text(m.src), "/") {
				return s.staticFixedURL(m, first.NamedChild(0), depth+1)
			}
		}
	case "ternary_expression":
		return s.staticFixedURL(m, n.ChildByFieldName("consequence"), depth+1) && s.staticFixedURL(m, n.ChildByFieldName("alternative"), depth+1)
	case "binary_expression":
		if op := n.ChildByFieldName("operator"); op != nil && op.Utf8Text(m.src) == "+" {
			return s.staticFixedURL(m, n.ChildByFieldName("left"), depth+1)
		}
	case "identifier":
		name := n.Utf8Text(m.src)
		if bindingReassigned(m, name) {
			return false
		}
		if v := topVariable(m, name); v != nil {
			return s.staticFixedURL(m, v, depth+1)
		}
		if imp, ok := m.imports[name]; ok && imp.name != "*" && imp.name != "default" {
			if target, local, _ := s.namedExport(m, imp.module, imp.name, 0); target != nil {
				if v := topVariable(target, local); v != nil {
					return s.staticFixedURL(target, v, depth+1)
				}
			}
		}
	case "call_expression":
		hm, fn := s.resolveCall(m, n)
		if hm == nil || fn == nil || !supportedCallee(fn) {
			return false
		}
		body := fn.ChildByFieldName("body")
		if body == nil {
			return false
		}
		if body.Kind() != "statement_block" {
			return s.staticFixedURL(hm, body, depth+1)
		}
		returns := 0
		ok := true
		var visit func(*sitter.Node)
		visit = func(c *sitter.Node) {
			if isFunction(c) {
				return
			}
			if c.Kind() == "return_statement" {
				returns++
				if c.NamedChildCount() == 1 && !s.staticFixedURL(hm, c.NamedChild(0), depth+1) {
					ok = false
				}
			}
			for i := uint(0); i < c.NamedChildCount(); i++ {
				visit(c.NamedChild(i))
			}
		}
		visit(body)
		return ok && returns > 0
	}
	return false
}
