package parse

import (
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
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
		r := analysis.Route{ID: "nextjs-page:" + m.file + ":" + e.name, Method: "GET", PathPattern: pattern, Framework: "nextjs", Registration: spanOf(m.file, e.decl)}
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
	f.recordXSS(f.module.evidence("server_render", n), v, context, "text/html", false, []analysis.Evidence{f.module.evidence("render_binding", tagNode)})
	return v, true
}
