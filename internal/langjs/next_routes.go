package langjs

import (
	"path"
	"sort"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/parse"
)

// nextSegment is one converted App Router folder segment.
type nextSegment struct {
	raw, pattern string
	param        string // parameter name for dynamic segments
	paramType    string // string, string[], string[] | undefined
	kind         string // literal, dynamic, catch_all, optional_catch_all, group, private, parallel, intercept
}

// convertNextSegment maps a folder name to the shared `:name` route syntax.
func convertNextSegment(seg string) nextSegment {
	s := nextSegment{raw: seg, kind: "literal", pattern: seg}
	switch {
	case strings.HasPrefix(seg, "[[...") && strings.HasSuffix(seg, "]]"):
		s.kind, s.param, s.paramType = "optional_catch_all", seg[5:len(seg)-2], "string[] | undefined"
		s.pattern = ":" + s.param + "*?"
	case strings.HasPrefix(seg, "[...") && strings.HasSuffix(seg, "]"):
		s.kind, s.param, s.paramType = "catch_all", seg[4:len(seg)-1], "string[]"
		s.pattern = ":" + s.param + "*"
	case strings.HasPrefix(seg, "[") && strings.HasSuffix(seg, "]"):
		s.kind, s.param, s.paramType = "dynamic", seg[1:len(seg)-1], "string"
		s.pattern = ":" + s.param
	case strings.HasPrefix(seg, "(.)") || strings.HasPrefix(seg, "(..)") || strings.HasPrefix(seg, "(...)"):
		s.kind, s.pattern = "intercept", ""
	case strings.HasPrefix(seg, "(") && strings.HasSuffix(seg, ")"):
		s.kind, s.pattern = "group", ""
	case strings.HasPrefix(seg, "_"):
		s.kind, s.pattern = "private", ""
	case strings.HasPrefix(seg, "@"):
		s.kind, s.pattern = "parallel", ""
	}
	return s
}

// nextRoutePattern converts the folder segments of a route file. routable is
// false for private folders and for parallel/intercepting segments.
func nextRoutePattern(segments []string) (pattern string, converted []nextSegment, routable bool) {
	parts := []string{}
	routable = true
	for _, seg := range segments {
		c := convertNextSegment(seg)
		converted = append(converted, c)
		switch c.kind {
		case "private", "parallel", "intercept":
			routable = false
		case "group":
		default:
			parts = append(parts, c.pattern)
		}
	}
	return "/" + strings.Join(parts, "/"), converted, routable
}

var nextHTTPMethods = []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}

func nextFileBase(file string) (string, string) {
	base := path.Base(file)
	ext := path.Ext(base)
	return strings.TrimSuffix(base, ext), ext
}

func nextSourceExt(ext string) bool {
	switch ext {
	case ".ts", ".tsx", ".js", ".jsx", ".mjs":
		return true
	}
	return false
}

// nextRouteSegments returns the folder segments of file under the App Router
// directory and its base name, or ok=false when file is not in the app tree.
func (p *nextProject) appSegments(file string) (segments []string, base, ext string, ok bool) {
	if p.appDir == "" || !strings.HasPrefix(file, p.appDir+"/") {
		return nil, "", "", false
	}
	rel := strings.TrimPrefix(file, p.appDir+"/")
	dir := path.Dir(rel)
	if dir != "." {
		segments = strings.Split(dir, "/")
	}
	base, ext = nextFileBase(file)
	return segments, base, ext, nextSourceExt(ext)
}

// nextExport is one exported binding of a route or page module.
type nextExport struct {
	name  string
	decl  *sitter.Node // export statement
	value *sitter.Node // function, call or identifier that supplies it
	owner *sourceModule
	gaps  []analysis.Gap
}

// nextExports lists the named exports of m that a Next.js file convention
// consumes: direct function and const declarations, export clauses with
// aliases, and one level of `export { X } from "./y"`.
func (s *moduleSet) nextExports(m *sourceModule, depth int) []nextExport {
	var out []nextExport
	root := m.tree.RootNode()
	for i := uint(0); i < root.NamedChildCount(); i++ {
		n := root.NamedChild(i)
		if n.Kind() != "export_statement" {
			continue
		}
		if decl := n.ChildByFieldName("declaration"); decl != nil {
			if strings.HasPrefix(n.Utf8Text(m.src), "export default") {
				out = append(out, nextExport{name: "default", decl: n, value: decl, owner: m})
				continue
			}
			switch decl.Kind() {
			case "function_declaration", "generator_function_declaration":
				if id := decl.ChildByFieldName("name"); id != nil {
					out = append(out, nextExport{name: id.Utf8Text(m.src), decl: n, value: decl, owner: m})
				}
			case "lexical_declaration", "variable_declaration":
				for j := uint(0); j < decl.NamedChildCount(); j++ {
					d := decl.NamedChild(j)
					id, v := d.ChildByFieldName("name"), d.ChildByFieldName("value")
					if id != nil && id.Kind() == "identifier" && v != nil {
						out = append(out, nextExport{name: id.Utf8Text(m.src), decl: n, value: v, owner: m})
					}
				}
			}
			continue
		}
		if v := n.ChildByFieldName("value"); v != nil {
			out = append(out, nextExport{name: "default", decl: n, value: v, owner: m})
			continue
		}
		source := ""
		if src := n.ChildByFieldName("source"); src != nil {
			source, _ = stringLiteral(src, m.src)
		}

		if source != "" && strings.Contains(n.Utf8Text(m.src), "export *") && depth < 4 {
			if target := s.importModule(m, source); target != nil && target != m {
				for _, e := range s.nextExports(target, depth+1) {
					if e.name != "default" {
						e.decl = n
						out = append(out, e)
					}
				}
			}
			continue
		}
		for j := uint(0); j < n.NamedChildCount(); j++ {
			clause := n.NamedChild(j)
			if clause.Kind() != "export_clause" {
				continue
			}
			for k := uint(0); k < clause.NamedChildCount(); k++ {
				spec := clause.NamedChild(k)
				id, alias := spec.ChildByFieldName("name"), spec.ChildByFieldName("alias")
				if id == nil {
					continue
				}
				visible := id
				if alias != nil {
					visible = alias
				}
				local := id.Utf8Text(m.src)
				if source == "" {
					out = append(out, nextExport{name: visible.Utf8Text(m.src), decl: n, value: id, owner: m})
					continue
				}
				// export { GET } from "./impl": follow one module hop.
				target := s.importModule(m, source)
				if target == nil || depth > 0 {
					out = append(out, nextExport{name: visible.Utf8Text(m.src), decl: n, owner: m, gaps: []analysis.Gap{{Kind: "unresolved_handler", Detail: "re-exported handler module is not resolved: " + source, At: parse.Span(m.file, n)}}})
					continue
				}
				found := false
				for _, e := range s.nextExports(target, depth+1) {
					if e.name == local {
						e.name = visible.Utf8Text(m.src)
						e.decl = n
						out = append(out, e)
						found = true
					}
				}
				if !found {
					out = append(out, nextExport{name: visible.Utf8Text(m.src), decl: n, owner: m, gaps: []analysis.Gap{{Kind: "unresolved_handler", Detail: "re-exported handler is not declared in " + source, At: parse.Span(m.file, n)}}})
				}
			}
		}
		if strings.HasPrefix(n.Utf8Text(m.src), "export *") {
			out = append(out, nextExport{name: "*", decl: n, owner: m, gaps: []analysis.Gap{{Kind: "unresolved_handler", Detail: "export * is not expanded into route handlers", At: parse.Span(m.file, n)}}})
		}
	}
	return out
}

// nextRouteEntries registers every exported HTTP method handler of an App
// Router route file. The file path is the registration; the export is the
// handler. Unsupported export shapes stay visible as entry gaps.
func (s *moduleSet) nextRouteEntries(out *analysis.AnalysisReport, m *sourceModule, p *nextProject) {
	segments, base, _, ok := p.appSegments(m.file)
	if !ok || base != "route" {
		return
	}
	pattern, converted, routable := nextRoutePattern(segments)
	if !routable {
		out.Gaps = append(out.Gaps, analysis.Gap{Kind: "next_route_not_routable", Detail: "route file under a private, parallel or intercepting folder is not a public endpoint", At: parse.Span(m.file, m.tree.RootNode())})
		return
	}
	if s.nextHasPage(m.file) {
		out.Gaps = append(out.Gaps, analysis.Gap{Kind: "next_route_conflict", Detail: "route and page files share one segment; Next.js rejects the build", At: parse.Span(m.file, m.tree.RootNode())})
		return
	}
	if s.next.routeFiles == nil {
		s.next.routeFiles = map[string]bool{}
	}
	s.next.routeFiles[m.file] = true
	exports := s.nextExports(m, 0)
	sort.SliceStable(exports, func(i, j int) bool { return methodOrder(exports[i].name) < methodOrder(exports[j].name) })
	for _, e := range exports {
		method := ""
		for _, verb := range nextHTTPMethods {
			if e.name == verb {
				method = verb
			}
		}
		if method == "" {
			if e.name == "default" {
				out.Gaps = append(out.Gaps, analysis.Gap{Kind: "next_route_default_export", Detail: "App Router route files dispatch named method exports, not a default export", At: parse.Span(m.file, e.decl)})
			}
			continue
		}
		r := analysis.Route{ID: "nextjs:" + m.file + ":" + method, Method: method, PathPattern: pattern, Framework: "nextjs", Registration: parse.Span(m.file, e.decl)}
		s.analyzeNextHandler(out, m, r, e, p, converted, "route_handler", "app")
	}
}

func methodOrder(name string) int {
	for i, v := range nextHTTPMethods {
		if v == name {
			return i
		}
	}
	return len(nextHTTPMethods)
}

// nextHasPage reports a page file in the same segment as a route file.
func (s *moduleSet) nextHasPage(routeFile string) bool {
	dir := path.Dir(routeFile)
	for _, ext := range []string{".tsx", ".jsx", ".ts", ".js"} {
		if s.allowed[dir+"/page"+ext] {
			return true
		}
	}
	return false
}

// pagesAPIEntries registers a Pages Router API route (`pages/api/**`) default
// export. The method is ANY: the handler's own req.method tests are ordinary
// conditional flow.
func (s *moduleSet) pagesAPIEntries(out *analysis.AnalysisReport, m *sourceModule, p *nextProject) {
	if p.pagesDir == "" || !strings.HasPrefix(m.file, p.pagesDir+"/api/") {
		return
	}
	rel := strings.TrimPrefix(m.file, p.pagesDir+"/")
	base, ext := nextFileBase(rel)
	if !nextSourceExt(ext) {
		return
	}
	dir := path.Dir(rel)
	segments := strings.Split(dir, "/")
	if base != "index" {
		segments = append(segments, base)
	}
	pattern, converted, routable := nextRoutePattern(segments)
	if !routable {
		return
	}
	for _, e := range s.nextExports(m, 0) {
		if e.name != "default" {
			continue
		}
		r := analysis.Route{ID: "nextjs-pages:" + m.file + ":ALL", Method: "ALL", PathPattern: pattern, Framework: "nextjs-pages", Registration: parse.Span(m.file, e.decl)}
		s.analyzeNextHandler(out, m, r, e, p, converted, "api_route", "pages")
	}
}

// nextRouteInventory lists App Router method handlers and Pages Router API
// routes for --routes. It uses the same file conventions as Analyze; handler
// bodies are not analyzed here.
func nextRouteInventory(root string, files []string) ([]analysis.Route, []analysis.Gap, error) {
	ps, err := newParsers()
	if err != nil {
		return nil, nil, err
	}
	set := &moduleSet{root: root, parsers: ps, modules: map[string]*sourceModule{}, allowed: map[string]bool{}}
	defer set.close()
	for _, f := range files {
		set.allowed[f] = true
	}
	set.detectNextProjects(files)
	if len(set.next.projects) == 0 {
		return nil, nil, nil
	}
	scratch := &analysis.AnalysisReport{}
	selected := set.applyNextScope(scratch, files)
	var routes []analysis.Route
	for _, f := range selected {
		p := set.nextProjectFor(f)
		if p == nil {
			continue
		}
		framework, router := "nextjs", "app"
		var segments []string
		base, ext := "", ""
		if s, b, e, ok := p.appSegments(f); ok && b == "route" {
			segments, base, ext = s, b, e
		} else if p.pagesDir != "" && strings.HasPrefix(f, p.pagesDir+"/api/") {
			rel := strings.TrimPrefix(f, p.pagesDir+"/")
			base, ext = nextFileBase(rel)
			if !nextSourceExt(ext) {
				continue
			}
			segments = strings.Split(path.Dir(rel), "/")
			if base != "index" {
				segments = append(segments, base)
			}
			framework, router = "nextjs-pages", "pages"
		} else {
			continue
		}
		pattern, _, routable := nextRoutePattern(segments)
		if !routable {
			continue
		}
		m, err := set.load(f)
		if err != nil {
			return nil, nil, err
		}
		if m.tree.RootNode().HasError() {
			scratch.Gaps = append(scratch.Gaps, analysis.Gap{Kind: "parse_error", Detail: "syntax error", At: parse.Span(f, m.tree.RootNode())})
			continue
		}
		for _, e := range set.nextExports(m, 0) {
			method := ""
			if router == "pages" && e.name == "default" {
				method = "ALL"
			}
			for _, v := range nextHTTPMethods {
				if router == "app" && e.name == v {
					method = v
				}
			}
			if method == "" {
				continue
			}
			reg := parse.Span(f, e.decl)
			routes = append(routes, analysis.Route{ID: framework + ":" + f + ":" + method, Method: method, PathPattern: pattern, Framework: framework, Registration: reg,
				Handler: analysis.Symbol{Name: e.name, Kind: "export", Span: reg},
				Steps:   []analysis.Step{{Kind: "registration", Symbol: analysis.Symbol{Name: "filesystem_route:" + f, Kind: "file", Span: reg}}}})
		}
	}
	return routes, scratch.Gaps, nil
}
