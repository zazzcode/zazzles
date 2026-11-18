package langjs

import (
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/parse"
)

// nextActionEntries registers Server Actions as public POST entries: every
// exported async function of a "use server" module, and every async function
// whose body begins with "use server" in a server module. Next.js posts actions
// to the current page URL with an action ID, so the path stays unresolved.
func (s *moduleSet) nextActionEntries(out *analysis.AnalysisReport, m *sourceModule, p *nextProject) {
	directive := moduleDirective(m)
	if directive == "use client" {
		return
	}
	if directive == "use server" {
		for _, e := range s.nextExports(m, 0) {
			res := s.nextHandler(e.owner, e.value, 0)
			if res.fn == nil || !asyncFunction(res.fn) {
				continue
			}
			s.analyzeNextAction(out, m, e, p)
		}
		return
	}
	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		if (n.Kind() == "function_declaration" || isFunction(n)) && asyncFunction(n) && functionDirective(n, m.src) == "use server" {
			name := "inline"
			if id := n.ChildByFieldName("name"); id != nil {
				name = id.Utf8Text(m.src)
			} else if p := n.Parent(); p != nil && p.Kind() == "variable_declarator" {
				if id := p.ChildByFieldName("name"); id != nil {
					name = id.Utf8Text(m.src)
				}
			}
			s.analyzeNextAction(out, m, nextExport{name: name, decl: n, value: n, owner: m}, p)
			return
		}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			visit(n.NamedChild(i))
		}
	}
	visit(m.tree.RootNode())
}

func (s *moduleSet) analyzeNextAction(out *analysis.AnalysisReport, m *sourceModule, e nextExport, p *nextProject) {
	r := analysis.Route{ID: "nextjs-action:" + m.file + ":" + e.name, Method: "POST", PathPattern: "", Framework: "nextjs", Registration: parse.Span(m.file, e.decl)}
	before := len(out.Entries)
	s.analyzeNextHandler(out, m, r, e, p, nil, "server_action", "app")
	if len(out.Entries) > before {
		entry := &out.Entries[before]
		entry.Name = "POST server action " + m.file + "#" + e.name
		entry.Gaps = append(entry.Gaps, analysis.Gap{Kind: "next_action_path_dynamic", Detail: "Server Actions are posted to the invoking page URL with an action ID header; any page can reach this public endpoint", At: parse.Span(m.file, e.decl)})
	}
}

// actionParameters binds every Server Action parameter as attacker-controlled
// request body data. TypeScript annotations are not runtime validation; a
// FormData parameter is a form object.
func (f *flow) actionParameters(fn *sitter.Node) {
	params := fn.ChildByFieldName("parameters")
	if params == nil {
		return
	}
	for i := uint(0); i < params.NamedChildCount(); i++ {
		p := params.NamedChild(i)
		pattern := p
		if p.Kind() == "required_parameter" || p.Kind() == "optional_parameter" {
			pattern = p.ChildByFieldName("pattern")
		}
		if pattern == nil || pattern.Kind() != "identifier" {
			continue
		}
		name := pattern.Utf8Text(f.module.src)
		typ := ""
		if t := p.ChildByFieldName("type"); t != nil {
			typ = strings.TrimSpace(strings.TrimPrefix(t.Utf8Text(f.module.src), ":"))
		}
		kind, initial := "", "unknown"
		if typ == "FormData" {
			kind, initial = "formData", "FormData"
		}
		f.env[name] = f.webSource(pattern, "http.body", initial, "", nil, value{}, false, kind)
	}
}
