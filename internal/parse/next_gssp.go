package parse

import (
	"path"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
)

// pagesPageEntries registers a Pages Router page that exports
// getServerSideProps as a GET entry. getServerSideProps runs per request on
// the server with a context whose query, params and req are request data; the
// props it returns are the page component's props for the server render. One
// flow covers both stages, so a request value that reaches a raw-HTML or URL
// sink in the component through props is one record. Pages without
// getServerSideProps have no per-request server input and are analyzed as
// browser modules only.
func (s *moduleSet) pagesPageEntries(out *analysis.AnalysisReport, m *sourceModule, p *nextProject) {
	if p.pagesDir == "" || !strings.HasPrefix(m.file, p.pagesDir+"/") || strings.HasPrefix(m.file, p.pagesDir+"/api/") {
		return
	}
	rel := strings.TrimPrefix(m.file, p.pagesDir+"/")
	base, ext := nextFileBase(rel)
	if !nextSourceExt(ext) || strings.HasPrefix(base, "_") || base == "404" || base == "500" {
		return
	}
	var segments []string
	if dir := path.Dir(rel); dir != "." {
		segments = strings.Split(dir, "/")
	}
	if base != "index" {
		segments = append(segments, base)
	}
	pattern, converted, routable := nextRoutePattern(segments)
	if !routable {
		return
	}
	var gssp, component, static *nextExport
	exports := s.nextExports(m, 0)
	for i := range exports {
		switch exports[i].name {
		case "getStaticProps":
			static = &exports[i]
		case "getInitialProps", "getServerSideProps":
			gssp = &exports[i]
		case "default":
			component = &exports[i]
		}
	}
	if static != nil {
		ps := &practiceSet{out: out, seen: map[string]bool{}}
		ps.add("NEXT-BUILD", "Build-time page data", "observed", "getStaticProps executes at build/revalidation time; it is not a per-request input entry", pattern, m.evidence("build_time_entry", static.decl))
	}
	if gssp == nil {
		gssp = s.pagesInitialProps(m, component)
	}
	if gssp == nil {
		return
	}
	r := analysis.Route{ID: "nextjs-pages-page:" + m.file, Method: "GET", PathPattern: pattern, Framework: "nextjs-pages", Registration: spanOf(m.file, gssp.decl)}
	e := httpEntry(r, m.evidence("entry_registration", gssp.decl), m.file+":"+m.hash+":nextjs")
	e.HTTP.SourcePath = pattern
	e.HTTP.Router = "pages"
	e.HTTP.Surface = "page"
	for _, seg := range converted {
		e.HTTP.Segments = append(e.HTTP.Segments, seg.raw)
	}
	e.HTTP.Aliases = s.nextAliases(p, pattern)
	e.Gaps = append([]analysis.Gap{}, gssp.gaps...)
	res := nextResolved{gaps: []analysis.Gap{}}
	if gssp.value != nil {
		res = s.nextHandler(gssp.owner, gssp.value, 0)
	}
	e.Gaps = append(e.Gaps, res.gaps...)
	if res.fn == nil || res.module == nil || res.module.tree.RootNode().HasError() {
		if res.module != nil && res.module.tree.RootNode().HasError() {
			e.Gaps = append(e.Gaps, analysis.Gap{Kind: "parse_error", Detail: "page module has syntax errors", At: spanOf(res.module.file, res.fn)})
		}
		registerInvocation(out, e, nil, "filesystem_route", nil, e.Gaps)
		noteHTTPDeclaration(out, r, nil)
		return
	}
	hm, fn := res.module, res.fn
	body := fn.ChildByFieldName("body")
	r.Handler = analysis.Symbol{Name: gssp.name, Kind: "function", Span: spanOf(hm.file, fn)}
	inputs := []analysis.InputBinding{}
	req := ""
	params := nextParams(fn, hm.src)
	paramEvidence := parameterEvidence(hm, body, 0)
	if len(params) > 0 {
		switch {
		case params[0].name != "":
			// context.query / context.params mirror req.query / req.params.
			req = params[0].name
			inputs = append(inputs, httpInput("http.request", req, paramEvidence))
		case params[0].fields != nil:
			for key, local := range params[0].fields {
				switch key {
				case "query":
					inputs = append(inputs, httpInput("http.query", local, paramEvidence))
				case "params":
					inputs = append(inputs, httpInput("http.params", local, paramEvidence))
				case "req":
					req = local
					inputs = append(inputs, httpInput("http.request", local, paramEvidence))
				}
			}
		}
	}
	context := append([]analysis.Evidence{}, res.wrappers...)
	context = append(context, res.auth...)
	evidence := hm.evidence("handler", body)
	s.rememberNodeHTTP(e, m, hm, gssp.decl, body, req, "", context)
	invocation := registerInvocation(out, e, &evidence, "filesystem_route", inputs, e.Gaps)
	entryIndex := len(out.Entries) - 1
	f := flow{report: out, module: hm, set: s, entry: e, invocation: invocation, registration: m,
		env: map[string]value{}, context: append([]analysis.Evidence{m.evidence("registration", gssp.decl), evidence}, context...),
		gaps: append([]analysis.Gap{}, e.Gaps...), helpers: &helperExpansion{budget: 24, stack: map[string]bool{}}, facts: newInputFacts()}
	f.seedInvocation()
	f.nextData = true
	f.statements(body)
	f.nextData = false
	// Stage 2: the page component renders with the returned props.
	if component != nil && component.value != nil {
		if cres := s.nextHandler(component.owner, component.value, 0); cres.fn != nil && cres.module == hm {
			props := value{}
			for _, ret := range f.returns {
				if gssp.name == "getInitialProps" {
					props = combine(props, ret)
				}
				if p, ok := ret.fields["props"]; ok {
					props = combine(props, p)
				}
			}
			f.request, f.response, f.parts = "", "", nil
			f.env = map[string]value{}
			f.web = &webState{project: p, segments: map[string]nextSegment{}, framework: r.Framework, surface: "page"}
			f.context = append(f.context, hm.evidence("page_component", cres.fn))
			cparams := nextParams(cres.fn, hm.src)
			if len(cparams) > 0 {
				switch {
				case cparams[0].name != "":
					f.env[cparams[0].name] = props
				case cparams[0].fields != nil:
					for key, local := range cparams[0].fields {
						if v, ok := props.fields[key]; ok {
							f.env[local] = f.transfer(v, "page_props", cparams[0].node)
						} else {
							f.env[local] = value{}
						}
					}
				}
			}
			if cbody := cres.fn.ChildByFieldName("body"); cbody != nil {
				if cbody.Kind() == "statement_block" {
					f.statements(cbody)
				} else {
					f.eval(cbody)
				}
			}
		}
	}
	f.finishValidation()
	out.Uses = append(out.Uses, f.uses...)
	e.Gaps = append(e.Gaps, f.gaps[len(e.Gaps):]...)
	out.Entries[entryIndex].Gaps = e.Gaps
	noteHTTPDeclaration(out, r, context)
}

// serverReactState binds `const [x, setX] = useState(init)` during a server
// render: the rendered state is the initial value; setters run only in the
// browser and are not traversed here.
func (f *flow) serverReactState(d, pattern *sitter.Node) bool {
	if f.web == nil || f.web.surface != "page" || f.client != nil || pattern.Kind() != "array_pattern" {
		return false
	}
	init := unwrapTS(d.ChildByFieldName("value"))
	if init == nil || init.Kind() != "call_expression" {
		return false
	}
	hook := reactHook(f.module, init.ChildByFieldName("function"), "useState", "useReducer", "useTransition", "useOptimistic")
	if hook == "" {
		return false
	}
	initial := value{}
	if args := init.ChildByFieldName("arguments"); args != nil && args.NamedChildCount() > 0 && (hook == "useState" || hook == "useOptimistic") {
		if a := args.NamedChild(0); !isFunction(a) {
			initial = f.transfer(f.eval(a), "react_state", d)
		}
	}
	for i := uint(0); i < pattern.NamedChildCount(); i++ {
		if c := pattern.NamedChild(i); c.Kind() == "identifier" {
			if i == 0 {
				f.env[c.Utf8Text(f.module.src)] = initial
			} else {
				f.env[c.Utf8Text(f.module.src)] = value{}
			}
		}
	}
	return true
}
