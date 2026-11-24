// Package langjs is the JavaScript/TypeScript language adapter: Node HTTP
// frameworks (Express, Next.js), browser frameworks, GraphQL and gRPC entries,
// with bounded module, value and control flow. It builds the base report that
// parse.Assemble requires for a full scan, and it owns the browser bridge
// (AnalyzeInlineScripts) that internal/langpy uses for inline scripts in
// templates. It builds on the language core API exported by internal/parse
// (core_api.go). Run produces the JS/TS report and Routes the JS/TS part of the
// route inventory; only internal/pipeline calls them.
package langjs

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/guidelines"
	"github.com/zazzcode/zazzles/scan/internal/lang"
	"github.com/zazzcode/zazzles/scan/internal/parse"
)

// Run resolves JS/TS route and browser entries and extracts bounded
// security evidence. It always returns the base report with its fixed
// limitations; a repository with no JS/TS files opens no grammar and loads no
// module. A non-empty entry must be a normalized, selected JS/TS file.
func Run(inv parse.Inventory, entry string, checks []analysis.Check, options parse.Options) (*analysis.AnalysisReport, error) {
	set, selected, err := openJavaScriptSet(inv)
	if err != nil {
		return nil, err
	}
	defer set.close()
	return set.javascriptReport(selected, entry, checks, options)
}

// openJavaScriptSet allows the inventory's JS/TS files in walk order. It opens
// the grammars only when there is at least one such file.
func openJavaScriptSet(inv parse.Inventory) (*moduleSet, []string, error) {
	var ps *parsers
	if inv.HasLanguage(lang.JavaScript, lang.TypeScript) {
		var err error
		if ps, err = newParsers(); err != nil {
			return nil, nil, err
		}
	}
	set := &moduleSet{root: inv.Root, parsers: ps, modules: map[string]*sourceModule{}, allowed: map[string]bool{}}
	var selected []string
	for _, f := range inv.Files {
		if f.Language == lang.JavaScript || f.Language == lang.TypeScript {
			set.allowed[f.Path] = true
			selected = append(selected, f.Path)
		}
	}
	return set, selected, nil
}

func (s *moduleSet) javascriptReport(selected []string, entry string, checks []analysis.Check, options parse.Options) (*analysis.AnalysisReport, error) {
	root := s.root
	out0 := &analysis.AnalysisReport{}
	s.detectNextProjects(selected)
	if entry == "" {
		selected = s.applyNextScope(out0, selected)
	}
	if entry != "" {
		entry = filepath.ToSlash(filepath.Clean(entry))
		if !s.allowed[entry] {
			return nil, fmt.Errorf("entry must be a selected JS/TS file relative to target root: %s", entry)
		}
		selected = []string{entry}
	}
	out := &analysis.AnalysisReport{SchemaVersion: analysis.ReportSchemaVersion, Root: root, Entries: []analysis.EntryPoint{}, Uses: []analysis.CandidateUse{}, Gaps: []analysis.Gap{}, Files: []analysis.Evidence{}, Limitations: []string{
		"ESM relative imports, literal CommonJS requires and direct exported handlers are resolved; dynamic imports, re-exports and mutated module bindings remain uncertain",
		"Verified Express receiver construction and direct registrations required; chained routes, mount composition and effective middleware are not resolved",
		"Supported helpers bind identifier parameters and direct returns; finite literal tables and local literal-argument factories retain closure contexts. Unsupported branches/captures, wrappers, unknown calls, recursion and asynchronous continuations remain gaps",
		"SQL text, NoSQL $where strings, query documents, and request-field validation are candidate findings, not confirmed vulnerabilities",
	}}
	out.Gaps = append(out.Gaps, out0.Gaps...)
	for _, file := range selected {
		m, err := s.load(file)
		if err != nil {
			return nil, err
		}
		if m.tree.RootNode().HasError() {
			out.Gaps = append(out.Gaps, analysis.Gap{Kind: "parse_error", Detail: "registration file has syntax errors", At: parse.Span(file, m.tree.RootNode())})
			continue
		}
		if options.DiscoverRoutes {
			out.Discovery = s.nodeDiscoveryAlternatives(m, out.Discovery, 1000)
		}
		s.graphqlEntries(out, m)
		s.grpcEntries(out, m)
		s.nodeFrameworkEntries(out, m)
		if p := s.nextProjectFor(file); p != nil {
			s.nextRouteEntries(out, m, p)
			s.pagesAPIEntries(out, m, p)
			s.pagesPageEntries(out, m, p)
			s.nextPageEntries(out, m, p)
			s.nextActionEntries(out, m, p)
		}
		locals := map[string]*sitter.Node{}
		collectFuncs(m.tree.RootNode(), m.src, locals)
		walkCalls(m.tree.RootNode(), func(call *sitter.Node) {
			fn := call.ChildByFieldName("function")
			if fn == nil || fn.Kind() != "member_expression" {
				return
			}
			obj := fn.ChildByFieldName("object")
			if obj == nil || obj.Kind() != "identifier" || !m.receivers[obj.Utf8Text(m.src)] {
				return
			}
			if s.finiteRoutes(out, m, call, obj.Utf8Text(m.src)) {
				return
			}
			routes, _ := routesFromCall(file, m.src, call, locals)
			for _, r := range routes {
				s.analyzeRoute(out, m, m, r, call, obj.Utf8Text(m.src), nil, r.PathPattern, "")
			}
		})
	}
	s.mountedRoutes(out, selected)
	s.pathConfiguredMounts(out, selected)
	s.exposureCandidates(out, selected)
	s.configurationCandidates(out, selected)
	s.passwordHashCandidates(out, selected)
	s.enumerationCandidates(out)
	s.authorizationCandidates(out)
	if err := s.browser(out); err != nil {
		return nil, err
	}
	s.registerRESTResources()
	s.linkStoredXSS(out)
	// After stored links, so an own-API stored row is not read as linked.
	s.linkOwnAPIOrigins(out)
	s.linkCrossTierXSS(out)
	s.linkTokenClaims(out)
	parse.AssembleXSSClaims(out)
	s.attachStoredWriteSets(out)
	s.assembleCommandClaims(out)
	s.assemblePathClaims(out)
	s.assembleSSRFClaims(out)
	s.assembleInterpreterClaims(out)
	s.assemblePollutionClaims(out)
	// Check assembly rebuilds the use list for its own claim families; the
	// command and path claims are independent of explicit check files and are kept whole.
	var commandUses []analysis.CandidateUse
	rest := out.Uses[:0:0]
	for _, u := range out.Uses {
		if u.Kind == "command_execution_candidate" || u.Kind == "path_traversal_candidate" || u.Kind == "ssrf_candidate" || u.Code != nil || u.Redirect != nil || u.Pollution != nil {
			commandUses = append(commandUses, u)
		} else {
			rest = append(rest, u)
		}
	}
	if len(checks) > 0 {
		out.Uses = rest
		s.buildChecks(out, checks)
		out.Uses = append(out.Uses, commandUses...)
	} else {
		s.automaticQueries(out)
	}
	s.assembleNodeInputs(out)
	s.nextPractice(out, selected)
	keys := make([]string, 0, len(s.modules))
	for k := range s.modules {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		m := s.modules[k]
		out.Files = append(out.Files, m.evidence("file", m.tree.RootNode()))
	}
	for _, key := range s.texts().Files() {
		if s.modules[key] != nil {
			continue
		}
		e, _ := s.texts().Get(key)
		e.Kind, e.Text = "file", ""
		out.Files = append(out.Files, e)
	}
	for _, item := range guidelines.ForPaths(keys) {
		out.AnalysisGuidelines = append(out.AnalysisGuidelines, analysis.GuidelinesRef{ID: item.ID, Version: item.Version, Languages: item.Languages})
	}
	return out, nil
}

func (m *sourceModule) evidence(kind string, n *sitter.Node) analysis.Evidence {
	if !m.commentsReady {
		m.comments = parse.SourceComments(m.tree.RootNode(), m.src, false)
		m.commentsReady = true
	}
	modelText := ""
	if kind != "file" {
		modelText = parse.ModelSource(m.src, n.StartByte(), n.EndByte(), m.comments)
	}
	text := n.Utf8Text(m.src)
	if kind == "file" {
		text = ""
	}
	return analysis.Evidence{ModelText: modelText, Kind: kind, Text: text, Span: parse.Span(m.file, n), SHA256: m.hash}
}

func (s *moduleSet) handler(m *sourceModule, n *sitter.Node) (*sourceModule, *sitter.Node, string, []analysis.Gap) {
	gaps := []analysis.Gap{}
	if n == nil {
		return nil, nil, "", []analysis.Gap{{Kind: "unresolved_handler", Detail: "no supported handler argument"}}
	}
	unwrapped := false
	if n.Kind() == "call_expression" {
		fn, args := n.ChildByFieldName("function"), n.ChildByFieldName("arguments")
		if args != nil && args.NamedChildCount() == 1 {
			if _, ok := s.transparentWrapper(m, n); ok {
				n = args.NamedChild(0)
				unwrapped = true
			} else if fn != nil && fn.Kind() == "member_expression" && handlerArgument(args.NamedChild(0)) {
				gaps = append(gaps, analysis.Gap{Kind: "unresolved_wrapper", Detail: "wrapper semantics not modeled", At: parse.Span(m.file, n)})
				n = args.NamedChild(0)
			}
		}
	}
	factory := n.Kind() == "call_expression"
	if factory {
		args := n.ChildByFieldName("arguments")
		if args == nil || args.NamedChildCount() != 0 {
			return nil, nil, "", append(gaps, analysis.Gap{Kind: "unresolved_factory", Detail: "factory arguments require parameter binding", At: parse.Span(m.file, n)})
		}
		n = n.ChildByFieldName("function")
	}
	target := m
	if n != nil && (n.Kind() == "identifier" || n.Kind() == "member_expression") {
		name := n.Utf8Text(m.src)
		if unwrapped && !contractBindingStable(m, strings.Split(name, ".")[0], n) {
			return nil, nil, "", append(gaps, analysis.Gap{Kind: "unresolved_handler", Detail: "wrapped handler binding is mutable or escapes", At: parse.Span(m.file, n)})
		}
		if shadowed(n, strings.Split(name, ".")[0], m.src) {
			return nil, nil, "", append(gaps, analysis.Gap{Kind: "unresolved_handler", Detail: "handler binding is shadowed", At: parse.Span(m.file, n)})
		}
		target, n = s.resolve(m, name)
	}
	if target == nil || n == nil || (!isFunction(n) && n.Kind() != "function_declaration" && n.Kind() != "method_definition") {
		return nil, nil, "", append(gaps, analysis.Gap{Kind: "unresolved_handler", Detail: "handler is not a directly resolved function", At: parse.Span(m.file, m.tree.RootNode())})
	}
	if target.tree.RootNode().HasError() {
		return nil, nil, "", append(gaps, analysis.Gap{Kind: "parse_error", Detail: "handler module has syntax errors", At: parse.Span(target.file, n)})
	}
	if unwrapped && factory && asyncFunction(n) {
		return nil, nil, "", append(gaps, analysis.Gap{Kind: "unresolved_factory", Detail: "async factory returns a promise rather than a handler", At: parse.Span(target.file, n)})
	}
	if unwrapped && !stableFunctionBinding(target, n) {
		return nil, nil, "", append(gaps, analysis.Gap{Kind: "unresolved_handler", Detail: "wrapped callable binding is mutable", At: parse.Span(target.file, n)})
	}
	if factory {
		body := n.ChildByFieldName("body")
		var returned *sitter.Node
		if body != nil && isFunction(body) {
			returned = body
		}
		// `() => handler` returns a named function of the same module.
		if body != nil && body.Kind() == "identifier" {
			if hm, fn := s.resolve(target, body.Utf8Text(target.src)); hm == target && fn != nil && supportedCallee(fn) {
				returned = fn
			}
		}
		if body != nil && !isFunction(body) {
			for i := uint(0); i < body.NamedChildCount(); i++ {
				c := body.NamedChild(i)
				if c.Kind() == "return_statement" && c.NamedChildCount() == 1 && isFunction(c.NamedChild(0)) {
					if returned != nil {
						return nil, nil, "", append(gaps, analysis.Gap{Kind: "unresolved_factory", Detail: "multiple returned handlers", At: parse.Span(target.file, body)})
					}
					returned = c.NamedChild(0)
				}
			}
		}
		n = returned
	}
	if n == nil {
		return nil, nil, "", append(gaps, analysis.Gap{Kind: "unresolved_factory", Detail: "no direct returned function", At: parse.Span(target.file, target.tree.RootNode())})
	}
	if unwrapped && !stableFunctionBinding(target, n) {
		return nil, nil, "", append(gaps, analysis.Gap{Kind: "unresolved_handler", Detail: "returned handler binding is mutable", At: parse.Span(target.file, n)})
	}
	params := n.ChildByFieldName("parameters")
	req := ""
	if params != nil && params.NamedChildCount() > 0 {
		p := params.NamedChild(0)
		if p.Kind() == "required_parameter" || p.Kind() == "optional_parameter" {
			p = p.ChildByFieldName("pattern")
		}
		if p != nil && p.Kind() == "identifier" {
			req = p.Utf8Text(target.src)
		}
	}
	if req == "" {
		return target, n.ChildByFieldName("body"), "", append(gaps, analysis.Gap{Kind: "request_projection_unresolved", Detail: "request parameter uses an unsupported projection", At: parse.Span(target.file, n)})
	}
	return target, n.ChildByFieldName("body"), req, gaps
}

func shadowed(call *sitter.Node, name string, src []byte) bool {
	for p := call.Parent(); p != nil; p = p.Parent() {
		params := p.ChildByFieldName("parameters")
		if params != nil {
			for i := uint(0); i < params.NamedChildCount(); i++ {
				param := params.NamedChild(i)
				if param.Kind() == "required_parameter" || param.Kind() == "optional_parameter" {
					param = param.ChildByFieldName("pattern")
				}
				if param != nil && param.Kind() == "identifier" && param.Utf8Text(src) == name {
					return true
				}
			}
		}
		if p.Kind() == "statement_block" {
			for i := uint(0); i < p.NamedChildCount(); i++ {
				d := p.NamedChild(i)
				if d.Kind() != "lexical_declaration" && d.Kind() != "variable_declaration" {
					continue
				}
				for j := uint(0); j < d.NamedChildCount(); j++ {
					n := d.NamedChild(j).ChildByFieldName("name")
					if n != nil && n.Utf8Text(src) == name {
						return true
					}
				}
			}
		}
	}
	return false
}

// parameterReceiver accepts a declared function's receiver parameter only when a
// same-module call supplies a module-level Express receiver at that position.
func parameterReceiver(m *sourceModule, call *sitter.Node, receiver string) bool {
	for p := call.Parent(); p != nil; p = p.Parent() {
		params := p.ChildByFieldName("parameters")
		if params == nil {
			continue
		}
		name := p.ChildByFieldName("name")
		if p.Kind() != "function_declaration" || name == nil {
			return false
		}
		declared := m.funcs[name.Utf8Text(m.src)]
		if declared == nil || declared.StartByte() != p.StartByte() {
			return false
		}
		pos := -1
		for i := uint(0); i < params.NamedChildCount(); i++ {
			v := params.NamedChild(i)
			if v.Kind() == "required_parameter" || v.Kind() == "optional_parameter" {
				v = v.ChildByFieldName("pattern")
			}
			if v != nil && v.Kind() == "identifier" && v.Utf8Text(m.src) == receiver {
				pos = int(i)
			}
		}
		if pos < 0 {
			return false
		}
		found := false
		walkCalls(m.tree.RootNode(), func(site *sitter.Node) {
			fn := site.ChildByFieldName("function")
			args := site.ChildByFieldName("arguments")
			if fn == nil || fn.Kind() != "identifier" || fn.Utf8Text(m.src) != name.Utf8Text(m.src) || args == nil || args.NamedChildCount() <= uint(pos) {
				return
			}
			arg := args.NamedChild(uint(pos))
			if arg.Kind() == "identifier" && m.receivers[arg.Utf8Text(m.src)] && !shadowed(site, arg.Utf8Text(m.src), m.src) {
				found = true
			}
		})
		return found
	}
	return false
}
