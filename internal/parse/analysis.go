package parse

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
	"github.com/zazzcode/zazzles/internal/guidelines"
	"github.com/zazzcode/zazzles/internal/lang"
	"github.com/zazzcode/zazzles/internal/walk"
)

// Analyze resolves route and browser entries and extracts bounded security evidence.
// Entry limits registration files; dependency modules remain inside the target manifest.
func Analyze(root, entry string) (*analysis.AnalysisReport, error) {
	return AnalyzeWithChecks(root, entry, nil)
}

// AnalyzeWithChecks assembles security evidence with optional declared requirements.
func AnalyzeWithChecks(root, entry string, checks []analysis.Check) (*analysis.AnalysisReport, error) {
	return AnalyzeWithOptions(root, entry, checks, Options{})
}

// Options controls optional acquisition discovery without changing Python adapters.
type Options struct{ DiscoverRoutes bool }

// AnalyzeWithOptions shares the same parsed module set with optional discovery.
func AnalyzeWithOptions(root, entry string, checks []analysis.Check, options Options) (result *analysis.AnalysisReport, resultErr error) {
	defer func() {
		if resultErr == nil && result != nil {
			result.RecordCheckMatches(checks)
			for i := range result.Uses {
				analysispacks.Attach(&result.Uses[i])
			}
		}
	}()

	if err := analysispacks.Validate(); err != nil {
		return nil, err
	}
	entry = filepath.ToSlash(filepath.Clean(entry))
	if entry == "." {
		entry = ""
	}
	if strings.EqualFold(filepath.Ext(entry), ".py") {
		py, err := newPythonSet(root)
		if err != nil {
			return nil, err
		}
		defer py.close()
		return py.report(entry, checks)
	}
	files, err := walk.Walk(root, walk.Options{})
	if err != nil {
		return nil, err
	}
	ps, err := newParsers()
	if err != nil {
		return nil, err
	}
	set := &moduleSet{root: root, parsers: ps, modules: map[string]*sourceModule{}, allowed: map[string]bool{}}
	defer set.close()
	var selected []string
	for _, f := range files.Files {
		if f.Language == lang.JavaScript || f.Language == lang.TypeScript {
			set.allowed[f.Path] = true
			selected = append(selected, f.Path)
		}
	}
	if entry != "" {
		entry = filepath.ToSlash(filepath.Clean(entry))
		if !set.allowed[entry] {
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
	for _, file := range selected {
		m, err := set.load(file)
		if err != nil {
			return nil, err
		}
		if m.tree.RootNode().HasError() {
			out.Gaps = append(out.Gaps, analysis.Gap{Kind: "parse_error", Detail: "registration file has syntax errors", At: spanOf(file, m.tree.RootNode())})
			continue
		}
		if options.DiscoverRoutes {
			out.Discovery = set.nodeDiscoveryAlternatives(m, out.Discovery, 1000)
		}
		set.graphqlEntries(out, m)
		set.grpcEntries(out, m)
		set.nodeFrameworkEntries(out, m)
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
			if set.finiteRoutes(out, m, call, obj.Utf8Text(m.src)) {
				return
			}
			routes, _ := routesFromCall(file, m.src, call, locals)
			for _, r := range routes {
				set.analyzeRoute(out, m, m, r, call, obj.Utf8Text(m.src), nil, r.PathPattern, "")
			}
		})
	}
	set.mountedRoutes(out, selected)
	if err := set.browser(out); err != nil {
		return nil, err
	}
	set.registerRESTResources()
	set.linkStoredXSS(out)
	set.linkCrossTierXSS(out)
	set.linkTokenClaims(out)
	assembleXSSClaims(out)
	set.assembleCommandClaims(out)
	set.assemblePathClaims(out)
	// Check assembly rebuilds the use list for its own claim families; the
	// command and path claims are independent of explicit check files and are kept whole.
	var commandUses []analysis.CandidateUse
	rest := out.Uses[:0:0]
	for _, u := range out.Uses {
		if u.Kind == "command_execution_candidate" || u.Kind == "path_traversal_candidate" {
			commandUses = append(commandUses, u)
		} else {
			rest = append(rest, u)
		}
	}
	if len(checks) > 0 {
		out.Uses = rest
		set.buildChecks(out, checks)
		out.Uses = append(out.Uses, commandUses...)
	} else {
		set.automaticQueries(out)
	}
	set.assembleNodeInputs(out)
	keys := make([]string, 0, len(set.modules))
	for k := range set.modules {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		m := set.modules[k]
		out.Files = append(out.Files, m.evidence("file", m.tree.RootNode()))
	}
	textKeys := make([]string, 0, len(set.textSources))
	for key := range set.textSources {
		if set.modules[key] == nil {
			textKeys = append(textKeys, key)
		}
	}
	sort.Strings(textKeys)
	for _, key := range textKeys {
		e := set.textSources[key]
		e.Kind, e.Text = "file", ""
		out.Files = append(out.Files, e)
	}
	for _, item := range guidelines.ForPaths(keys) {
		out.AnalysisGuidelines = append(out.AnalysisGuidelines, analysis.GuidelinesRef{ID: item.ID, Version: item.Version, Languages: item.Languages})
	}
	if entry == "" {
		py, err := newPythonSet(root)
		if err != nil {
			return nil, err
		}
		defer py.close()
		more, err := py.report("", checks)
		if err != nil {
			return nil, err
		}
		out.MergeEntries(more)
		out.Uses = append(out.Uses, more.Uses...)
		out.Gaps = append(out.Gaps, more.Gaps...)
		out.Files = append(out.Files, more.Files...)
		if len(more.Entries) > 0 {
			out.Limitations = append(out.Limitations, more.Limitations...)
			out.AnalysisGuidelines = append(out.AnalysisGuidelines, more.AnalysisGuidelines...)
		}
	}
	if err := finalizeEntries(out); err != nil {
		return nil, err
	}
	return out, nil
}

func (m *sourceModule) evidence(kind string, n *sitter.Node) analysis.Evidence {
	if !m.commentsReady {
		m.comments = sourceComments(m.tree.RootNode(), m.src, false)
		m.commentsReady = true
	}
	modelText := ""
	if kind != "file" {
		modelText = modelSource(m.src, n.StartByte(), n.EndByte(), m.comments)
	}
	text := n.Utf8Text(m.src)
	if kind == "file" {
		text = ""
	}
	return analysis.Evidence{ModelText: modelText, Kind: kind, Text: text, Span: spanOf(m.file, n), SHA256: m.hash}
}

func (s *moduleSet) handler(m *sourceModule, n *sitter.Node) (*sourceModule, *sitter.Node, string, []analysis.Gap) {
	gaps := []analysis.Gap{}
	if n == nil {
		return nil, nil, "", []analysis.Gap{{Kind: "unresolved_handler", Detail: "no supported handler argument"}}
	}
	if n.Kind() == "call_expression" {
		fn := n.ChildByFieldName("function")
		args := n.ChildByFieldName("arguments")
		if fn != nil && fn.Kind() == "member_expression" && args != nil && args.NamedChildCount() == 1 {
			gaps = append(gaps, analysis.Gap{Kind: "unresolved_wrapper", Detail: "wrapper semantics not modeled", At: spanOf(m.file, n)})
			n = args.NamedChild(0)
		}
	}
	factory := n.Kind() == "call_expression"
	if factory {
		args := n.ChildByFieldName("arguments")
		if args == nil || args.NamedChildCount() != 0 {
			return nil, nil, "", append(gaps, analysis.Gap{Kind: "unresolved_factory", Detail: "factory arguments require parameter binding", At: spanOf(m.file, n)})
		}
		n = n.ChildByFieldName("function")
	}
	target := m
	if n != nil && (n.Kind() == "identifier" || n.Kind() == "member_expression") {
		name := n.Utf8Text(m.src)
		if shadowed(n, strings.Split(name, ".")[0], m.src) {
			return nil, nil, "", append(gaps, analysis.Gap{Kind: "unresolved_handler", Detail: "handler binding is shadowed", At: spanOf(m.file, n)})
		}
		target, n = s.resolve(m, name)
	}
	if target == nil || n == nil || (!isFunction(n) && n.Kind() != "function_declaration") {
		return nil, nil, "", append(gaps, analysis.Gap{Kind: "unresolved_handler", Detail: "handler is not a directly resolved function", At: spanOf(m.file, m.tree.RootNode())})
	}
	if target.tree.RootNode().HasError() {
		return nil, nil, "", append(gaps, analysis.Gap{Kind: "parse_error", Detail: "handler module has syntax errors", At: spanOf(target.file, n)})
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
						return nil, nil, "", append(gaps, analysis.Gap{Kind: "unresolved_factory", Detail: "multiple returned handlers", At: spanOf(target.file, body)})
					}
					returned = c.NamedChild(0)
				}
			}
		}
		n = returned
	}
	if n == nil {
		return nil, nil, "", append(gaps, analysis.Gap{Kind: "unresolved_factory", Detail: "no direct returned function", At: spanOf(target.file, target.tree.RootNode())})
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
		return target, n.ChildByFieldName("body"), "", append(gaps, analysis.Gap{Kind: "request_projection_unresolved", Detail: "request parameter uses an unsupported projection", At: spanOf(target.file, n)})
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
