package langpy

import (
	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
	"github.com/zazzcode/zazzles/scan/internal/parse"
	"strings"
)

func (f *pythonFlow) interpreterOperation(n, fn *sitter.Node, nodes []*sitter.Node, values []pythonValue) {
	name := pyText(f.module, fn)
	q := f.qualified(name)
	root := strings.Split(name, ".")[0]
	if _, shadow := f.env[root]; shadow {
		return
	}
	if f.set.staticInvalid[f.module.file+":"+root] {
		return
	}
	family, contract, keyword := "", "", ""
	if (name == "eval" || name == "exec" || name == "compile") && (q == name || q == "") && f.module.imports[root].module == "" && f.module.vars[root] == nil && f.module.funcs[root] == nil {
		family, contract, keyword = "code", "python-eval-v1", "source"
		q = name
	}
	switch q {
	case "jinja2.Template", "jinja2.environment.Template", "flask.render_template_string", "mako.template.Template":
		// Template source compiled by a verified engine (close-findings-gaps D-24).
		family, contract, keyword = "code", "python-template-source-v1", "source"
		if q == "mako.template.Template" {
			keyword = "text"
		}
	case "flask.redirect", "django.shortcuts.redirect", "django.http.HttpResponseRedirect", "django.http.HttpResponsePermanentRedirect", "starlette.responses.RedirectResponse", "fastapi.responses.RedirectResponse", "aiohttp.web.HTTPFound", "aiohttp.web.HTTPMovedPermanently", "aiohttp.web.HTTPSeeOther":
		family, contract, keyword = "redirect", "python-redirect-v1", "url"
	}
	if family == "" {
		return
	}
	if family == "redirect" {
		switch q {
		case "flask.redirect", "aiohttp.web.HTTPFound", "aiohttp.web.HTTPMovedPermanently", "aiohttp.web.HTTPSeeOther":
			keyword = "location"
		case "django.shortcuts.redirect":
			keyword = "to"
		case "django.http.HttpResponseRedirect", "django.http.HttpResponsePermanentRedirect":
			keyword = "redirect_to"
		}
	}
	if family == "code" && len(nodes) == 0 && name != "compile" {
		return
	}

	var arg *sitter.Node
	var operand pythonValue
	if len(nodes) > 0 {
		arg, operand = nodes[0], values[0]
	} else {
		arg = pyKeywordIn(f.module, n, keyword)
		if arg != nil {
			operand = f.quiet(arg)
		}
	}
	if arg == nil || len(operand.deps) == 0 {
		return
	}
	f.pythonInterpreter(n, q, fn, operand, family, contract)
}

func (f *pythonFlow) pythonInterpreter(n *sitter.Node, q string, fn *sitter.Node, destination pythonValue, family, contract string) {
	m := f.module
	kind, slot := "code_execution_candidate", "code"
	if family == "redirect" {
		kind, slot = "open_redirect_candidate", "destination"
	}
	execution := "server"
	if contract == "python-template-source-v1" {
		kind, execution = analysispacks.TemplateKind, "template_engine"
	}
	u := f.addUse(kind, n, destination)
	paths := []analysis.CommandPath{}
	for i := range u.Dependencies {
		u.Dependencies[i].SinkSlot = slot
		paths = append(paths, analysis.CommandPath{Dependency: i, Operand: slot})
	}
	if family == "code" {
		u.Code = &analysis.CodeFacts{Operation: q, ContractID: contract, ExecutionContext: execution, Shape: "whole_program", Paths: paths}
		u.APIModel = analysispacks.CodeContract(contract)
	} else {
		u.Redirect = &analysis.RedirectFacts{Operation: q, ContractID: contract, DestinationOrigin: analysis.DestinationRequest, Paths: paths}
		u.APIModel = analysispacks.RedirectContract(contract)
	}
	u.Context = append(u.Context, m.evidence("sink_binding", fn))
	guards, guardIndex, derived, names := f.pythonOperandGuards(u, n)
	f.completePythonOperandClaim(u, n, destination, guards, guardIndex, derived, names, func(u *analysis.CandidateUse, extra map[string][]analysis.Evidence, blockers, coverage []analysis.Gap) *analysis.Completeness {
		c := parse.SSRFCompleteness(u, extra, blockers, coverage)
		c.ClaimKind = family
		c.Required = []string{"input_source", "sink_binding", "invoked_callable", "control_flow", family + "_operand"}
		c.Evidence[family+"_operand"] = []analysis.Evidence{u.Sink}
		c.Scope = family + " operand claim"
		return c
	}, u.CodePaths())
}

func (f *pythonFlow) pythonOperandGuards(u *analysis.CandidateUse, n *sitter.Node) ([]analysis.Evidence, []int, [][]string, map[string]bool) {
	m := f.module
	names := map[string]bool{}
	for _, d := range u.Dependencies {
		for _, name := range parse.CommandDepNames(d) {
			names[name] = true
		}
	}
	mentions := func(text string) bool {
		for name := range names {
			if name != "" && name != "." && strings.Contains(text, name) {
				return true
			}
		}
		return false
	}
	list := make([]string, 0, len(names))
	for name := range names {
		list = append(list, name)
	}
	var guards []analysis.Evidence
	guardIndex := []int{}
	for _, e := range f.context {
		if (e.Kind == "branch_precondition" || e.Kind == "branch_false_precondition") && mentions(e.Text) && !parse.PresenceOnlyCondition(e.Text, list) {
			guardIndex = append(guardIndex, len(u.Context))
			u.Context = append(u.Context, e)
			guards = append(guards, e)
		}
	}
	scan := parse.NewCommandGuardScan(f.guardLang(), n, f.pyHelperCallSites)
	for _, site := range scan.Collect(nil, u.Dependencies, func(site parse.GuardSite) bool {
		return site.Kind == parse.TerminatingGuardKind && !guardRecorded(guards, m.evidence(site.Kind, site.Cond))
	}) {
		ev := m.evidence(parse.CommandGuardEvidenceKind(site), site.Whole)
		if !guardRecorded(guards, ev) {
			guardIndex = append(guardIndex, len(u.Context))
			u.Context = append(u.Context, ev)
			guards = append(guards, ev)
		}
	}
	var conditions []*sitter.Node
	for _, g := range guards {
		if c := parse.NodeAt(m.tree.RootNode(), g.Span.StartByte, g.Span.EndByte); c != nil {
			if c.Kind() == "if_statement" {
				c = c.ChildByFieldName("condition")
			}
			if c != nil {
				conditions = append(conditions, c)
			}
		}
	}
	for _, decl := range parse.CollectionDefinitions(conditions, m.src, func(name string) *sitter.Node {
		if pyConstantCollection(m, name) {
			return pyModuleVarDecl(m, name)
		}
		return nil
	}) {
		u.Context = append(u.Context, m.evidence("allowlist_definition", decl))
	}
	return guards, guardIndex, scan.Derived(u.Dependencies), names
}
