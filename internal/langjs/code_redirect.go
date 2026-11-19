package langjs

import (
	"fmt"
	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
	"github.com/zazzcode/zazzles/internal/parse"
	"strings"
)

func (f *flow) interpreterCall(call, fn, args *sitter.Node) {
	if fn == nil || args == nil || args.NamedChildCount() == 0 {
		return
	}
	m := f.module
	name := fn.Utf8Text(m.src)
	root := strings.Split(name, ".")[0]
	if unwrapped := unwrapTS(fn); unwrapped != nil && unwrapped.Kind() == "sequence_expression" && unwrapped.NamedChildCount() == 2 {
		last := unwrapped.NamedChild(1)
		if last.Kind() == "identifier" && last.Utf8Text(m.src) == "eval" {
			name, root = "eval", "eval"
		}
	}

	if interpreterMemberMutated(m, name) {
		return
	}
	unshadowed := func() bool {
		return !shadowed(call, root, m.src) && !topLevelBinding(m, root) && !bindingReassigned(m, root)
	}
	response := f.response
	if response == "" {
		response = f.redirectResponse
	}
	contract, slot := "", 0
	switch {
	case (name == "eval" || name == "globalThis.eval" || name == "window.eval" || name == "(0, eval)") && unshadowed():
		contract = "js-eval-v1"
	case (name == "Function" || name == "globalThis.Function" || name == "window.Function") && unshadowed():
		contract = "js-function-constructor-v1"
	case f.client != nil && (name == "setTimeout" || name == "setInterval" || name == "window.setTimeout" || name == "window.setInterval" || name == "setImmediate" || name == "window.setImmediate") && unshadowed():
		if isFunction(unwrapTS(args.NamedChild(0))) {
			return
		}
		if arg := args.NamedChild(0); arg.Kind() == "identifier" {
			if def := localInitializer(m, call, arg.Utf8Text(m.src)); def != nil && isFunction(unwrapTS(def)) {
				return
			}
		}
		contract = "js-timer-string-v1"
	}
	binding := []analysis.Evidence{m.evidence("sink_binding", fn)}
	if imp, ok := m.imports[root]; ok && (imp.module == "vm" || imp.module == "node:vm" || imp.module == "notevil" || imp.module == "safe-eval" || imp.module == "vm2" || imp.module == "static-eval" || imp.module == "expr-eval" || imp.module == "mathjs") && !shadowed(call, root, m.src) && !bindingReassigned(m, root) {
		op := imp.name
		if len(strings.Split(name, ".")) == 2 {
			op = strings.Split(name, ".")[1]
		}
		if (imp.module == "vm" || imp.module == "node:vm") && (len(strings.Split(name, ".")) == 1 && imp.name == op || len(strings.Split(name, ".")) == 2 && (imp.name == "default" || imp.name == "*")) && containsString([]string{"runInThisContext", "runInNewContext", "runInContext", "Script", "compileFunction", "SourceTextModule"}, op) {
			contract = "node-vm-v1"
			binding = append(binding, m.evidence("sink_binding", imp.declaration))
		}
		if (imp.module == "notevil" || imp.module == "safe-eval" || imp.module == "static-eval") && len(strings.Split(name, ".")) == 1 && (imp.name == "default" || imp.name == "*" || imp.module == "notevil" && imp.name == "eval") || imp.module == "mathjs" && op == "evaluate" || imp.module == "expr-eval" && op == "evaluate" {
			contract = "js-safe-eval-libs-v1"
			binding = append(binding, m.evidence("sink_binding", imp.declaration))
		}
	}
	if contract == "" && f.client == nil {
		if op, ok := templateEngineCall(m, call, name, root); ok {
			binding = append(binding, m.evidence("sink_binding", m.imports[root].declaration))
			f.recordInterpreter(call, args.NamedChild(0), f.eval(args.NamedChild(0)), "template", op, "js-template-source-v1", binding, 0)
			return
		}
	}
	if contract == "" {
		if bindings := sandboxInstanceBinding(m, call, fn); len(bindings) > 0 {
			contract = "js-safe-eval-libs-v1"
			binding = bindings
		}
	}
	if contract == "node-vm-v1" && f.vmSandboxEvaluator(call, args, binding) {
		return
	}
	if contract != "" {
		count := uint(1)
		if contract == "js-function-constructor-v1" {
			count = args.NamedChildCount()
		}
		for i := uint(0); i < count; i++ {
			f.recordInterpreter(call, args.NamedChild(i), f.eval(args.NamedChild(i)), "code", name, contract, binding, int(i))
		}
		return
	}
	contract = ""
	if fn.Kind() == "member_expression" {
		obj, prop := fn.ChildByFieldName("object"), fn.ChildByFieldName("property")
		if obj != nil && prop != nil {
			recv, method := obj.Utf8Text(m.src), prop.Utf8Text(m.src)
			if recv == response && response != "" && (method == "redirect" || method == "location") {
				contract = "express-redirect-v1"
				if f.entry.HTTP != nil {
					switch f.entry.HTTP.Framework {
					case "fastify":
						contract = "fastify-redirect-v1"
					case "hapi":
						contract = "hapi-redirect-v1"
					}
				}
				if method == "redirect" && args.NamedChildCount() > 1 && args.NamedChild(0).Kind() == "number" {
					slot = 1
				}
			}
			if recv == response && response != "" && method == "writeHead" && args.NamedChildCount() >= 2 {
				status := args.NamedChild(0).Utf8Text(m.src)
				if len(status) == 3 && status[0] == '3' {
					headers := args.NamedChild(1)
					destination := property(headers, "Location", m.src)
					if destination == nil {
						destination = property(headers, "location", m.src)
					}
					if destination != nil {
						f.recordInterpreter(call, destination, f.eval(destination), "redirect", name, "node-location-header-v1", binding, 1)
					}
				}
				return
			}
			if recv == response && response != "" && (method == "setHeader" || method == "header" || method == "set") && args.NamedChildCount() > 1 {
				header, _ := stringLiteral(args.NamedChild(0), m.src)
				if strings.EqualFold(header, "Location") && redirectStatusBefore(m, call, response) {
					contract = "node-location-header-v1"
					slot = 1
				}
			}
			if imp, ok := m.imports[recv]; ok && imp.module == "next/server" && imp.name == "NextResponse" && method == "redirect" && !shadowed(call, recv, m.src) {
				contract = "next-redirect-v1"
				binding = append(binding, m.evidence("sink_binding", imp.declaration))
			}
			if f.client != nil && ((recv == "location" || recv == "window.location") && (method == "assign" || method == "replace") || recv == "window" && method == "open") && unshadowed() {
				contract = "browser-navigation-v1"
			}
			if f.client != nil && (method == "push" || method == "replace") && f.env[recv].web == "nextRouter" {
				contract = "browser-navigation-v1"
			}
		}
	}
	if imp, ok := m.imports[name]; ok && imp.module == "next/navigation" && (imp.name == "redirect" || imp.name == "permanentRedirect") && !shadowed(call, name, m.src) {
		contract = "next-redirect-v1"
		binding = append(binding, m.evidence("sink_binding", imp.declaration))
	}
	if contract != "" && slot < int(args.NamedChildCount()) {
		arg := args.NamedChild(uint(slot))
		v := f.eval(arg)
		if text, ok := stringLiteral(arg, m.src); ok && text == "back" && contract == "express-redirect-v1" {
			v = value{deps: []analysis.Dependency{{Source: m.evidence("input_source", arg)}}}
		}
		f.recordInterpreter(call, arg, v, "redirect", name, contract, binding, slot)
	}
}

func containsString(items []string, want string) bool {
	for _, v := range items {
		if v == want {
			return true
		}
	}
	return false
}

func redirectStatusBefore(m *sourceModule, call *sitter.Node, response string) bool {
	status := ""
	// Only preceding statements in the same block dominate this write. The last
	// response status wins; a conditional status change makes it unknown.
	for parent := call.Parent(); parent != nil; parent = parent.Parent() {
		if parent.Kind() != "statement_block" {
			continue
		}
		for i := uint(0); i < parent.NamedChildCount(); i++ {
			st := parent.NamedChild(i)
			if st.EndByte() > call.StartByte() {
				break
			}
			if !strings.Contains(st.Utf8Text(m.src), response+".status") {
				continue
			}
			status = ""
			if st.Kind() != "expression_statement" || st.NamedChildCount() != 1 {
				continue
			}
			expr := st.NamedChild(0)
			if expr.Kind() == "call_expression" {
				fn, args := expr.ChildByFieldName("function"), expr.ChildByFieldName("arguments")
				if fn != nil && args != nil && args.NamedChildCount() == 1 && fn.Utf8Text(m.src) == response+".status" {
					status = args.NamedChild(0).Utf8Text(m.src)
				}
			}
			if expr.Kind() == "assignment_expression" {
				l, r := expr.ChildByFieldName("left"), expr.ChildByFieldName("right")
				if l != nil && r != nil && l.Utf8Text(m.src) == response+".statusCode" {
					status = r.Utf8Text(m.src)
				}
			}
		}
		break
	}
	return len(status) == 3 && status[0] == '3'
}

func (f *flow) recordInterpreter(call, arg *sitter.Node, v value, family, op, contract string, binding []analysis.Evidence, operand int) {
	if len(v.deps) == 0 {
		return
	}
	if family == "redirect" && f.fixedLiteralRedirect(arg) {
		return
	}
	kind, slot := "code_execution_candidate", "code"
	if family == "redirect" {
		kind, slot = "open_redirect_candidate", "destination"
	}
	if family == "template" {
		kind, family = analysispacks.TemplateKind, "code"
	}
	deps := append([]analysis.Dependency{}, v.deps...)
	paths := make([]analysis.CommandPath, 0, len(deps))
	for i := range deps {
		deps[i].SinkSlot = slot
		paths = append(paths, analysis.CommandPath{Dependency: i, Operand: slot})
	}
	context := append([]analysis.Evidence{}, f.context...)
	context = append(context, binding...)
	if f.client != nil {
		for parent := call.Parent(); parent != nil; parent = parent.Parent() {
			if isFunction(parent) || parent.Kind() == "function_declaration" {
				if body := parent.ChildByFieldName("body"); body != nil {
					context = append(context, f.module.evidence("handler", body))
				}
				break
			}
		}
	}
	u := analysis.CandidateUse{ID: fmt.Sprintf("use:%s:%s:%d:%s:%d", f.invocation.ID, f.module.file, call.StartByte(), family, operand), EntryID: f.entry.ID, EntryKind: f.entry.Kind, InvocationContextID: f.invocation.ID, Kind: kind, Sink: f.module.evidence(kind, call), Dependencies: deps, Context: context, Gaps: append(append([]analysis.Gap{}, f.gaps...), v.gaps...), Assessment: analysis.Assessment{Status: "not_run"}}
	if family == "code" {
		execution := "server"
		if f.client != nil {
			execution = "browser"
		}
		if kind == analysispacks.TemplateKind {
			execution = "template_engine"
		}
		u.Code = &analysis.CodeFacts{Operation: op, ContractID: contract, ExecutionContext: execution, Shape: codeOperandShape(f.module, arg), Constraint: codeOperandConstraint(f.module, arg, 0), Paths: paths}
	} else {
		u.Redirect = &analysis.RedirectFacts{Operation: op, ContractID: contract, DestinationOrigin: analysis.DestinationRequest, Paths: paths}
	}
	f.uses = append(f.uses, u)
}

func (f *flow) fixedLiteralRedirect(n *sitter.Node) bool {
	return f.fixedLiteralPrefixRedirect(n) || f.fixedOriginDestination(n, 0)
}

func (f *flow) fixedLiteralPrefixRedirect(n *sitter.Node) bool {
	n = unwrapTS(n)
	if n == nil {
		return false
	}
	if n.Kind() == "identifier" {
		if bindingReassigned(f.module, n.Utf8Text(f.module.src)) {
			return false
		}
		n = unwrapTS(localInitializer(f.module, n, n.Utf8Text(f.module.src)))
		if n == nil {
			return false
		}
	}
	prefix := ""
	if n.Kind() == "template_string" && n.NamedChildCount() > 0 && n.NamedChild(0).Kind() == "string_fragment" {
		prefix = n.NamedChild(0).Utf8Text(f.module.src)
	}
	if n.Kind() == "binary_expression" {
		prefix, _ = stringLiteral(n.ChildByFieldName("left"), f.module.src)
	}
	if strings.HasPrefix(prefix, "?") || strings.HasPrefix(prefix, "#") {
		return true
	}
	if len(prefix) > 1 && prefix[0] == '/' && prefix[1] != '/' && prefix[1] != '\\' {
		return true
	}
	i := strings.Index(prefix, "://")
	return i > 0 && strings.Contains(prefix[i+3:], "/")
}

func (s *moduleSet) assembleInterpreterClaims(report *analysis.AnalysisReport) {
	for _, kind := range []string{"code_execution_candidate", "open_redirect_candidate", analysispacks.TemplateKind} {
		family := "code"
		if kind == "open_redirect_candidate" {
			family = "redirect"
		}
		s.assembleClaims(report, claimHooks{
			chainGapCovered: func(u *analysis.CandidateUse, g analysis.Gap) bool {
				if g.Kind == "request_projection_unresolved" {
					if ctx := s.nodeHTTP[u.EntryID]; ctx != nil {
						params := nextParams(ctx.body.Parent(), ctx.handler.src)
						if len(params) > 0 && len(params[0].fields) > 0 {
							for key := range params[0].fields {
								if !containsString([]string{"query", "body", "payload", "params", "cookies", "headers"}, key) {
									return false
								}
							}
							return true
						}
					}
				}
				if g.Kind != "input_helper_unresolved" {
					return false
				}
				m := s.modules[g.At.File]
				if m == nil {
					return false
				}
				n := parse.NodeAt(m.tree.RootNode(), g.At.StartByte, g.At.EndByte)
				if n == nil {
					return false
				}
				fn := n.ChildByFieldName("function")
				if fn != nil && fn.Kind() == "member_expression" {
					obj, prop := fn.ChildByFieldName("object"), fn.ChildByFieldName("property")
					if obj != nil && prop != nil && obj.Kind() == "regex" && prop.Utf8Text(m.src) == "test" {
						return true
					}
				}
				return s.verifiedInterpreterSink(m, n)
			},
			kind: kind, checkID: "automatic-" + family, checkKind: family, chainEvidence: s.interpreterChainEvidence,
			present: func(u *analysis.CandidateUse) bool { return u.Code != nil || u.Redirect != nil }, fields: commandFields, guards: s.interpreterGuards,
			gapCovered: func(u *analysis.CandidateUse, g analysis.Gap, complete bool, bodies, transforms []analysis.Evidence, extra map[string][]analysis.Evidence) bool {
				if g.Kind == "input_helper_unresolved" {
					m := s.modules[g.At.File]
					if m != nil {
						n := parse.NodeAt(m.tree.RootNode(), g.At.StartByte, g.At.EndByte)
						if n != nil && s.verifiedInterpreterSink(m, n) {
							return true
						}
					}
				}
				return s.commandGapCovered(u, g, complete, bodies, transforms, extra)
			},
			complete: func(u *analysis.CandidateUse, extra map[string][]analysis.Evidence, blockers, coverage []analysis.Gap) *analysis.Completeness {
				c := parse.SSRFCompleteness(u, extra, blockers, coverage)
				c.ClaimKind = family
				c.Scope = family + " claim over the verified operand and independent source paths"
				c.Required = []string{"input_source", "sink_binding", "invoked_callable", "control_flow", family + "_operand"}
				c.Evidence[family+"_operand"] = []analysis.Evidence{u.Sink}
				delete(c.Evidence, "destination_operand")
				return c
			},
			finish: func(u *analysis.CandidateUse, c *analysis.Completeness, guards []analysis.Evidence, indices []int) {
				paths := u.CodePaths()
				parse.FinishOperandPaths(u, paths, c, guards, indices, s.commandDerivedNames(u), func(g analysis.Gap, d analysis.Dependency) bool { return parse.GapTouchesDependency(g, d) })
				if u.Code != nil {
					if u.Code.Constraint != "" {
						c.Evidence["code_constrained_operand"] = []analysis.Evidence{u.Sink}
					}
					if u.Code.ContractID == "node-vm-v1" {
						c.ModelFacts = append(c.ModelFacts, "vm_not_security_boundary")
					}
					if u.Code.Shape == "inside_string_literal" {
						c.ModelFacts = append(c.ModelFacts, "code_inside_string_literal")
					}
					if u.Code.ContractID == "js-safe-eval-libs-v1" {
						for _, binding := range c.Evidence["sink_binding"] {
							if strings.Contains(binding.Text, "notevil") {
								c.ModelFacts = append(c.ModelFacts, "sandbox_library_advisory: notevil CVE-2021-23771 / GHSA-8g4m-cjm2-96wq; sandbox escape")
								break
							}
						}
					}
				}
				if u.Redirect != nil {
					s.redirectRestrictionEvidence(u, c)
					s.redirectHelperRestrictions(u, c)
					s.redirectPredicateFacts(u, c)
					if strings.Contains(u.Sink.Text, "'back'") || strings.Contains(u.Sink.Text, `"back"`) {
						c.ModelFacts = append(c.ModelFacts, "redirect_back_referer")
					}
					if s.urlSchemeOnlyTests(u, c) {
						c.ModelFacts = append(c.ModelFacts, "url_scheme_only_test")
					}
				}
			},
			contract: func(u *analysis.CandidateUse) *analysis.APIModel {
				if u.Code != nil {
					return analysispacks.CodeContract(u.Code.ContractID)
				}
				return analysispacks.RedirectContract(u.Redirect.ContractID)
			}, resolve: s.resolveGuardedControlFlow,
		})
	}
}

func (s *moduleSet) verifiedInterpreterSink(m *sourceModule, call *sitter.Node) bool {
	fn := call.ChildByFieldName("function")
	if fn == nil {
		return false
	}
	name := fn.Utf8Text(m.src)
	root := strings.Split(name, ".")[0]
	if shadowed(call, root, m.src) || bindingReassigned(m, root) {
		return false
	}
	if !topLevelBinding(m, root) && (name == "eval" || name == "globalThis.eval" || name == "window.eval" || name == "Function") {
		return true
	}
	imp, ok := m.imports[root]
	if !ok {
		return false
	}
	return imp.module == "vm" || imp.module == "node:vm" || imp.module == "notevil"
}

func codeOperandShape(m *sourceModule, n *sitter.Node) string {
	if n != nil && n.Kind() == "template_string" {
		for i := uint(0); i+1 < n.NamedChildCount(); i++ {
			part := n.NamedChild(i)
			if part.Kind() == "string_fragment" && n.NamedChild(i+1).Kind() == "template_substitution" {
				text := part.Utf8Text(m.src)
				if strings.ContainsAny(text, "'\"") {
					return "inside_string_literal"
				}
			}
		}
	}
	return "whole_program"
}

func mergeInterpreterUse(a, b analysis.CandidateUse) analysis.CandidateUse {
	a.Dependencies = combine(value{deps: a.Dependencies}, value{deps: b.Dependencies}).deps
	a.Gaps = parse.DedupeGaps(append(append([]analysis.Gap{}, a.Gaps...), b.Gaps...))
	// Assembly runs after merging, so every path is rebuilt over the union of
	// sources. Context controls remain source evidence for guard re-discovery.
	for _, e := range b.Context {
		found := false
		for _, old := range a.Context {
			found = found || old == e
		}
		if !found {
			a.Context = append(a.Context, e)
		}
	}
	paths := []analysis.CommandPath{}
	for i, d := range a.Dependencies {
		paths = append(paths, analysis.CommandPath{Dependency: i, Operand: d.SinkSlot})
	}
	if a.Code != nil {
		facts := *a.Code
		facts.Paths = paths
		a.Code = &facts
	}
	if a.Redirect != nil {
		facts := *a.Redirect
		facts.Paths = paths
		a.Redirect = &facts
	}
	return a
}

// jsTemplateEngines maps an engine module to the calls that compile their
// first argument as template source (close-findings-gaps D-24).
var jsTemplateEngines = map[string][]string{
	"ejs": {"render", "compile"}, "handlebars": {"compile"}, "pug": {"render", "compile"},
	"nunjucks": {"renderString"}, "lodash": {"template"}, "underscore": {"template"}, "lodash.template": {"default"},
}

// templateEngineCall recognises a verified engine call on an unshadowed
// import binding: engine.method(source, ...).
func templateEngineCall(m *sourceModule, call *sitter.Node, name, root string) (string, bool) {
	imp, ok := m.imports[root]
	if !ok || shadowed(call, root, m.src) || bindingReassigned(m, root) {
		return "", false
	}
	methods := jsTemplateEngines[imp.module]
	parts := strings.Split(name, ".")
	switch {
	case len(parts) == 2 && (imp.name == "default" || imp.name == "*") && containsString(methods, parts[1]):
		return imp.module + "." + parts[1], true
	case len(parts) == 1 && containsString(methods, imp.name):
		return imp.module + "." + imp.name, true
	case len(parts) == 1 && imp.module == "lodash.template" && (imp.name == "default" || imp.name == "*"):
		return "lodash.template", true
	}
	return "", false
}
