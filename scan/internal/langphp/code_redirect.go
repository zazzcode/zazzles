package langphp

import (
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
)

// templateUse records a template_injection_candidate: v is compiled as Twig
// template source.
func (f *phpFlow) templateUse(n *sitter.Node, op string, v phpValue, node *sitter.Node) {
	before := len(f.report.Uses)
	f.codeUse(n, op, v, node)
	if len(f.report.Uses) == before {
		return
	}
	u := &f.report.Uses[len(f.report.Uses)-1]
	u.Kind = analysispacks.TemplateKind
	u.ID = strings.TrimSuffix(u.ID, ":code_execution_candidate") + ":" + analysispacks.TemplateKind
	u.Sink.Kind = analysispacks.TemplateKind
	u.Code.ContractID, u.Code.ExecutionContext = "php-template-source-v1", "template_engine"
	u.APIModel = analysispacks.CodeContract("php-template-source-v1")
}

// codeUse records a code_execution_candidate for an interpreter-string operand
// (eval, string assert, create_function) under php-eval-v1 (D-10).
func (f *phpFlow) codeUse(n *sitter.Node, op string, v phpValue, node *sitter.Node) {
	if len(v.deps) == 0 {
		return
	}
	u := f.addUse("code_execution_candidate", n, v)
	paths := []analysis.CommandPath{}
	for i := range u.Dependencies {
		u.Dependencies[i].SinkSlot = "code"
		protection := "raw"
		switch u.Dependencies[i].SinkSlot {
		default:
			protection = phpCodeProtection(v.deps, i)
		}
		paths = append(paths, analysis.CommandPath{Dependency: i, Operand: "code", Protection: protection})
	}
	phpCiteGuards(u, paths, f.module.evidence("code_operand", node))
	u.Code = &analysis.CodeFacts{Operation: op, ContractID: "php-eval-v1", ExecutionContext: "server", Shape: "whole_program", Paths: paths}
	u.APIModel = analysispacks.CodeContract("php-eval-v1")
	u.Context = append(u.Context, f.module.evidence("sink_binding", phpCallee(n)))
	c := &analysis.Completeness{ClaimKind: "code", Required: []string{"input_source", "sink_binding", "invoked_callable", "control_flow", "code_operand"}, Evidence: map[string][]analysis.Evidence{
		"sink_binding":     {f.module.evidence("sink_binding", phpCallee(n))},
		"invoked_callable": {f.entryEvidence()},
		"code_operand":     {f.module.evidence("code_operand", node)},
		"control_flow":     append([]analysis.Evidence{f.module.evidence("operation", n)}, f.context...),
	}, Blockers: []analysis.Gap{}, Coverage: append([]analysis.Gap{}, u.Gaps...), Scope: "PHP interpreter-string operand claim; the operand is source text, not a file destination."}
	for _, d := range u.Dependencies {
		if d.Source.Kind == "input_source" || d.Source.Kind == "storage_source" {
			c.Evidence["input_source"] = append(c.Evidence["input_source"], d.Source)
		}
	}
	c.Blockers = append(c.Blockers, phpStoredOnlyBlockers(v.deps, u.Sink.Span)...)
	u.Completeness = c
}

func phpCodeProtection(deps []phpDep, i int) string {
	if i < len(deps) {
		switch deps[i].protection {
		case "numeric", "non_content":
			return "guarded"
		case "unknown", phpUnwritten, phpShellDenylist, phpRegexCapture:
			return "unknown"
		}
	}
	return "raw"
}

// headerUse models header('Location: <dest>') as the canonical PHP redirect
// (D-9): a Location header is an implied 302; only the destination operand is
// the claim. Non-Location headers are not redirects and produce no claim.
func (f *phpFlow) headerUse(n *sitter.Node, node *sitter.Node, v phpValue) {
	if len(v.deps) == 0 {
		return
	}
	if !phpIsLocationHeader(f.module, node) {
		return
	}
	u := f.addUse("open_redirect_candidate", n, v)
	paths := []analysis.CommandPath{}
	for i := range u.Dependencies {
		u.Dependencies[i].SinkSlot = "destination"
		paths = append(paths, analysis.CommandPath{Dependency: i, Operand: "destination", Protection: phpCodeProtection(v.deps, i)})
	}
	phpCiteGuards(u, paths, f.module.evidence("redirect_operand", node))
	u.Redirect = &analysis.RedirectFacts{Operation: "header", ContractID: "php-header-redirect-v1", DestinationOrigin: analysis.DestinationRequest, Paths: paths}
	u.APIModel = analysispacks.RedirectContract("php-header-redirect-v1")
	u.Context = append(u.Context, f.module.evidence("sink_binding", phpCallee(n)))
	c := &analysis.Completeness{ClaimKind: "redirect", Required: []string{"input_source", "sink_binding", "invoked_callable", "control_flow", "redirect_operand"}, Evidence: map[string][]analysis.Evidence{
		"sink_binding":     {f.module.evidence("sink_binding", phpCallee(n))},
		"invoked_callable": {f.entryEvidence()},
		"redirect_operand": {f.module.evidence("redirect_operand", node)},
		"control_flow":     append([]analysis.Evidence{f.module.evidence("operation", n)}, f.context...),
	}, Blockers: []analysis.Gap{}, Coverage: append([]analysis.Gap{}, u.Gaps...), Scope: "PHP Location header destination claim; PHP makes a Location header an implied 302 redirect."}
	for _, d := range u.Dependencies {
		if d.Source.Kind == "input_source" || d.Source.Kind == "storage_source" {
			c.Evidence["input_source"] = append(c.Evidence["input_source"], d.Source)
		}
	}
	c.Blockers = append(c.Blockers, phpStoredOnlyBlockers(v.deps, u.Sink.Span)...)
	u.Completeness = c
}

// phpIsLocationHeader reports whether the header() operand's constant prefix
// names the Location header (case-insensitive; PHP treats the name so).
func phpIsLocationHeader(m *phpModule, node *sitter.Node) bool {
	prefix := phpConstantPrefix(m, node, 32)
	if prefix == "" {
		return false
	}
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(prefix)), "location")
}

// phpConstantPrefix collects the leading literal text of a concatenation or
// string node, bounded by limit bytes.
func phpConstantPrefix(m *phpModule, n *sitter.Node, limit int) string {
	if n == nil {
		return ""
	}
	switch n.Kind() {
	case "string", "encapsed_string":
		text, ok := phpStringLiteral(m, n)
		if !ok {
			return ""
		}
		if len(text) > limit {
			text = text[:limit]
		}
		return text
	case "binary_expression":
		if left := phpField(n, "left"); left != nil {
			if p := phpConstantPrefix(m, left, limit); p != "" {
				return p
			}
		}
		return ""
	case "parenthesized_expression":
		if n.NamedChildCount() > 0 {
			return phpConstantPrefix(m, n.NamedChild(0), limit)
		}
	}
	return ""
}

// phpCiteGuards gives guarded code/redirect paths the control citation the
// shared facts contract requires: the operand evidence whose value the
// numeric or non-content constraint covers.
func phpCiteGuards(u *analysis.CandidateUse, paths []analysis.CommandPath, operand analysis.Evidence) {
	control := -1
	for i := range paths {
		if paths[i].Protection != "guarded" {
			continue
		}
		if control < 0 {
			control = len(u.Context)
			u.Context = append(u.Context, operand)
		}
		paths[i].Controls = []int{control}
		paths[i].Reason = "numeric or non-content value cannot carry operand syntax"
	}
}
