package parse

import (
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
)

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
	u.Completeness = c
}

func phpCodeProtection(deps []phpDep, i int) string {
	if i < len(deps) {
		switch deps[i].protection {
		case "numeric", "non_content":
			return "constrained"
		case "unknown", phpUnwritten, phpShellDenylist:
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
