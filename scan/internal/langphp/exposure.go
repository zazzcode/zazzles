package langphp

import (
	"regexp"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
)

// phpDiagnostic marks a value returned by a diagnostic operation of branch 1
// D-1 (getenv() with no argument, php_uname, phpversion, ini_get_all, or a
// returning print_r/var_export over an internal-state array). The claim is
// recorded only where the value is output.
type phpDiagnostic struct {
	operation, subject string
	at                 analysis.Evidence
}

var phpInfoFlag = regexp.MustCompile(`^(INFO_[A-Z_]+|-?[0-9]+)(\s*\|\s*(INFO_[A-Z_]+|-?[0-9]+))*$`)

// diagnosticCall records a diagnostic operation that outputs internal state,
// and marks a value that carries internal state for its output sinks. v is
// the value the existing call model returned; it is returned unchanged except
// for the marker, so no other claim changes.
func (f *phpFlow) diagnosticCall(n *sitter.Node, nodes []*sitter.Node, v phpValue) phpValue {
	if n.Kind() != "function_call_expression" {
		return v
	}
	m := f.module
	name := strings.ToLower(strings.TrimPrefix(f.callName(n), `\`))
	if !f.builtin(name) {
		return v
	}
	switch name {
	case "phpinfo":
		flag := ""
		if len(nodes) > 0 {
			if text := strings.TrimSpace(phpText(m, nodes[0])); phpInfoFlag.MatchString(text) {
				flag = text
			}
		}
		f.recordExposureNode(n, m.evidence("diagnostic_operation", n), name, analysis.ExposureConfiguration, flag, "")
	case "debug_print_backtrace":
		f.recordExposureNode(n, m.evidence("diagnostic_operation", n), name, analysis.ExposureStack, "", "")
	case "var_dump", "debug_zval_refcount":
		for _, arg := range nodes {
			if subject := f.internalStateArgument(arg); subject != "" {
				f.recordExposureNode(n, m.evidence("diagnostic_operation", n), name, subject, "", "")
				break
			}
		}
	case "print_r", "var_export":
		if len(nodes) == 0 {
			return v
		}
		subject := f.internalStateArgument(nodes[0])
		if subject == "" {
			return v
		}
		returning := false
		if len(nodes) > 1 {
			switch strings.ToLower(strings.TrimSpace(phpText(m, nodes[1]))) {
			case "true", "1":
				returning = true
			case "false", "0":
			default:
				// A non-literal mode is not modeled: no claim.
				return v
			}
		}
		operation := m.evidence("diagnostic_operation", n)
		if !returning {
			f.recordExposureNode(n, operation, name, subject, "", "")
			return v
		}
		v.diagnostic = &phpDiagnostic{operation: name, subject: subject, at: operation}
	case "getenv":
		if len(nodes) == 0 {
			v.diagnostic = &phpDiagnostic{operation: name, subject: analysis.ExposureEnvironment, at: m.evidence("diagnostic_operation", n)}
		}
	case "php_uname", "phpversion":
		v.diagnostic = &phpDiagnostic{operation: name, subject: analysis.ExposureRuntimeState, at: m.evidence("diagnostic_operation", n)}
	case "ini_get_all":
		v.diagnostic = &phpDiagnostic{operation: name, subject: analysis.ExposureConfiguration, at: m.evidence("diagnostic_operation", n)}
	case "dump", "dd":
		if f.symfony != nil {
			f.recordExposureNode(n, m.evidence("diagnostic_operation", n), name, analysis.ExposureRuntimeState, "", analysis.ExposureEnvironmentDependent)
		}
	}
	return v
}

// internalStateArgument returns the subject of an argument that is one of the
// internal-state arrays of D-1, or "".
func (f *phpFlow) internalStateArgument(arg *sitter.Node) string {
	m := f.module
	if arg == nil {
		return ""
	}
	switch arg.Kind() {
	case "variable_name":
		switch phpVarName(m, arg) {
		case "_SERVER", "_ENV":
			return analysis.ExposureEnvironment
		case "GLOBALS":
			return analysis.ExposureRuntimeState
		}
	case "function_call_expression":
		name := strings.ToLower(strings.TrimPrefix(f.callName(arg), `\`))
		if !f.builtin(name) {
			return ""
		}
		switch name {
		case "getenv":
			if len(phpArgs(arg)) == 0 {
				return analysis.ExposureEnvironment
			}
		case "get_defined_vars":
			return analysis.ExposureRuntimeState
		case "ini_get_all", "get_defined_constants":
			return analysis.ExposureConfiguration
		}
	}
	return ""
}

// diagnosticOutput records an output sink (echo, print, a Response body)
// whose value carries internal state.
func (f *phpFlow) diagnosticOutput(sink *sitter.Node, v phpValue) {
	if d := v.diagnostic; d != nil {
		f.recordExposure(f.module.evidence(analysis.ExposureKind, sink), d.at, d.operation, d.subject, "", "", sink)
	}
}

// diagnosticTemplateOutput records a Twig interpolation whose value carries
// internal state: the anchor is the interpolation and the dominating
// conditions are those of the render call that reached it.
func (f *phpFlow) diagnosticTemplateOutput(sink analysis.Evidence, renderCall *sitter.Node, v phpValue) {
	if d := v.diagnostic; d != nil {
		f.recordExposure(evidenceAs(sink, analysis.ExposureKind), d.at, d.operation, d.subject, "", "", renderCall)
	}
}

// recordExposureNode anchors the candidate at a PHP sink node.
func (f *phpFlow) recordExposureNode(sink *sitter.Node, operation analysis.Evidence, name, subject, flag, gapKind string) {
	f.recordExposure(f.module.evidence(analysis.ExposureKind, sink), operation, name, subject, flag, gapKind, sink)
}

// evidenceAs returns the same source evidence under another role name.
func evidenceAs(e analysis.Evidence, kind string) analysis.Evidence {
	e.Kind = kind
	return e
}

// recordExposure emits one candidate per operation per entry (D-3). Guards
// are the dominating conditions the guard engine recorded (D-2); guardNode is
// the PHP node whose enclosing conditions dominate the sink (the sink itself,
// or the render call for a Twig interpolation).
func (f *phpFlow) recordExposure(sink analysis.Evidence, operation analysis.Evidence, name, subject, flag, gapKind string, guardNode *sitter.Node) {
	if f.entry.HTTP == nil {
		return
	}
	for _, u := range f.report.Uses {
		if u.Kind == analysis.ExposureKind && u.InvocationContextID == f.invocation.ID && u.Sink.Span == sink.Span {
			return
		}
	}
	u := f.addUseAt(analysis.ExposureKind, sink, phpValue{})
	facts := analysis.ExposureFacts{Operation: name, Subject: subject, Flag: flag, EntryServed: "yes"}
	for _, e := range phpDedupeEvidence(append(append([]analysis.Evidence{}, f.context...), f.throwingGuards(guardNode)...)) {
		switch e.Kind {
		case "branch_precondition", "branch_false_precondition", "configuration_precondition":
			facts.Guards = append(facts.Guards, e)
		}
	}
	u.Exposure = &facts
	u.APIModel = analysispacks.ExposureContract(analysispacks.PHPDiagnosticOutput)
	var entry []analysis.Evidence
	for _, e := range []analysis.Evidence{f.entryEvidence(), f.entry.Location} {
		if e.Span.File != "" {
			entry = append(entry, e)
		}
	}
	c := &analysis.Completeness{
		ClaimKind: "exposure",
		Required:  analysispacks.ExposureRoles(),
		Scope:     "Verified diagnostic operation, its entry and its dominating conditions; no request source.",
		Evidence: map[string][]analysis.Evidence{
			"diagnostic_operation": {operation},
			"entry":                entry,
			"control_flow":         append([]analysis.Evidence{evidenceAs(sink, "operation")}, f.context...),
			"sink_binding":         {evidenceAs(sink, "sink_binding")},
		},
		Blockers: []analysis.Gap{},
		Coverage: append([]analysis.Gap{}, u.Gaps...),
	}
	if len(facts.Guards) > 0 {
		c.Evidence["guard"] = facts.Guards
	}
	if gapKind != "" {
		g := analysis.Gap{Kind: gapKind, Detail: "Framework dump output depends on the debug environment.", At: sink.Span}
		u.Gaps = append(u.Gaps, g)
		c.Blockers = append(c.Blockers, g)
	}
	u.Completeness = c
}

// throwingGuards returns the conditions of earlier if statements in the
// enclosing blocks of n whose only branch ends in a throw: the operation runs
// only when the condition is false. The shared guard engine does not treat
// throw as terminating (changing it would change existing requests), so the
// exposure record adds these as branch_false_precondition evidence.
func (f *phpFlow) throwingGuards(n *sitter.Node) []analysis.Evidence {
	var out []analysis.Evidence
	for child, parent := n, n.Parent(); parent != nil; child, parent = parent, parent.Parent() {
		if parent.Kind() == "function_definition" || parent.Kind() == "method_declaration" || parent.Kind() == "anonymous_function" || parent.Kind() == "arrow_function" {
			break
		}
		if parent.Kind() != "compound_statement" && parent.Kind() != "program" {
			continue
		}
		for i := uint(0); i < parent.NamedChildCount(); i++ {
			s := parent.NamedChild(i)
			if s.StartByte() >= child.StartByte() {
				break
			}
			if s.Kind() != "if_statement" || phpField(s, "alternative") != nil || !phpEndsInThrow(phpField(s, "body")) {
				continue
			}
			test := phpField(s, "condition")
			if test != nil && test.Kind() == "parenthesized_expression" && test.NamedChildCount() > 0 {
				test = test.NamedChild(0)
			}
			if test != nil {
				out = append(out, f.module.evidence("branch_false_precondition", test))
			}
		}
	}
	return out
}

func phpEndsInThrow(body *sitter.Node) bool {
	if body == nil {
		return false
	}
	last := body
	if body.Kind() == "compound_statement" {
		if body.NamedChildCount() == 0 {
			return false
		}
		last = body.NamedChild(body.NamedChildCount() - 1)
	}
	return last.Kind() == "expression_statement" && last.NamedChildCount() == 1 && last.NamedChild(0).Kind() == "throw_expression"
}
