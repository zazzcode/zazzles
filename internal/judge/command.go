package judge

import (
	"fmt"
	"strings"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
)

// commandRoles are the Go-mandatory evidence obligations; selected catalog
// obligations are unioned with them and can never remove one.
var commandRoles = []string{"input_source", "sink_binding", "invoked_callable", "control_flow", "command_operands", "execution_configuration"}

// facet groups the request-derived paths that one question assesses.
type commandFacet struct {
	paths []analysis.CommandPath
}

func (f commandFacet) any(protection string) bool {
	for _, p := range f.paths {
		if p.Protection == protection {
			return true
		}
	}
	return false
}

// reachable reports a path whose source-to-operand facts are resolved: raw, or
// guarded by a control whose adequacy only the assessment can judge.
func (f commandFacet) reachable() bool { return f.any("raw") || f.any("guarded") }

func (f commandFacet) all(protection string) bool {
	for _, p := range f.paths {
		if p.Protection != protection {
			return false
		}
	}
	return true
}

// commandFacets partitions the paths by effective operand semantics. Shell
// syntax, executable choice and argument interpretation stay separate claims.
func commandFacets(f *analysis.CommandFacts) (shell, executable, argument commandFacet) {
	shellText := f.EffectiveShellMode == "enabled" && f.Interpreter == ""
	for _, p := range f.Paths {
		switch {
		case p.Operand == analysis.CommandSlotShell || shellText:
			shell.paths = append(shell.paths, p)
		case p.Operand == analysis.CommandSlotExecutable || p.Operand == analysis.CommandSlotOverride || p.Operand == analysis.CommandSlotOption:
			executable.paths = append(executable.paths, p)
		default:
			argument.paths = append(argument.paths, p)
		}
	}
	return
}

// fixedAbsoluteExecutable reports a constant absolute executable operand.
func fixedAbsoluteExecutable(f *analysis.CommandFacts) bool {
	for _, o := range f.Operands {
		if (o.Slot == analysis.CommandSlotExecutable || o.Slot == analysis.CommandSlotOverride) && !o.Dynamic && strings.HasPrefix(o.Constant, "/") {
			return true
		}
	}
	return false
}

func applyCommandPolicy(use analysis.CandidateUse, a *analysis.Assessment) {
	a.FindingStatus, a.Protection = "needs_evidence", "uncertain"
	var blockers []analysis.Gap
	add := func(kind, detail string) {
		blockers = append(blockers, analysis.Gap{Kind: kind, Detail: detail, At: use.Sink.Span})
	}
	if a.QuestionVersion != analysispacks.CommandProtocol {
		add("command_protocol_missing", "Command-specific versioned answers are required.")
	}
	c, f := use.Completeness, use.Command
	if f == nil || c == nil || c.ClaimKind != "command_execution" || use.APIModel == nil || use.APIModel.ID != f.ContractID {
		add("command_claim_missing", "Source-backed command facts, verified operation contract and completeness are required.")
		a.BlockingGaps = blockers
		a.Reason = "The command claim lacks source-backed facts or a verified operation contract."
		return
	}
	if err := f.Validate(len(use.Dependencies), len(use.Context)); err != nil {
		add("command_facts_invalid", err.Error())
	}
	roles := append([]string{}, commandRoles...)
	roles = append(roles, c.Required...)
	if use.Components != nil {
		roles = append(roles, use.Components.Required...)
	}
	seen := map[string]bool{}
	for _, role := range roles {
		if seen[role] {
			continue
		}
		seen[role] = true
		if len(c.Evidence[role]) == 0 {
			add("command_evidence_missing", role)
		}
	}
	if f.EffectiveShellMode == "unknown" {
		add("command_shell_mode_unknown", "The effective shell mode is not established.")
	}
	if f.ArgvShape == "unknown" {
		add("command_argv_unknown", "The argument vector shape is not established.")
	}
	ans := a.Answers
	shell, executable, argument := commandFacets(f)

	// Consistency gates: answers must agree with the established facts.
	var contradictions []string
	contradict := func(format string, args ...any) {
		contradictions = append(contradictions, fmt.Sprintf(format, args...))
	}
	switch ans["shell_syntax_protection"] {
	case "vulnerable":
		if len(shell.paths) == 0 {
			contradict("shell vulnerability claimed but no request-derived path reaches an effective shell command operand")
		} else if !shell.reachable() {
			contradict("shell vulnerability claimed but every shell path has unresolved facts")
		}
	case "protected":
		if len(shell.paths) == 0 || !shell.all("guarded") {
			contradict("shell protection claimed without a dominating or enclosing control on every request-derived shell path")
		}
	case "not_applicable":
		if len(shell.paths) > 0 {
			contradict("shell facet marked not applicable although a request-derived value reaches an effective shell command operand")
		}
	}
	switch ans["executable_control"] {
	case "unsafe":
		if !executable.reachable() {
			contradict("executable control unsafe without a resolved request-derived executable, override or shell-configuration path")
		}
	case "constrained":
		if len(executable.paths) > 0 && !executable.all("guarded") {
			contradict("executable constrained without a control on every request-derived executable path")
		}
		if len(executable.paths) == 0 && !fixedAbsoluteExecutable(f) && f.EffectiveShellMode != "enabled" {
			contradict("a bare or dynamic executable name has unresolved PATH selection; a fixed absolute path is required")
		}
	}
	switch ans["argument_control"] {
	case "unsafe":
		if !argument.reachable() || f.Interpreter == "" {
			contradict("argument option control is not established: unknown utility options are Review, not a positive")
		}
	case "constrained":
		if len(argument.paths) > 0 && !argument.all("guarded") {
			contradict("arguments constrained without a control on every request-derived argument path")
		}
	case "not_applicable":
		if len(argument.paths) > 0 {
			contradict("argument facet marked not applicable although a request-derived argument operand exists")
		}
	}
	if len(f.Paths) == 0 {
		contradict("no request-derived operand path is recorded")
	}
	for _, p := range f.Paths {
		if p.Protection == "unknown" && ans["protection_coverage"] == "complete" {
			contradict("coverage marked complete although a request-derived path has unresolved facts")
			break
		}
	}

	// A raw witness is scoped to its own source-to-operand path; unresolved
	// siblings stay visible as path-scoped blockers without voiding it.
	global := []analysis.Gap{}
	for _, g := range c.Blockers {
		touches := false
		for _, d := range use.Dependencies {
			if gapTouchesCommandDependency(g, d) {
				touches = true
			}
		}
		if !touches {
			global = append(global, g)
		}
	}
	unsafeFacet := ""
	switch {
	case ans["shell_syntax_protection"] == "vulnerable" && shell.reachable():
		unsafeFacet = "shell syntax (CWE-78)"
	case ans["executable_control"] == "unsafe" && executable.reachable():
		unsafeFacet = "executable selection"
	case ans["argument_control"] == "unsafe" && argument.reachable() && f.Interpreter != "":
		unsafeFacet = "option/interpreter control (CWE-88)"
	}
	scoped := append(append([]analysis.Gap{}, blockers...), global...)
	if len(contradictions) > 0 {
		a.BlockingGaps = append(append(blockers, c.Blockers...), analysis.Gap{Kind: "command_answers_inconsistent", Detail: strings.Join(contradictions, "; "), At: use.Sink.Span})
		a.Reason = "Command answers contradict the source-backed facts; raw answers are retained and no status is claimed from them."
		return
	}
	if unsafeFacet != "" && len(scoped) == 0 {
		a.BlockingGaps = nil
		a.FindingStatus, a.Protection = "confirmed_vulnerability", "insufficient"
		a.Reason = "A consistent " + unsafeFacet + " answer is supported by an independent source-to-operand path with a verified " + f.Operation + " binding under the declared " + f.Platform + " assumption. Unresolved sibling paths remain visible. This is a static judgment, not runtime exploitation or independent Findings Review."
		return
	}
	a.BlockingGaps = append(append([]analysis.Gap{}, blockers...), c.Blockers...)
	if len(a.BlockingGaps) > 0 {
		a.Reason = "Claim-relevant command evidence is incomplete; raw answers and unrelated coverage gaps are retained."
		return
	}
	applicable, unsafeSomewhere, unknown := 0, false, false
	for name, facet := range map[string]commandFacet{"shell_syntax_protection": shell, "executable_control": executable, "argument_control": argument} {
		answer := ans[name]
		switch answer {
		case "protected", "constrained":
			applicable++
		case "vulnerable", "unsafe":
			unsafeSomewhere = true
		case "unknown":
			unknown = true
		case "not_applicable":
		}
		_ = facet
	}
	if !unsafeSomewhere && !unknown && applicable > 0 && ans["protection_coverage"] == "complete" && !hasUnguardedPath(f) {
		a.FindingStatus, a.Protection = "protected_for_claim", "sufficient"
		a.Reason = "Every applicable facet is protected or constrained by a source-backed control on each request-derived path with complete coverage; this applies only to the stated claim."
		return
	}
	a.Reason = "The command assessment is inconclusive; unknown, unsafe-without-a-complete-witness or incomplete coverage cannot support protection."
}

func hasUnguardedPath(f *analysis.CommandFacts) bool {
	for _, p := range f.Paths {
		if p.Protection != "guarded" {
			return true
		}
	}
	return false
}

// gapTouchesCommandDependency mirrors parse's path-scoping: the gap lies on a
// dependency's source or transfer chain.
func gapTouchesCommandDependency(g analysis.Gap, d analysis.Dependency) bool {
	for _, e := range append([]analysis.Evidence{d.Source}, d.Transfers...) {
		if e.Kind != "input_source" && e.Kind != "call_argument_dependency" {
			continue
		}
		if g.At.File == e.Span.File && g.At.StartByte >= e.Span.StartByte && g.At.EndByte <= e.Span.EndByte {
			return true
		}
	}
	return false
}
