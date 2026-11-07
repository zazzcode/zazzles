package report

import (
	"fmt"

	"github.com/zazzcode/zazzles/internal/analysis"
)

func describeCommand(u analysis.CandidateUse, f *analysis.Finding) {
	f.Title = "Process execution needs review"
	f.Summary = "Scan identified a request-derived value reaching a process operation. Its shell, executable and argument semantics have not been established as a defect or as protected."
	if u.Command != nil {
		f.Summary = fmt.Sprintf("Scan identified a request-derived value reaching %s under the declared %s assumption (effective shell %s). Shell syntax, executable selection and argument interpretation are assessed as separate facets.", u.Command.Operation, u.Command.Platform, u.Command.EffectiveShellMode)
	}
}

// confirmCommand promotes a gated command assessment to a finding and names
// the unsafe facet and its conditions from the raw answers and source facts.
func confirmCommand(u analysis.CandidateUse, f *analysis.Finding) {
	a := u.Assessment
	f.RecordType, f.Status = "finding", "confirmed_vulnerability"
	switch {
	case a.Answers["shell_syntax_protection"] == "vulnerable":
		f.Title = "Command injection supported by source analysis"
		f.Summary = "A request-derived value reaches shell command text of " + u.Command.Operation + " with no established constraint. This is a static source judgment under the declared " + u.Command.Platform + " assumption, not runtime exploitation or independent Findings Review. Remediate the process operand named by the evidence; shell syntax, executable and arguments are separate facets."
	case a.Answers["executable_control"] == "unsafe":
		f.Title = "Request-controlled executable selection supported by source analysis"
		f.Summary = "A request-derived value selects the executable, executable override or shell configuration of " + u.Command.Operation + ". No shell-syntax witness is claimed. This is a static source judgment, not runtime exploitation."
	default:
		f.Title = "Request-controlled process option or interpreter argument supported by source analysis"
		f.Summary = "A request-derived argument reaches an interpreter or utility option with established semantics for " + u.Command.Operation + " (CWE-88 option injection). This is a static source judgment, not runtime exploitation."
	}
	if u.Command.EffectiveShellMode != "enabled" || u.Command.Interpreter != "" {
		f.Uncertainty += " Effective shell mode: " + u.Command.EffectiveShellMode + "; interpreter: " + u.Command.Interpreter + "."
	}
	f.Uncertainty += " The execution assumption is " + u.Command.Platform + "; unresolved sibling paths, if any, remain separate blocking or coverage records."
}

func commandGuidance() Guidance {
	return Guidance{Title: "Keep request data out of process execution", Actions: []string{
		"Prefer eliminating process execution by using a library API for the task.",
		"Otherwise use a fixed trusted absolute executable, disable the shell, and pass each value as a separate argument.",
		"Constrain each value with a utility-specific, enforced rule such as a finite set of permitted literals that cannot be option syntax, rejecting before the call. `--` is not a universal option terminator.",
	}, ExampleStatus: "not_generated; utility-specific constraints and tests required"}
}

func commandFindingGuidance(u analysis.CandidateUse, at string) Guidance {
	g := commandGuidance()
	operand := "the request-derived operand"
	if u.Command != nil {
		for _, p := range u.Command.Paths {
			if p.Protection == "raw" {
				operand = "operand " + p.Operand
				break
			}
		}
	}
	g.Title = "Repair this process invocation"
	g.Actions = append([]string{"At " + at + ", change " + operand + " of " + u.Sink.Text + ". Do not strip arbitrary punctuation, label an argument array safe by itself, or rely on quoting without an enforced constraint."}, g.Actions...)
	g.ExampleStatus = "no automatic patch; no verified fix is exported"
	return g
}
