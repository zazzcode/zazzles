package judge

import (
	"slices"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
)

// applyExposurePolicy follows the lane contract policy order (section 2.7)
// with the exposure table of branch 1 D-13.
func applyExposurePolicy(use analysis.CandidateUse, a *analysis.Assessment) {
	a.FindingStatus, a.Protection = "needs_evidence", "uncertain"
	gap := func(kind, detail string) {
		a.Reason = detail
		a.BlockingGaps = append(a.BlockingGaps, analysis.Gap{Kind: "exposure_" + kind, Detail: detail, At: use.Sink.Span})
	}
	if a.QuestionVersion != analysispacks.ExposureProtocol {
		gap("protocol_missing", "Versioned exposure answers are required.")
		return
	}
	f, c := use.Exposure, use.Completeness
	if f == nil || c == nil || c.ClaimKind != "exposure" || use.APIModel == nil || use.APIModel.ID != analysispacks.PHPDiagnosticOutput && use.APIModel.ID != analysispacks.NodeDiagnosticOutput {
		gap("claim_missing", "Exposure requires source-backed facts, completeness and a verified diagnostic contract.")
		return
	}
	if err := f.Validate(); err != nil {
		gap("facts_invalid", err.Error())
		return
	}
	for _, role := range append(analysispacks.ExposureRoles(), c.Required...) {
		if len(c.Evidence[role]) == 0 {
			gap("evidence_missing", "Missing exposure evidence role "+role+".")
			return
		}
	}
	output, reach := a.Answers["exposure_output"], a.Answers["exposure_reach"]
	if reach == "restricted" && len(f.Guards) == 0 || reach == "reachable" && f.EntryServed == "no" {
		gap("answers_inconsistent", "The answers contradict the recorded guards or entry.")
		return
	}
	blocking := slices.Clone(c.Blockers)
	for _, g := range use.Gaps {
		if g.Kind == analysis.ExposureEnvironmentDependent && !slices.ContainsFunc(blocking, func(b analysis.Gap) bool { return b.Kind == g.Kind }) {
			blocking = append(blocking, g)
		}
	}
	if len(blocking) > 0 {
		a.BlockingGaps = append(a.BlockingGaps, blocking...)
		a.Reason = "Claim-relevant exposure evidence is incomplete."
		return
	}
	if output == "benign" || reach == "restricted" && len(f.Guards) > 0 {
		a.FindingStatus, a.Protection = "protected_for_claim", "sufficient"
		a.Reason = "The assessment supports that the operation discloses nothing internal or that a recorded guard restricts it."
		return
	}
	if output == "internal_state" && reach == "reachable" {
		a.FindingStatus, a.Protection = "confirmed_vulnerability", "insufficient"
		a.Reason = "A diagnostic operation that discloses internal state is reachable from the recorded entry."
		return
	}
	a.Reason = "The answers do not establish a reachable disclosure or a protection."
}
