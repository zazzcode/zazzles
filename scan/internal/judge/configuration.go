package judge

import (
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
)

// applyConfigurationPolicy follows the lane policy order and D-3.
func applyConfigurationPolicy(use analysis.CandidateUse, a *analysis.Assessment) {
	a.FindingStatus, a.Protection = "needs_evidence", "uncertain"
	gap := func(kind, detail string) {
		a.Reason = detail
		a.BlockingGaps = append(a.BlockingGaps, analysis.Gap{Kind: "configuration_" + kind, Detail: detail, At: use.Sink.Span})
	}
	if a.QuestionVersion != analysispacks.ConfigurationProtocol {
		gap("protocol_missing", "Versioned configuration answers are required.")
		return
	}
	c := use.Completeness
	if use.Configuration == nil || c == nil || c.ClaimKind != "configuration" {
		gap("claim_missing", "Configuration claims require the recorded setting and its completeness.")
		return
	}
	for _, role := range []string{"setting", "scope"} {
		if len(c.Evidence[role]) == 0 {
			gap("evidence_missing", "Missing configuration evidence role "+role+".")
			return
		}
	}
	for _, g := range append(append([]analysis.Gap{}, use.Gaps...), c.Blockers...) {
		if g.Kind == "deploy_mapping_unresolved" || g.Kind == "config_file_unread" {
			gap("evidence_missing", "A blocking configuration gap is recorded.")
			a.BlockingGaps[len(a.BlockingGaps)-1].Kind = g.Kind
			return
		}
	}
	facts := use.Configuration
	answers := a.Answers
	if answers["mitigation"] == "adequate" && len(facts.Mitigations) == 0 {
		gap("answers_inconsistent", "mitigation adequate requires a recorded mitigation.")
		return
	}
	if answers["setting_effect"] == "not_in_effect" && configInstalled(facts) && scopeMapped(use, facts) {
		gap("answers_inconsistent", "not_in_effect contradicts a mapped installed setting.")
		return
	}
	switch {
	case answers["setting_effect"] == "not_in_effect" || answers["weakness"] == "benign" || (answers["mitigation"] == "adequate" && len(facts.Mitigations) > 0):
		a.FindingStatus, a.Protection = "protected_for_claim", "protected"
	case answers["setting_effect"] == "in_effect" && answers["weakness"] == "weakens" && (answers["mitigation"] == "none" || answers["mitigation"] == "inadequate"):
		a.FindingStatus, a.Protection = "confirmed_vulnerability", "vulnerable"
	}
}

func configInstalled(f *analysis.ConfigurationFacts) bool {
	for _, e := range f.Joined {
		if e.Kind == "config_installed" {
			return true
		}
	}
	return false
}

func scopeMapped(use analysis.CandidateUse, f *analysis.ConfigurationFacts) bool {
	if f.Scope == "" {
		return false
	}
	for _, g := range append(append([]analysis.Gap{}, use.Gaps...), use.Completeness.Blockers...) {
		if g.Kind == "deploy_mapping_unresolved" {
			return false
		}
	}
	return true
}

func wireConfiguration(f *analysis.ConfigurationFacts) any {
	if f == nil {
		return nil
	}
	return f
}
