package judge

import (
	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
)

const xssQuestionVersion = analysispacks.XSSProtocol

var xssQuestions = componentQuestions(analysispacks.XSSQuestions())

func xssChoices(name string) []map[string]string { return analysispacks.XSSChoices(name) }

func applyXSSPolicy(use analysis.CandidateUse, a *analysis.Assessment) {
	a.FindingStatus, a.Protection = "needs_evidence", "uncertain"
	var blockers []analysis.Gap
	if a.QuestionVersion != xssQuestionVersion {
		blockers = append(blockers, analysis.Gap{Kind: "xss_protocol_missing", Detail: "XSS-specific versioned answers are required."})
	}
	if use.XSS == nil || use.Completeness == nil || use.Completeness.ClaimKind != "xss" || use.APIModel == nil {
		blockers = append(blockers, analysis.Gap{Kind: "xss_claim_missing", Detail: "Source-backed rendering facts, binding contract and completeness are required."})
	} else {
		blockers = append(blockers, use.Completeness.Blockers...)
		roles := append([]string{"render_source", "render_binding", "render_context"}, use.Completeness.Required...)
		if use.Components != nil {
			roles = append(roles, use.Components.Required...)
		}
		seen := map[string]bool{}
		for _, role := range roles {
			if seen[role] {
				continue
			}
			seen[role] = true
			if len(use.Completeness.Evidence[role]) == 0 {
				blockers = append(blockers, analysis.Gap{Kind: "xss_evidence_missing", Detail: role})
			}
		}
		if (use.XSS.Type == "stored" || use.XSS.Type == "cross_tier") && !use.XSS.OriginResolved {
			blockers = append(blockers, analysis.Gap{Kind: "storage_origin_unresolved", Detail: "Stored rendering origin is unresolved."})
		}
		if a.Answers["output_context"] != use.XSS.OutputContext || use.XSS.Protection == "unknown" {
			blockers = append(blockers, analysis.Gap{Kind: "xss_context_unresolved", Detail: "Answers must agree with the established rendering context and protection facts."})
		}
	}
	blockers, cited, closedNoWrite := dischargeStoredOrigin(use, a, blockers)
	a.BlockingGaps = blockers
	if len(blockers) > 0 {
		a.Reason = "The XSS claim has missing or unresolved source-backed evidence."
		if r := storedResolution(a); r != nil && r.Answer == "no_request_write_in_evidence" && !closedNoWrite {
			a.Reason += " The decision model found no request write among the listed writes, but a store is not closed, so unlisted writers remain possible."
		}
		return
	}
	if closedNoWrite {
		a.FindingStatus, a.Protection = "protected_for_claim", "sufficient"
		a.Reason = "Model-resolved with scanner coverage: no listed write stores a request-controlled value into the column read, and every store is closed (schema and every writer in scanned source), so the rendered stored value is not attacker-controlled for this claim."
		return
	}
	ans, facts := a.Answers, use.XSS
	switch ans["xss_exposure"] {
	case "vulnerable":
		if ans["xss_all_paths_protected"] != "no" || (ans["encoding_adequacy"] != "inadequate" && ans["encoding_adequacy"] != "not_present") ||
			(ans["sanitizer_effectiveness"] != "ineffective" && ans["sanitizer_effectiveness"] != "absent") ||
			(facts.Protection != "raw" && facts.Protection != "ineffective") {
			a.Reason = "XSS exposure, encoding, sanitization and per-path answers contradict each other or the source facts."
			return
		}
		a.FindingStatus, a.Protection = "confirmed_vulnerability", "insufficient"
		a.Reason = "Complete source-backed rendering claim and consistent XSS-specific answers establish an unsafe supported path; this is static analysis, not runtime confirmation."
		if cited {
			a.Reason = "Model-resolved stored flow: the decision model cited a verified listed write that stores a request-controlled value into the column read. " + a.Reason
		}
	case "protected":
		if cited {
			a.Reason = "Protection would rest on a model-resolved stored-origin fact; the record stays Review."
			return
		}
		if ans["xss_all_paths_protected"] != "yes" || (ans["encoding_adequacy"] != "adequate" && ans["sanitizer_effectiveness"] != "effective") ||
			(facts.Protection != "encoded" && facts.Protection != "sanitized") {
			a.Reason = "Protection is not established on every relevant path in the stated output context."
			return
		}
		a.FindingStatus, a.Protection = "protected_for_claim", "sufficient"
		a.Reason = "Consistent XSS-specific answers and static protection facts support protection for this rendering claim."
	default:
		a.Reason = "XSS assessment is inconclusive; absence of a positive answer is not protection."
	}
}
