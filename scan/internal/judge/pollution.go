package judge

import (
	"slices"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
)

func applyPollutionPolicy(use analysis.CandidateUse, a *analysis.Assessment) {
	a.FindingStatus, a.Protection = "needs_evidence", "uncertain"
	a.Reason = "The supplied answers and evidence do not establish a prototype write or complete protection."
	a.BlockingGaps = nil
	add := func(kind, detail string) {
		a.BlockingGaps = append(a.BlockingGaps, analysis.Gap{Kind: kind, Detail: detail, At: use.Sink.Span})
	}
	facts, c := use.Pollution, use.Completeness
	if a.QuestionVersion != analysispacks.PollutionProtocol || facts == nil || c == nil || c.ClaimKind != "pollution" {
		add("pollution_claim_missing", "Versioned answers and source-backed prototype write facts are required")
		return
	}
	a.BlockingGaps = append(a.BlockingGaps, c.Blockers...)
	for _, role := range analysispacks.PollutionRoles() {
		if len(c.Evidence[role]) == 0 {
			add("pollution_evidence_missing", role)
		}
	}
	if facts.ContractID != "" {
		if use.APIModel == nil || use.APIModel.ID != facts.ContractID || analysispacks.PollutionContract(facts.ContractID) == nil {
			add("pollution_claim_missing", "The write lacks a verified library contract")
		}
		if facts.Version == "" || len(c.Evidence["dependency_version"]) == 0 {
			if !slices.ContainsFunc(a.BlockingGaps, func(g analysis.Gap) bool { return g.Kind == "version_unresolved" }) {
				add("version_unresolved", "The write library's affected version is unresolved")
			}
		}
	} else if facts.Operation != analysis.PollutionMerge && facts.Operation != analysis.PollutionWalk && facts.Operation != analysis.PollutionNested {
		add("pollution_claim_missing", "The operation is not a verified source-visible write")
	}
	blocked, open := analysispacks.ListPrototypeKeys(facts.Blocked)
	if !slices.Equal(blocked, facts.Blocked) || !slices.Equal(open, facts.Open) || facts.KeyOperand == "" {
		add("pollution_facts_invalid", "The write has an inconsistent key listing or operand")
	}
	routes := analysispacks.OpenPrototypeRoutes(open, facts.KeyLevels)
	raw, guarded, valid := pollutionPaths(use, len(routes) > 0)
	if !valid {
		add("pollution_facts_invalid", "Each operand path must reference its own dependency and source-established controls")
	}
	answers := a.Answers
	control, bypass, coverage := answers["prototype_key_control"], answers["key_guard_bypass"], answers["protection_coverage"]
	switch {
	case bypass == "bypass_identified" && (len(routes) == 0 || facts.Guard == "" || facts.Guard == "unknown"):
		add("pollution_bypass_unsupported", "The recorded key guard does not support the bypass answer")
	case control == "protected" && !guarded || coverage == "complete" && !guarded ||
		control == "vulnerable" && !raw || bypass == "no_bypass" && facts.Guard == "deny_list" && len(routes) > 0:
		add("pollution_answers_inconsistent", "The answers contradict the recorded paths or key guard")
	}
	if len(a.BlockingGaps) > 0 {
		return
	}
	if guarded && len(routes) == 0 && control == "protected" && bypass == "no_bypass" && coverage == "complete" {
		a.FindingStatus, a.Protection = "protected_for_claim", "sufficient"
		a.Reason = "Source-backed controls cover every recorded key path and prototype lookup."
	}
	if raw && control == "vulnerable" && coverage == "incomplete" &&
		(facts.Guard == "" && bypass == "not_applicable" || facts.Guard == "deny_list" && bypass == "bypass_identified") {
		a.FindingStatus, a.Protection = "confirmed_vulnerability", "insufficient"
		a.Reason = "Request-derived keys reach a complete write path that can pollute Object.prototype."
	}
}

func pollutionPaths(use analysis.CandidateUse, routesOpen bool) (raw, guarded, valid bool) {
	facts := use.Pollution
	if len(facts.Paths) == 0 || len(facts.Paths) != len(use.Dependencies) {
		return false, false, false
	}
	seen := make([]bool, len(use.Dependencies))
	guarded = true
	for _, p := range facts.Paths {
		if p.Dependency < 0 || p.Dependency >= len(seen) || seen[p.Dependency] || p.Operand != facts.KeyOperand {
			return false, false, false
		}
		seen[p.Dependency] = true
		d := use.Dependencies[p.Dependency]
		if d.SinkSlot != p.Operand || (p.Protection != "unknown" && d.Source.Kind != "input_source") {
			return false, false, false
		}
		for _, i := range p.Controls {
			if i < 0 || i >= len(use.Context) || use.Context[i].Kind != "key_guard" {
				return false, false, false
			}
		}
		switch p.Protection {
		case "raw":
			if !routesOpen {
				return false, false, false
			}
			raw = true
		case "guarded":
			if routesOpen || len(p.Controls) == 0 {
				return false, false, false
			}
		case "unknown":
		default:
			return false, false, false
		}
		guarded = guarded && p.Protection == "guarded"
	}
	return raw, guarded, true
}
