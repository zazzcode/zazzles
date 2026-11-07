package judge

import "github.com/zazzcode/zazzles/internal/analysis"

// applyPolicy uses claim-scoped completeness when supplied. Legacy candidates
// remain conservative until their dependency and binding evidence is assembled.
func applyPolicy(use analysis.CandidateUse, a *analysis.Assessment) {
	if validationUse(use) {
		applyValidationPolicy(use, a)
		return
	}
	if use.Kind == "xss_candidate" {
		applyXSSPolicy(use, a)
		return
	}
	if use.Kind == "command_execution_candidate" {
		applyCommandPolicy(use, a)
		return
	}
	if logUse(use) {
		applyLogPolicy(use, a)
		return
	}
	if use.InputFacts != nil {
		if err := use.InputFacts.Validate(use.Dependencies); err != nil {
			a.FindingStatus = "needs_evidence"
			a.Protection = "uncertain"
			a.Reason = err.Error()
			return
		}
	}
	a.Protection = a.Answers["protection"]
	if use.Completeness == nil {
		if len(use.Gaps) > 0 {
			a.Protection = "uncertain"
			a.FindingStatus = "needs_evidence"
			a.BlockingGaps = use.Gaps
			a.Reason = "candidate has no claim-scoped completeness evidence"
		}
		return
	}
	c := use.Completeness
	if c.ClaimKind == "injection" {
		switch a.Answers["injection_protection"] {
		case "vulnerable":
			a.Protection = "insufficient"
		case "protected":
			a.Protection = "sufficient"
		default:
			a.Protection = "uncertain"
		}
	}
	blockers := append([]analysis.Gap{}, c.Blockers...)
	if c.ClaimKind == "injection" && a.Answers["injection_protection"] == "vulnerable" {
		for _, role := range []string{"sql_all_inputs_hex", "selector_type_guard", "selector_path_string"} {
			if len(c.Evidence[role]) > 0 {
				blockers = append(blockers, analysis.Gap{Kind: "injection_constraint_review", Detail: "Vulnerable answer requires independent review against supplied " + role + " evidence; no constraint bypass is established by this bounded policy", At: use.Sink.Span})
			}
		}
	}
	requiredRoles := append([]string{}, c.Required...)
	if use.APIModel != nil && use.APIModel.ID == "mongoose-path-id-objectid-v1" {
		requiredRoles = append(requiredRoles, "selector_path_string")
	}
	if use.Components != nil {
		for _, role := range use.Components.Required {
			found := false
			for _, existing := range requiredRoles {
				if existing == role {
					found = true
				}
			}
			if !found {
				requiredRoles = append(requiredRoles, role)
			}
		}
	}
	for _, required := range requiredRoles {
		if len(c.Evidence[required]) == 0 {
			blockers = append(blockers, analysis.Gap{Kind: "required_evidence_missing", Detail: required, At: use.Sink.Span})
		}
	}
	if c.ClaimKind == "injection" {
		if use.APIModel == nil {
			blockers = append(blockers, analysis.Gap{Kind: "api_contract_missing", Detail: "verified operation contract is required"})
		}
		for _, role := range []string{"input_source", "sink_binding", "invoked_callable", "control_flow"} {
			if len(c.Evidence[role]) == 0 {
				blockers = append(blockers, analysis.Gap{Kind: "injection_evidence_missing", Detail: role})
			}
		}
		if use.Kind == "nosql_query_candidate" {
			for _, name := range []string{"source_coverage", "library_coverage", "guard_coverage", "path_coverage"} {
				answer := a.Answers[name]
				if answer != "yes" {
					blockers = append(blockers, analysis.Gap{Kind: "injection_semantic_coverage", Detail: name + ": " + answer})
				}
			}
		}
	}
	if use.APIModel != nil && use.APIModel.ID == "mongoose-find-by-id-objectid-v1" {
		if use.InputFacts == nil {
			blockers = append(blockers, analysis.Gap{Kind: "input_facts_missing", Detail: "source/type/transfer facts are required"})
		} else {
			blockers = append(blockers, use.InputFacts.Gaps...)
			if a.Answers["injection_protection"] == "vulnerable" && use.InputFacts.ScalarInputs() {
				blockers = append(blockers, analysis.Gap{Kind: "injection_constraint_review", Detail: "scalar sink operands contradict operator injection; no bypass is established"})
			}
			if a.Answers["injection_protection"] == "protected" && !use.InputFacts.ScalarInputs() && !use.InputFacts.HasValueControls() && len(c.Evidence["selector_type_guard"]) == 0 {
				blockers = append(blockers, analysis.Gap{Kind: "input_type_unresolved", Detail: "protection needs scalar sink facts or supplied enforcing controls"})
			}
		}
	}
	a.BlockingGaps = blockers
	if len(blockers) > 0 {
		a.Protection = "uncertain"
		a.FindingStatus = "needs_evidence"
		a.Reason = "claim-relevant evidence is incomplete; model answers and unrelated coverage gaps are retained"
		return
	}
	if c.ClaimKind == "injection" {
		switch a.Answers["injection_protection"] {
		case "vulnerable":
			if use.Kind == "nosql_query_candidate" && a.Answers["all_paths_protected"] != "no" {
				a.FindingStatus = "needs_evidence"
				a.Protection = "uncertain"
				a.Reason = "Injection and per-path protection answers do not consistently establish an unsafe branch."
				return
			}
			a.FindingStatus = "confirmed_vulnerability"
			a.Reason = "Source-backed injection claim has required source, binding and path evidence, no declared blockers, and an independent injection-specific insufficient-protection assessment; this is a static judgment, not runtime confirmation."
		case "protected":
			if use.Kind == "nosql_query_candidate" && a.Answers["all_paths_protected"] != "yes" {
				a.FindingStatus = "needs_evidence"
				a.Protection = "uncertain"
				a.Reason = "Protection was not established on all relevant conditional paths."
				return
			}
			a.FindingStatus = "protected_for_claim"
			a.Reason = "Injection-specific assessment supports syntax protection for the supplied claim; field validation and construction practice remain separate."
		case "not_applicable":
			a.FindingStatus = "not_applicable"
		default:
			a.FindingStatus = "needs_evidence"
			a.Reason = "Injection-specific assessment is missing or uncertain; construction-practice answers cannot establish injection."
		}
		return
	}
	switch a.Protection {
	case "insufficient":
		a.FindingStatus = "supported_potential"
		a.Reason = "source-backed claim has no declared blocking gaps; this is not runtime confirmation"
	case "sufficient":
		a.FindingStatus = "protected_for_claim"
		a.Reason = "assessment applies only to the stated constraint and supplied analysis scope"
	case "not_applicable":
		a.FindingStatus = "not_applicable"
	default:
		a.FindingStatus = "needs_evidence"
	}
}
