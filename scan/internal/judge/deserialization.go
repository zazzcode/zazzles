package judge

import (
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
)

func applyDeserializationPolicy(use analysis.CandidateUse, a *analysis.Assessment) {
	a.FindingStatus, a.Protection = "needs_evidence", "uncertain"
	gap := func(kind, detail string) {
		a.Reason = detail
		a.BlockingGaps = append(a.BlockingGaps, analysis.Gap{Kind: "deserialization_" + kind, Detail: detail, At: use.Sink.Span})
	}
	if a.QuestionVersion != analysispacks.DeserializationProtocol {
		gap("protocol_missing", "Versioned deserialization answers are required.")
		return
	}
	f, c := use.Deserialization, use.Completeness
	if f == nil || c == nil || c.ClaimKind != "deserialization" || use.APIModel == nil || f.ContractID != use.APIModel.ID {
		gap("claim_missing", "Deserialization requires source-backed facts, completeness and a verified contract.")
		return
	}
	if err := f.Validate(len(use.Dependencies), len(use.Context)); err != nil {
		gap("facts_invalid", err.Error())
		return
	}
	for _, role := range append([]string{"input_source", "sink_binding", "invoked_callable", "control_flow", "deserialization_operand"}, c.Required...) {
		if len(c.Evidence[role]) == 0 {
			gap("evidence_missing", "Missing deserialization evidence role "+role+".")
			return
		}
	}
	var request, rawRequest, unknown, controlled bool
	allGuarded := true
	for _, p := range f.Paths {
		if use.Dependencies[p.Dependency].Source.Kind == "input_source" {
			request = true
			rawRequest = rawRequest || p.Protection == "raw"
		}
		allGuarded = allGuarded && p.Protection == "guarded"
		unknown = unknown || p.Protection == "unknown"
		controlled = controlled || len(p.Controls) > 0
	}
	if !request {
		gap("origin_unresolved", "A request origin for the data operand is missing.")
		return
	}
	controls := map[string]bool{}
	for _, control := range f.Controls {
		controls[control.Kind] = true
	}
	ans := a.Answers
	exposure, integrity, classes, coverage := ans["deserialization_exposure"], ans["integrity_control"], ans["class_restriction"], ans["protection_coverage"]
	if exposure == "not_applicable" && rawRequest || exposure == "protected" && !controlled ||
		integrity == "verified_before_decode" && !controls[analysis.DeserializationIntegrity] ||
		classes == "adequate" && !controls[analysis.DeserializationClassList] || coverage == "complete" && unknown {
		gap("answers_inconsistent", "The answers contradict the recorded controls or operand paths.")
		return
	}
	if f.Capability == analysis.DeserializationUnresolved || f.Capability == analysis.DeserializationRestrictedTypes {
		detail := "The operation has " + f.Capability + " capability."
		if f.OptionGap != "" {
			detail += " Option evidence gap: " + f.OptionGap + "."
		}
		gap("capability_unresolved", detail)
		return
	}
	a.BlockingGaps = append(a.BlockingGaps, c.Blockers...)
	if len(a.BlockingGaps) > 0 {
		a.Reason = "Claim-relevant deserialization evidence is incomplete."
		return
	}
	if allGuarded && exposure == "protected" && coverage == "complete" && (integrity == "verified_before_decode" || classes == "adequate") {
		a.FindingStatus, a.Protection = "protected_for_claim", "sufficient"
		a.Reason = "The recorded protection is enforced on every data operand path."
		return
	}
	if exposure == "vulnerable" && rawRequest && (integrity == "none" || integrity == "present_inadequate") && (classes == "none" || classes == "inadequate") {
		a.FindingStatus, a.Protection = "confirmed_vulnerability", "insufficient"
		a.Reason = "Request-controlled bytes reach the verified deserializer on a raw path."
		return
	}
	a.Reason = "The answers do not establish a complete vulnerable or protected path."
}
