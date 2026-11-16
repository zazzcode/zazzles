package judge

import (
	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
	"strconv"
)

func applyInterpreterPolicy(use analysis.CandidateUse, a *analysis.Assessment) {
	family, protocol, contract := "code", analysispacks.CodeProtocol, ""
	if use.Code != nil {
		contract = use.Code.ContractID
	}
	if use.Kind == "open_redirect_candidate" {
		family, protocol = "redirect", analysispacks.RedirectProtocol
		if use.Redirect != nil {
			contract = use.Redirect.ContractID
		}
	}
	a.FindingStatus, a.Protection = "needs_evidence", "uncertain"
	add := func(kind, detail string) {
		a.BlockingGaps = append(a.BlockingGaps, analysis.Gap{Kind: family + "_" + kind, Detail: detail, At: use.Sink.Span})
	}
	a.BlockingGaps = nil
	c := use.Completeness
	paths := use.CodePaths()
	if a.QuestionVersion != protocol {
		add("protocol_missing", "Versioned family answers required")
	}
	if contract == "" || c == nil || c.ClaimKind != family || use.APIModel == nil || use.APIModel.ID != contract || len(paths) == 0 {
		add("claim_missing", "Verified operand facts, contract and completeness required")
		return
	}
	if use.Code != nil {
		if err := use.Code.Validate(len(use.Dependencies), len(use.Context)); err != nil {
			add("facts_invalid", err.Error())
		}
	}
	if use.Redirect != nil {
		if err := use.Redirect.Validate(len(use.Dependencies), len(use.Context)); err != nil {
			add("facts_invalid", err.Error())
		}
	}
	for _, d := range use.Dependencies {
		switch d.Source.Kind {
		case "input_source", "browser_source", "browser_event_source", "event_input_binding":
		default:
			add("origin_unresolved", "The operand origin is not established as request/browser-controlled")
		}
	}
	roles := append([]string{"input_source", "sink_binding", "invoked_callable", "control_flow", family + "_operand"}, c.Required...)
	if use.Components != nil {
		roles = append(roles, use.Components.Required...)
	}
	for _, role := range roles {
		if len(c.Evidence[role]) == 0 {
			add("evidence_missing", role)
		}
	}
	raw, unknown, guarded := false, false, true
	for _, p := range paths {
		if p.Dependency < 0 || p.Dependency >= len(use.Dependencies) || use.Dependencies[p.Dependency].SinkSlot != p.Operand {
			add("facts_invalid", "Operand path references an absent dependency or slot")
		}
		for _, i := range p.Controls {
			if i < 0 || i >= len(use.Context) {
				add("facts_invalid", "Control index out of bounds")
			}
		}
		raw = raw || p.Protection == "raw"
		unknown = unknown || p.Protection == "unknown"
		guarded = guarded && p.Protection == "guarded"
		if p.Protection != "raw" && p.Protection != "guarded" && p.Protection != "unknown" {
			add("facts_invalid", "Invalid path protection")
		}
	}
	pathBlockers := []analysis.Gap{}
	for _, g := range c.Blockers {
		touches := false
		for _, d := range use.Dependencies {
			touches = touches || gapTouchesCommandDependency(g, d)
		}
		if touches {
			pathBlockers = append(pathBlockers, g)
		} else {
			a.BlockingGaps = append(a.BlockingGaps, g)
		}
	}
	ans := a.Answers
	control, restriction := ans["code_control"], ans["code_restriction"]
	effective := restriction == "allowlist_grammar" || restriction == "type_conversion"
	if family == "redirect" {
		control, restriction = ans["destination_control"], ans["destination_restriction"]
		effective = restriction == "same_site_relative" || restriction == "parsed_origin_check" || restriction == "host_allowlist"
	}
	// Transform protection requires a constraint on the complete operand, not
	// merely a converted occurrence of a source also used raw in that operand.
	transformed := family == "code" && len(c.Evidence["code_constrained_operand"]) > 0

	if effective && !guarded && !transformed || unknown && ans["protection_coverage"] == "complete" || control == "none" || family == "code" && control == "data_only" || family == "redirect" && control == "fixed_origin" {
		add("answers_inconsistent", "The answers contradict the recorded operand paths and controls")
		a.Reason = "Answers contradict source-established operand facts."
		return
	}
	if len(a.BlockingGaps) > 0 {
		a.Reason = "Claim-relevant binding, flow or control evidence is incomplete."
		return
	}
	if len(pathBlockers) > 0 && (effective || !raw && !guarded) {
		a.BlockingGaps = append(a.BlockingGaps, pathBlockers...)
		a.Reason = "Claim-relevant operand paths remain unresolved."
		return
	}

	if effective && (guarded || transformed) && ans["protection_coverage"] == "complete" && !unknown {
		a.FindingStatus, a.Protection = "protected_for_claim", "sufficient"
		a.Reason = "Every operand path has a source-established enforcing guard or constraining conversion."
		return
	}
	if use.Code != nil && use.Code.ContractID == "js-safe-eval-libs-v1" {
		restriction = "sandbox_library"
	}
	if family == "code" && restriction == "sandbox_library" {
		if hasModelFact(c, "sandbox_library_advisory") {
			a.FindingStatus, a.Protection = "poor_practice", "insufficient"
			a.Reason = "The code evaluator relies on a library with a source-established sandbox bypass advisory."
		}
		return
	}
	if family == "redirect" && restriction == "prefix_or_substring" {
		safeAll := true
		substringWitness := false
		for _, p := range paths {
			safe := redirectSafePrefixPath(use, c, p)
			safeAll = safeAll && safe
			substringWitness = substringWitness || !safe && len(c.Evidence["redirect_raw_substring_path_"+strconv.Itoa(p.Dependency)]) > 0
		}
		if safeAll && guarded && ans["protection_coverage"] == "complete" {
			a.FindingStatus, a.Protection = "protected_for_claim", "sufficient"
			a.Reason = "Every destination path enforces a literal full-origin prefix with a trailing slash."
			return
		}
		if substringWitness || hasModelFact(c, "url_scheme_only_test") {
			restriction = "none"
			raw = true
		} else {
			a.FindingStatus, a.Protection = "poor_practice", "insufficient"
			a.Reason = "An unparsed destination prefix is the only established restriction."
			return
		}
	}

	controlled := control == "whole_program" || control == "inside_string_literal"
	if family == "redirect" {
		controlled = control == "full_url" || control == "host" || control == "path_only"
	}
	if controlled && (restriction == "none" || family == "code" && restriction == "blacklist_only") && raw {
		a.FindingStatus, a.Protection = "confirmed_vulnerability", "insufficient"
		a.Reason = "A request-derived operand reaches a verified " + family + " operation on a complete raw path without an effective restriction."
		return
	}
	a.BlockingGaps = append(a.BlockingGaps, pathBlockers...)
	a.Reason = "The supplied answers do not establish a complete vulnerable or protected operand path."
}

func redirectSafePrefixPath(u analysis.CandidateUse, c *analysis.Completeness, p analysis.CommandPath) bool {
	for _, i := range p.Controls {
		if i < 0 || i >= len(u.Context) {
			continue
		}
		guard := u.Context[i]
		for _, ev := range c.Evidence["redirect_origin_prefix"] {
			if guard.Span.File == ev.Span.File && guard.Span.StartByte <= ev.Span.StartByte && guard.Span.EndByte >= ev.Span.EndByte {
				return true
			}
		}
	}
	return false
}
