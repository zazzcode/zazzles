package judge

import (
	"fmt"
	"strings"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
)

// ssrfRoles are the Go-mandatory evidence obligations; selected catalog
// obligations are unioned with them and can never remove one.
var ssrfRoles = []string{"input_source", "sink_binding", "invoked_callable", "control_flow", "destination_operand"}

// applySSRFPolicy classifies a server-side request forgery answer only when it
// agrees with the source-backed destination facts. Model confidence never
// fills a missing binding, path or control.
func applySSRFPolicy(use analysis.CandidateUse, a *analysis.Assessment) {
	a.FindingStatus, a.Protection = "needs_evidence", "uncertain"
	var blockers []analysis.Gap
	add := func(kind, detail string) {
		blockers = append(blockers, analysis.Gap{Kind: kind, Detail: detail, At: use.Sink.Span})
	}
	if a.QuestionVersion != analysispacks.SSRFProtocol {
		add("ssrf_protocol_missing", "SSRF-specific versioned answers are required.")
	}
	c, f := use.Completeness, use.Outbound
	if f == nil || c == nil || c.ClaimKind != "ssrf" || use.APIModel == nil || use.APIModel.ID != f.ContractID {
		add("ssrf_claim_missing", "Source-backed destination facts, a verified client contract and completeness are required.")
		a.BlockingGaps = blockers
		a.Reason = "The SSRF claim lacks source-backed destination facts or a verified client contract."
		return
	}
	if err := f.Validate(len(use.Dependencies), len(use.Context)); err != nil {
		add("ssrf_facts_invalid", err.Error())
	}
	if f.DestinationOrigin != analysis.DestinationRequest || len(f.Paths) == 0 {
		add("ssrf_destination_not_request", "No request-derived path to the destination operand is recorded.")
	}
	roles := append([]string{}, ssrfRoles...)
	roles = append(roles, c.Required...)
	if use.Components != nil {
		roles = append(roles, use.Components.Required...)
	}
	seen := map[string]bool{}
	for _, role := range roles {
		if !seen[role] {
			seen[role] = true
			if len(c.Evidence[role]) == 0 {
				add("ssrf_evidence_missing", role)
			}
		}
	}
	ans := a.Answers
	rawAny, unknownAny, guardedAll := false, false, len(f.Paths) > 0
	for _, p := range f.Paths {
		rawAny = rawAny || p.Protection == "raw"
		unknownAny = unknownAny || p.Protection == "unknown"
		guardedAll = guardedAll && p.Protection == "guarded"
	}
	var contradictions []string
	contradict := func(format string, args ...any) {
		contradictions = append(contradictions, fmt.Sprintf(format, args...))
	}
	if ans["destination_control"] == "none" {
		contradict("destination control marked none although a request-derived value reaches the destination operand")
	}
	switch ans["destination_restriction"] {
	case "host_allowlist", "scheme_and_host_check":
		if !guardedAll {
			contradict("a destination restriction is claimed without a source-backed control on every request-derived destination path")
		}
	}
	if unknownAny && ans["protection_coverage"] == "complete" {
		contradict("coverage marked complete although a request-derived destination path has unresolved facts")
	}
	if rawAny && ans["protection_coverage"] == "complete" && ans["destination_restriction"] != "none" && ans["destination_restriction"] != "prefix_only" {
		contradict("coverage marked complete with a restriction although a request-derived destination path has no control")
	}
	// A raw witness is scoped to its own source-to-destination path; unresolved
	// siblings and chain gaps stay visible without voiding an independent witness.
	global := []analysis.Gap{}
	for _, g := range c.Blockers {
		touches := false
		for _, d := range use.Dependencies {
			touches = touches || gapTouchesCommandDependency(g, d)
		}
		if !touches {
			global = append(global, g)
		}
	}
	scoped := append(append([]analysis.Gap{}, blockers...), global...)
	if len(contradictions) > 0 {
		a.BlockingGaps = append(append(blockers, c.Blockers...), analysis.Gap{Kind: "ssrf_answers_inconsistent", Detail: strings.Join(contradictions, "; "), At: use.Sink.Span})
		a.Reason = "SSRF answers contradict the source-backed facts; raw answers are retained and no status is claimed from them."
		return
	}
	hostControl := ans["destination_control"] == "full_url" || ans["destination_control"] == "host"
	restriction := ans["destination_restriction"]
	if restriction == "prefix_only" && hasModelFact(c, "url_scheme_only_test") {
		// Source-established: every raw-text URL test fixes only the scheme, so
		// the prefix test the model found restricts no host.
		restriction = "none"
	}
	if hostControl && restriction == "none" && rawAny && len(scoped) == 0 {
		a.BlockingGaps = nil
		a.FindingStatus, a.Protection = "confirmed_vulnerability", "insufficient"
		a.Reason = "A consistent SSRF answer is supported by an independent request-to-destination path through a verified " + f.Operation + " binding with no enforced destination restriction. Unresolved sibling paths remain visible. This is a static judgment, not runtime network reachability, DNS or redirect analysis, or independent Findings Review."
		return
	}
	if hostControl && restriction == "prefix_only" && len(scoped) == 0 {
		a.BlockingGaps = nil
		a.FindingStatus, a.Protection = "poor_practice", "insufficient"
		a.Reason = "The request controls the destination host and only an unparsed string prefix, substring or pattern test restricts it. That is a construction-practice finding: userinfo, alternative host forms and redirects can pass such a test, but whether one does here is not inferred."
		return
	}
	a.BlockingGaps = append(append([]analysis.Gap{}, blockers...), c.Blockers...)
	if len(a.BlockingGaps) > 0 {
		a.Reason = "Claim-relevant SSRF evidence is incomplete; raw answers and unrelated coverage gaps are retained."
		return
	}
	switch ans["destination_restriction"] {
	case "host_allowlist", "scheme_and_host_check":
		if ans["protection_coverage"] == "complete" && guardedAll && !rawAny && !unknownAny {
			a.FindingStatus, a.Protection = "protected_for_claim", "sufficient"
			a.Reason = "Every request-derived destination path is covered by a source-backed control on the same value that restricts scheme and host, with complete coverage; this applies only to the stated claim and does not establish network policy or redirect behavior beyond the supplied source."
			return
		}
	}
	if ans["destination_control"] == "path_or_query" {
		a.Reason = "The request controls only the path or query of a fixed host according to the assessment; that is not destination host control and no SSRF status is claimed. Review the target API for path-based effects separately."
		return
	}
	a.Reason = "The SSRF assessment is inconclusive; unknown answers, an unsafe path without a complete witness or incomplete coverage cannot support protection or a finding."
}

// hasModelFact reports a source-established fact code on the claim.
func hasModelFact(c *analysis.Completeness, code string) bool {
	for _, f := range c.ModelFacts {
		if f == code || strings.HasPrefix(f, code+":") {
			return true
		}
	}
	return false
}
