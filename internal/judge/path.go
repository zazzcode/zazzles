package judge

import (
	"fmt"
	"strings"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
)

// pathRoles are the Go-mandatory evidence obligations; selected catalog
// obligations are unioned with them and can never remove one.
var pathRoles = []string{"input_source", "sink_binding", "invoked_callable", "control_flow", "path_operands"}

func hasTransform(f analysis.PathFlow, kinds ...string) bool {
	for _, t := range f.Transforms {
		for _, k := range kinds {
			if t == k {
				return true
			}
		}
	}
	return false
}

// guardKindsOf returns the classified kinds of the controls attached to a flow.
func guardKindsOf(f *analysis.PathFacts, flow analysis.PathFlow) []string {
	var kinds []string
	for _, i := range flow.Controls {
		kinds = append(kinds, f.Guards[i].Kind)
	}
	return kinds
}

func enforcingGuard(f *analysis.PathFacts, flow analysis.PathFlow, kinds ...string) bool {
	for _, k := range guardKindsOf(f, flow) {
		for _, want := range kinds {
			if k == want {
				return true
			}
		}
	}
	return false
}

// anyEnforcing reports a control that can establish containment on the flow.
func anyEnforcing(f *analysis.PathFacts, flow analysis.PathFlow) bool {
	for _, k := range guardKindsOf(f, flow) {
		if analysis.EnforcingPathGuard(k) {
			return true
		}
	}
	return false
}

// absoluteCanReplaceBase reports whether an absolute request value can replace the
// trusted base in the operand construction, so a '..' text check cannot contain it.
// path.join and string concatenation append an absolute value; path.resolve,
// os.path.join and the pathlib / operator replace the base with it.
func absoluteCanReplaceBase(f analysis.PathFlow, python bool) bool {
	if hasTransform(f, analysis.PathTransformConcat, analysis.PathTransformTemplate) {
		return false
	}
	if python {
		return true
	}
	if hasTransform(f, analysis.PathTransformResolve) {
		return true
	}
	return !hasTransform(f, analysis.PathTransformJoin)
}

// unsafeWitness reports a flow that independently establishes traversal: raw, or
// guarded only by controls that cannot establish containment. A bare prefix
// check, an unclassified control, a reduction such as basename and a '..' text
// check that the construction already neutralizes are not witnesses.
func unsafeWitness(f *analysis.PathFacts, flow analysis.PathFlow, python bool) bool {
	if hasTransform(flow, analysis.PathTransformReduce) {
		return false
	}
	if flow.Operand == analysis.PathSlotArchive && (f.Extractor == nil || f.Extractor.Assessment != "vulnerable_version") {
		// Entry names reach the destination only through a release known not to
		// validate them; a fixed, ranged or undeclared release is not a witness.
		return false
	}
	switch flow.Protection {
	case "raw":
		return true
	case "guarded":
		for _, k := range guardKindsOf(f, flow) {
			if !analysis.KnownNonEnforcingPathGuard(k) {
				return false
			}
		}
		if flow.DecodedAfterGuard {
			return true
		}
		for _, k := range guardKindsOf(f, flow) {
			if k == analysis.PathGuardDotDotText && !absoluteCanReplaceBase(flow, python) {
				return false
			}
			if k == analysis.PathGuardSubstring && flow.NormalizedBeforeGuard {
				return false
			}
		}
		return true
	}
	return false
}

// weakControlsOnly reports that every request-derived flow is guarded and every
// control on it is a recognized weak kind: a prefix comparison without a separator
// boundary, a normalized positive substring check, a '..' text test or a separator-only test.
// Such a control is poor practice (it does not establish containment) without being a proven
// exploit; an unclassified control is not recognized and never counts here.
func weakControlsOnly(f *analysis.PathFacts) bool {
	if len(f.Paths) == 0 {
		return false
	}
	for _, flow := range f.Paths {
		if flow.Protection != "guarded" || len(flow.Controls) == 0 || hasTransform(flow, analysis.PathTransformReduce) {
			return false
		}
		for _, k := range guardKindsOf(f, flow) {
			switch k {
			case analysis.PathGuardPrefixBare, analysis.PathGuardDotDotText, analysis.PathGuardSeparatorText, analysis.PathGuardSubstring:
			default:
				return false
			}
		}
	}
	return true
}

func applyPathPolicy(use analysis.CandidateUse, a *analysis.Assessment) {
	a.FindingStatus, a.Protection = "needs_evidence", "uncertain"
	var blockers []analysis.Gap
	add := func(kind, detail string) {
		blockers = append(blockers, analysis.Gap{Kind: kind, Detail: detail, At: use.Sink.Span})
	}
	if a.QuestionVersion != analysispacks.PathProtocol {
		add("path_protocol_missing", "Path-specific versioned answers are required.")
	}
	c, f := use.Completeness, use.Path
	if f == nil || c == nil || c.ClaimKind != "path_traversal" || use.APIModel == nil || use.APIModel.ID != f.ContractID {
		add("path_claim_missing", "Source-backed path facts, verified operation contract and completeness are required.")
		a.BlockingGaps = blockers
		a.Reason = "The path claim lacks source-backed facts or a verified operation contract."
		return
	}
	if err := f.Validate(len(use.Dependencies), len(use.Context)); err != nil {
		add("path_facts_invalid", err.Error())
	}
	roles := append([]string{}, pathRoles...)
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
			add("path_evidence_missing", role)
		}
	}
	python := strings.HasSuffix(use.Sink.Span.File, ".py")
	ans := a.Answers

	// Consistency gates: answers must agree with the established facts.
	var contradictions []string
	contradict := func(format string, args ...any) {
		contradictions = append(contradictions, fmt.Sprintf(format, args...))
	}
	witness, guardedAll, rawAny, unknownAny, decodedAny := false, len(f.Paths) > 0, false, false, false
	for _, flow := range f.Paths {
		witness = witness || unsafeWitness(f, flow, python)
		guardedAll = guardedAll && flow.Protection == "guarded" && anyEnforcing(f, flow)
		rawAny = rawAny || flow.Protection == "raw"
		unknownAny = unknownAny || flow.Protection == "unknown"
		decodedAny = decodedAny || flow.DecodedAfterGuard
	}
	if len(f.Paths) == 0 {
		contradict("no request-derived path flow is recorded")
	}
	switch ans["path_traversal"] {
	case "vulnerable":
		if !witness && !weakControlsOnly(f) {
			contradict("traversal claimed but no request-derived flow is an independent unsafe witness (raw, or guarded only by controls that cannot establish containment)")
		}
	case "protected":
		if !guardedAll {
			contradict("protection claimed without an enforcing-capable control (allow-list, separator-bounded prefix, relative or commonpath check) on every request-derived path")
		}
	case "not_applicable":
		contradict("path facet marked not applicable although a request-derived value reaches the effective path operand")
	}
	switch ans["containment_control"] {
	case "finite_allowlist":
		for _, flow := range f.Paths {
			if !enforcingGuard(f, flow, analysis.PathGuardAllowlist) {
				contradict("allow-list containment claimed without an allow-list control on every request-derived path")
				break
			}
		}
	case "lexical_boundary", "resolved_boundary":
		for _, flow := range f.Paths {
			if !enforcingGuard(f, flow, analysis.PathGuardPrefixBoundary, analysis.PathGuardRelative, analysis.PathGuardCommonPath, analysis.PathGuardComponentSanitizer, analysis.PathGuardFrameworkRoot, analysis.PathGuardLibraryEntryCheck) {
				contradict("boundary containment claimed without a separator-bounded prefix, relative or commonpath control on every request-derived path")
				break
			}
		}
		if ans["containment_control"] == "resolved_boundary" {
			for _, flow := range f.Paths {
				if !hasTransform(flow, analysis.PathTransformRealpath) || !flow.RealpathBeforeGuard {
					contradict("symbolic-link-resolved containment claimed but a request-derived path is not produced by a realpath/resolve call before the boundary check in the supplied source")
					break
				}
			}
		}
	case "none":
		if ans["path_traversal"] == "protected" {
			contradict("protection claimed with no enforced containment")
		}
	}
	if decodedAny && (ans["path_traversal"] == "protected" || ans["protection_coverage"] == "complete") {
		contradict("a decoding step follows the control on a request-derived path, so the control does not cover the decoded value")
	}
	if unknownAny && ans["protection_coverage"] == "complete" {
		contradict("coverage marked complete although a request-derived path has unresolved facts")
	}
	if rawAny && ans["protection_coverage"] == "complete" && ans["path_traversal"] == "protected" {
		contradict("coverage marked complete although a request-derived path reaches the operand without a control")
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
	scoped := append(append([]analysis.Gap{}, blockers...), global...)
	if len(contradictions) > 0 {
		a.BlockingGaps = append(append(blockers, c.Blockers...), analysis.Gap{Kind: "path_answers_inconsistent", Detail: strings.Join(contradictions, "; "), At: use.Sink.Span})
		a.Reason = "Path answers contradict the source-backed facts; raw answers are retained and no status is claimed from them."
		return
	}
	if ans["path_traversal"] == "vulnerable" && ans["containment_control"] == "none" && witness && len(scoped) == 0 {
		a.BlockingGaps = nil
		a.FindingStatus, a.Protection = "confirmed_vulnerability", "insufficient"
		a.Reason = "A consistent traversal answer is supported by an independent source-to-operand path with a verified " + f.Operation + " binding under the declared " + f.Platform + " assumption; no enforced containment is established. Unresolved sibling paths remain visible. This is a static judgment, not runtime exploitation, symbolic-link or filesystem-state analysis, or independent Findings Review."
		return
	}
	if ans["path_traversal"] == "vulnerable" && ans["containment_control"] == "none" && !witness && weakControlsOnly(f) && len(scoped) == 0 {
		a.BlockingGaps = nil
		a.FindingStatus, a.Protection = "poor_practice", "insufficient"
		a.Reason = "Every request-derived path is guarded only by a recognized weak control (a prefix comparison without a separator boundary, a '..' text test or a separator-only test) that does not establish containment, and the assessment finds no enforced containment. This is a construction-practice finding, not a confirmed exploit: whether a sibling path or a decoded value can pass the control depends on the filesystem layout and inputs, which are not inferred."
		return
	}
	a.BlockingGaps = append(append([]analysis.Gap{}, blockers...), c.Blockers...)
	if len(a.BlockingGaps) > 0 {
		a.Reason = "Claim-relevant path evidence is incomplete; raw answers and unrelated coverage gaps are retained."
		return
	}
	switch ans["containment_control"] {
	case "finite_allowlist", "lexical_boundary", "resolved_boundary":
		if ans["path_traversal"] == "protected" && ans["protection_coverage"] == "complete" && guardedAll && !rawAny && !unknownAny {
			a.FindingStatus, a.Protection = "protected_for_claim", "sufficient"
			a.Reason = "Every request-derived path is covered by a source-backed enforcing control on the same value with complete coverage under the declared " + f.Platform + " assumption; this applies only to the stated claim and does not address symbolic links created after the check unless a resolved boundary was established."
			return
		}
	}
	a.Reason = "The path assessment is inconclusive; unknown answers, an unsafe path without a complete witness, a bare prefix comparison or incomplete coverage cannot support protection or a finding."
}
