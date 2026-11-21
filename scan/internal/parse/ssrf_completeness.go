package parse

import "github.com/zazzcode/zazzles/scan/internal/analysis"

// ssrfRequiredRoles are the mandatory evidence obligations of the claim,
// unioned with the catalog's selected obligations by policy.
var ssrfRequiredRoles = []string{"input_source", "sink_binding", "invoked_callable", "control_flow", "destination_operand"}

const ssrfScope = "server-side request forgery claim over the supplied entry invocation, verified outbound client contract, the destination operand and guard/transfer context; request data sent as body or headers is not destination control"

// SSRFCompleteness builds the claim-scoped completeness shared by every
// language adapter.
func SSRFCompleteness(u *analysis.CandidateUse, extraRoles map[string][]analysis.Evidence, blockers, coverage []analysis.Gap) *analysis.Completeness {
	roles := namespacedRoles(u, "ssrf_")
	c := &analysis.Completeness{ClaimKind: "ssrf", Required: append([]string{}, ssrfRequiredRoles...), Evidence: roles, Blockers: blockers, Coverage: coverage, Scope: ssrfScope}
	if c.Blockers == nil {
		c.Blockers = []analysis.Gap{}
	}
	if c.Coverage == nil {
		c.Coverage = []analysis.Gap{}
	}
	for role, items := range extraRoles {
		c.Evidence[role] = append(c.Evidence[role], items...)
	}
	for _, d := range u.Dependencies {
		c.Evidence["input_source"] = append(c.Evidence["input_source"], d.Source)
	}
	c.Evidence["destination_operand"] = append(c.Evidence["destination_operand"], u.Sink)
	if len(c.Evidence["invoked_callable"]) == 0 {
		c.Evidence["invoked_callable"] = append([]analysis.Evidence{}, c.Evidence["handler"]...)
	}
	return c
}
