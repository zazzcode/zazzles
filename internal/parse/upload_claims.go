package parse

import "github.com/zazzcode/zazzles/internal/analysis"

// uploadRequiredRoles are the mandatory evidence obligations of an upload
// claim (close-findings-gaps W5).
var uploadRequiredRoles = []string{"input_source", "sink_binding", "invoked_callable", "control_flow", "upload_operand"}

const uploadScope = "unrestricted-upload claim over one verified upload write: stored-name origin, server-side type controls dominating the write and the destination; path containment is a separate claim"

// UploadCompleteness builds the claim-scoped completeness shared by the
// language adapters. Roles carry the adapter's source evidence.
func UploadCompleteness(u *analysis.CandidateUse, roles map[string][]analysis.Evidence, blockers, coverage []analysis.Gap) *analysis.Completeness {
	c := &analysis.Completeness{ClaimKind: "upload", Required: append([]string{}, uploadRequiredRoles...), Evidence: map[string][]analysis.Evidence{},
		Blockers: append([]analysis.Gap{}, blockers...), Coverage: append([]analysis.Gap{}, coverage...), Scope: uploadScope}
	for role, items := range roles {
		c.Evidence[role] = append(c.Evidence[role], items...)
	}
	for _, d := range u.Dependencies {
		c.Evidence["input_source"] = append(c.Evidence["input_source"], d.Source)
	}
	return c
}
