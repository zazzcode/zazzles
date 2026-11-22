package judge

import (
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
)

func policyEvidence(kind string, line int) analysis.Evidence {
	return analysis.Evidence{Kind: kind, Text: kind, Span: analysis.Span{File: "src/App.php", StartLine: line, EndLine: line, StartByte: line * 10, EndByte: line*10 + 5}, SHA256: "h"}
}

func exposurePolicyUse(guards int, served string, gaps ...string) analysis.CandidateUse {
	f := &analysis.ExposureFacts{Operation: "phpinfo", Subject: analysis.ExposureConfiguration, EntryServed: served}
	for i := 0; i < guards; i++ {
		f.Guards = append(f.Guards, policyEvidence("branch_false_precondition", 2+i))
	}
	c := &analysis.Completeness{ClaimKind: "exposure", Required: analysispacks.ExposureRoles(), Evidence: map[string][]analysis.Evidence{}}
	for _, role := range analysispacks.ExposureRoles() {
		c.Evidence[role] = []analysis.Evidence{policyEvidence(role, 5)}
	}
	u := analysis.CandidateUse{Kind: analysis.ExposureKind, Sink: policyEvidence(analysis.ExposureKind, 5), Exposure: f, Completeness: c, APIModel: analysispacks.ExposureContract(analysispacks.PHPDiagnosticOutput)}
	for _, g := range gaps {
		gap := analysis.Gap{Kind: g, At: u.Sink.Span}
		u.Gaps = append(u.Gaps, gap)
		c.Blockers = append(c.Blockers, gap)
	}
	return u
}

func TestExposurePolicy(t *testing.T) {
	for _, tt := range []struct {
		rule, version, output, reach string
		use                          func() analysis.CandidateUse
		status, gap                  string
	}{
		{"protocol", "exposure-components-v0", "internal_state", "reachable", func() analysis.CandidateUse { return exposurePolicyUse(0, "yes") }, "needs_evidence", "exposure_protocol_missing"},
		{"claim", "", "internal_state", "reachable", func() analysis.CandidateUse {
			u := exposurePolicyUse(0, "yes")
			u.Completeness.ClaimKind = "injection"
			return u
		}, "needs_evidence", "exposure_claim_missing"},
		{"facts", "", "internal_state", "reachable", func() analysis.CandidateUse {
			u := exposurePolicyUse(0, "yes")
			u.Exposure.Subject = "secrets"
			return u
		}, "needs_evidence", "exposure_facts_invalid"},
		{"evidence", "", "internal_state", "reachable", func() analysis.CandidateUse {
			u := exposurePolicyUse(0, "yes")
			delete(u.Completeness.Evidence, "entry")
			return u
		}, "needs_evidence", "exposure_evidence_missing"},
		{"inconsistent restricted without guard", "", "internal_state", "restricted", func() analysis.CandidateUse { return exposurePolicyUse(0, "yes") }, "needs_evidence", "exposure_answers_inconsistent"},
		{"inconsistent reachable unserved", "", "internal_state", "reachable", func() analysis.CandidateUse { return exposurePolicyUse(0, "no") }, "needs_evidence", "exposure_answers_inconsistent"},
		{"blocking environment-dependent gap", "", "internal_state", "reachable", func() analysis.CandidateUse {
			return exposurePolicyUse(0, "yes", analysis.ExposureEnvironmentDependent)
		}, "needs_evidence", analysis.ExposureEnvironmentDependent},
		{"protected benign", "", "benign", "reachable", func() analysis.CandidateUse { return exposurePolicyUse(0, "yes") }, "protected_for_claim", ""},
		{"protected restricted with guard", "", "internal_state", "restricted", func() analysis.CandidateUse { return exposurePolicyUse(1, "yes") }, "protected_for_claim", ""},
		{"confirmed", "", "internal_state", "reachable", func() analysis.CandidateUse { return exposurePolicyUse(0, "yes") }, "confirmed_vulnerability", ""},
		{"otherwise review", "", "unknown", "reachable", func() analysis.CandidateUse { return exposurePolicyUse(0, "yes") }, "needs_evidence", ""},
	} {
		t.Run(tt.rule, func(t *testing.T) {
			version := tt.version
			if version == "" {
				version = analysispacks.ExposureProtocol
			}
			a := analysis.Assessment{QuestionVersion: version, Answers: map[string]string{"exposure_output": tt.output, "exposure_reach": tt.reach}}
			applyPolicy(tt.use(), &a)
			assertPolicy(t, a, tt.status, tt.gap)
		})
	}
}

func massPolicyUse(fields int, guards ...string) analysis.CandidateUse {
	f := &analysis.MassAssignmentFacts{Shape: analysis.MassAssignmentPropertyWrite, TargetClass: `App\Entity\Account`, TargetStored: "yes", SecurityFields: []analysis.SecurityField{}}
	for i := 0; i < fields; i++ {
		f.SecurityFields = append(f.SecurityFields, analysis.SecurityField{StorageKey: "php-sql:account.grants", Roles: []string{analysis.RoleSource}, Evidence: []analysis.Evidence{policyEvidence(analysis.RoleSource, 9)}})
	}
	for i, g := range guards {
		f.KeyGuards = append(f.KeyGuards, policyEvidence(g, 3+i))
	}
	c := &analysis.Completeness{ClaimKind: "mass_assignment", Required: analysispacks.MassAssignmentRoles(), Evidence: map[string][]analysis.Evidence{}}
	for _, role := range analysispacks.MassAssignmentRoles() {
		c.Evidence[role] = []analysis.Evidence{policyEvidence(role, 7)}
	}
	return analysis.CandidateUse{Kind: analysis.MassAssignmentKind, Sink: policyEvidence(analysis.MassAssignmentKind, 7), MassAssignment: f, Completeness: c}
}

func withGap(u analysis.CandidateUse, kind string, blocker bool) analysis.CandidateUse {
	g := analysis.Gap{Kind: kind, At: u.Sink.Span}
	u.Gaps = append(u.Gaps, g)
	if blocker {
		u.Completeness.Blockers = append(u.Completeness.Blockers, g)
	} else {
		u.Completeness.Coverage = append(u.Completeness.Coverage, g)
	}
	return u
}

func TestMassAssignmentPolicy(t *testing.T) {
	for _, tt := range []struct {
		rule, version, control, restriction, impact string
		use                                         func() analysis.CandidateUse
		status, gap                                 string
	}{
		{"protocol", "mass-assignment-components-v0", "request_chosen", "none", "privileged_field", func() analysis.CandidateUse { return massPolicyUse(1) }, "needs_evidence", "mass_assignment_protocol_missing"},
		{"claim", "", "request_chosen", "none", "privileged_field", func() analysis.CandidateUse { u := massPolicyUse(1); u.Completeness.ClaimKind = "injection"; return u }, "needs_evidence", "mass_assignment_claim_missing"},
		{"facts", "", "request_chosen", "none", "privileged_field", func() analysis.CandidateUse { u := massPolicyUse(1); u.MassAssignment.Shape = "array_merge"; return u }, "needs_evidence", "mass_assignment_facts_invalid"},
		{"evidence", "", "request_chosen", "none", "privileged_field", func() analysis.CandidateUse {
			u := massPolicyUse(1)
			delete(u.Completeness.Evidence, "target_class")
			return u
		}, "needs_evidence", "mass_assignment_evidence_missing"},
		{"inconsistent adequate without allow-list", "", "request_chosen", "adequate", "privileged_field", func() analysis.CandidateUse { return massPolicyUse(1, analysis.KeyExistenceCheck) }, "needs_evidence", "mass_assignment_answers_inconsistent"},
		{"inconsistent privileged without fields", "", "request_chosen", "none", "privileged_field", func() analysis.CandidateUse { return massPolicyUse(0) }, "needs_evidence", "mass_assignment_answers_inconsistent"},
		{"inconsistent fixed with whole bag", "", "fixed", "none", "privileged_field", func() analysis.CandidateUse { return massPolicyUse(1) }, "needs_evidence", "mass_assignment_answers_inconsistent"},
		{"blocking form gap", "", "request_chosen", "none", "privileged_field", func() analysis.CandidateUse {
			return withGap(massPolicyUse(1), analysis.MassAssignmentFormUnmodeled, true)
		}, "needs_evidence", analysis.MassAssignmentFormUnmodeled},
		{"blocking serializer gap", "", "request_chosen", "none", "privileged_field", func() analysis.CandidateUse {
			return withGap(massPolicyUse(1), analysis.MassAssignmentSerializerUnmodeled, true)
		}, "needs_evidence", analysis.MassAssignmentSerializerUnmodeled},
		{"blocking payload gap", "", "request_chosen", "none", "privileged_field", func() analysis.CandidateUse {
			return withGap(massPolicyUse(1), analysis.MassAssignmentPayloadUnmodeled, true)
		}, "needs_evidence", analysis.MassAssignmentPayloadUnmodeled},
		{"census unresolved blocks with no fields", "", "request_chosen", "none", "no_sensitive_field", func() analysis.CandidateUse {
			return withGap(massPolicyUse(0), analysis.SecurityFieldsUnresolved, false)
		}, "needs_evidence", analysis.SecurityFieldsUnresolved},
		{"census unresolved does not block with fields", "", "request_chosen", "none", "privileged_field", func() analysis.CandidateUse {
			return withGap(massPolicyUse(1), analysis.SecurityFieldsUnresolved, false)
		}, "confirmed_vulnerability", ""},
		{"protected allow-list", "", "request_chosen", "adequate", "privileged_field", func() analysis.CandidateUse { return massPolicyUse(1, analysis.KeyAllowList) }, "protected_for_claim", ""},
		{"confirmed none", "", "request_chosen", "none", "privileged_field", func() analysis.CandidateUse { return massPolicyUse(1) }, "confirmed_vulnerability", ""},
		{"confirmed inadequate", "", "request_chosen", "inadequate", "privileged_field", func() analysis.CandidateUse { return massPolicyUse(1, analysis.KeyAllowList) }, "confirmed_vulnerability", ""},
		{"no sensitive field stays review", "", "request_chosen", "none", "no_sensitive_field", func() analysis.CandidateUse { return massPolicyUse(1) }, "needs_evidence", ""},
		{"otherwise review", "", "unknown", "none", "privileged_field", func() analysis.CandidateUse { return massPolicyUse(1) }, "needs_evidence", ""},
	} {
		t.Run(tt.rule, func(t *testing.T) {
			version := tt.version
			if version == "" {
				version = analysispacks.MassAssignmentProtocol
			}
			a := analysis.Assessment{QuestionVersion: version, Answers: map[string]string{"key_control": tt.control, "key_restriction": tt.restriction, "field_impact": tt.impact}}
			applyPolicy(tt.use(), &a)
			assertPolicy(t, a, tt.status, tt.gap)
		})
	}
}

func authzPolicyUse(provenance string, guards int, auth string, facets []string, placeholder bool, gaps ...string) analysis.CandidateUse {
	if len(facets) == 0 {
		facets = []string{analysis.FacetObjectLevel}
	}
	f := &analysis.AuthorizationFacts{
		Facets: facets, SubjectClass: `App\Entity\Item`, SubjectProvenance: provenance,
		Operation:  analysis.StateChange{Operation: "update", StorageKey: "php-sql:item.name"},
		MethodSafe: "no", SecurityFields: []analysis.SecurityFieldFact{},
	}
	if facets[0] == analysis.FacetDataExposure {
		f.Operation.Operation = "read"
	}
	for i := 0; i < guards; i++ {
		f.Guards = append(f.Guards, analysis.AuthorizationGuard{Kind: analysis.GuardRole, Evidence: policyEvidence("authorization_guard", 2+i)})
	}
	c := &analysis.Completeness{ClaimKind: "authorization", Required: analysispacks.AuthorizationRoles(), Evidence: map[string][]analysis.Evidence{}}
	for _, role := range append(analysispacks.AuthorizationRoles(), "sink_binding") {
		c.Evidence[role] = []analysis.Evidence{policyEvidence(role, 5)}
	}
	u := analysis.CandidateUse{
		Kind: analysis.AuthorizationKind, Sink: policyEvidence(analysis.AuthorizationKind, 5),
		Authorization: f, Completeness: c, APIModel: analysispacks.AuthorizationContract(analysispacks.PHPAuthorizationOperation),
		EntryFacts: &analysis.EntryPoint{Access: &analysis.EntryAccess{Authentication: auth}},
	}
	if placeholder {
		u.Dependencies = []analysis.Dependency{{Source: analysis.Evidence{Kind: "input_source", ModelText: "route placeholder", Span: analysis.Span{File: "src/App.php"}}}}
	}
	for _, g := range gaps {
		gap := analysis.Gap{Kind: g, At: u.Sink.Span}
		c.Blockers = append(c.Blockers, gap)
	}
	return u
}

func TestAuthorizationPolicy(t *testing.T) {
	obj := []string{analysis.FacetObjectLevel}
	for _, tt := range []struct {
		rule, version, subject, guard, access string
		use                                   func() analysis.CandidateUse
		status, gap                           string
	}{
		{"protocol", "authorization-components-v0", "request_selected", "none", "inadequate", func() analysis.CandidateUse {
			return authzPolicyUse(analysis.SubjectRequestSelected, 0, analysis.AccessRequired, obj, true)
		}, "needs_evidence", "authorization_protocol_missing"},
		{"claim", "", "request_selected", "none", "inadequate", func() analysis.CandidateUse {
			u := authzPolicyUse(analysis.SubjectRequestSelected, 0, analysis.AccessRequired, obj, true)
			u.Completeness.ClaimKind = "injection"
			return u
		}, "needs_evidence", "authorization_claim_missing"},
		{"facts", "", "request_selected", "none", "inadequate", func() analysis.CandidateUse {
			u := authzPolicyUse(analysis.SubjectRequestSelected, 0, analysis.AccessRequired, obj, true)
			u.Authorization.SubjectProvenance = "picked"
			return u
		}, "needs_evidence", "authorization_facts_invalid"},
		{"evidence", "", "request_selected", "none", "inadequate", func() analysis.CandidateUse {
			u := authzPolicyUse(analysis.SubjectRequestSelected, 0, analysis.AccessRequired, obj, true)
			delete(u.Completeness.Evidence, "entry_access")
			return u
		}, "needs_evidence", "authorization_evidence_missing"},
		{"guard none with a guard", "", "request_selected", "none", "inadequate", func() analysis.CandidateUse {
			return authzPolicyUse(analysis.SubjectRequestSelected, 1, analysis.AccessRequired, obj, true)
		}, "needs_evidence", "authorization_answers_inconsistent"},
		{"guard adequate with none", "", "request_selected", "adequate", "inadequate", func() analysis.CandidateUse {
			return authzPolicyUse(analysis.SubjectRequestSelected, 0, analysis.AccessRequired, obj, true)
		}, "needs_evidence", "authorization_answers_inconsistent"},
		{"access adequate when none", "", "request_selected", "none", "adequate", func() analysis.CandidateUse {
			return authzPolicyUse(analysis.SubjectRequestSelected, 0, analysis.AccessNone, obj, true)
		}, "needs_evidence", "authorization_answers_inconsistent"},
		{"not_selected on a route placeholder", "", "not_selected", "none", "inadequate", func() analysis.CandidateUse {
			return authzPolicyUse(analysis.SubjectRequestSelected, 0, analysis.AccessRequired, obj, true)
		}, "needs_evidence", "authorization_answers_inconsistent"},
		{"blocking access rule", "", "request_selected", "none", "inadequate", func() analysis.CandidateUse {
			return authzPolicyUse(analysis.SubjectRequestSelected, 0, analysis.AccessRequired, obj, true, "access_rule_unresolved")
		}, "needs_evidence", "access_rule_unresolved"},
		{"security fields block a census-only facet", "", "request_selected", "none", "inadequate", func() analysis.CandidateUse {
			return authzPolicyUse(analysis.SubjectRequestSelected, 0, analysis.AccessRequired, []string{analysis.FacetFunctionLevel}, true, analysis.SecurityFieldsUnresolved)
		}, "needs_evidence", analysis.SecurityFieldsUnresolved},
		{"security fields do not block an object write", "", "request_selected", "none", "inadequate", func() analysis.CandidateUse {
			return authzPolicyUse(analysis.SubjectRequestSelected, 0, analysis.AccessRequired, []string{analysis.FacetObjectLevel, analysis.FacetFunctionLevel}, true, analysis.SecurityFieldsUnresolved)
		}, "confirmed_vulnerability", ""},
		{"address trust is not blocking", "", "request_selected", "none", "inadequate", func() analysis.CandidateUse {
			return authzPolicyUse(analysis.SubjectRequestSelected, 0, analysis.AccessRequired, obj, true, "address_trust_configuration_unread")
		}, "confirmed_vulnerability", ""},
		{"protected by a guard", "", "request_selected", "adequate", "inadequate", func() analysis.CandidateUse {
			return authzPolicyUse(analysis.SubjectRequestSelected, 1, analysis.AccessRequired, obj, true)
		}, "protected_for_claim", ""},
		{"protected by access", "", "request_selected", "none", "adequate", func() analysis.CandidateUse {
			return authzPolicyUse(analysis.SubjectRequestSelected, 0, analysis.AccessRequired, obj, true)
		}, "protected_for_claim", ""},
		{"confirmed", "", "request_selected", "none", "inadequate", func() analysis.CandidateUse {
			return authzPolicyUse(analysis.SubjectRequestSelected, 0, analysis.AccessRequired, obj, true)
		}, "confirmed_vulnerability", ""},
		{"confirmed with an inadequate guard", "", "request_selected", "inadequate", "inadequate", func() analysis.CandidateUse {
			return authzPolicyUse(analysis.SubjectRequestSelected, 1, analysis.AccessRequired, obj, true)
		}, "confirmed_vulnerability", ""},
		{"enumerated exposure needs no request selection", "", "unknown", "none", "inadequate", func() analysis.CandidateUse {
			return authzPolicyUse(analysis.SubjectEnumerated, 0, analysis.AccessNone, []string{analysis.FacetDataExposure}, false)
		}, "confirmed_vulnerability", ""},
		{"otherwise review", "", "unknown", "unknown", "unknown", func() analysis.CandidateUse {
			return authzPolicyUse(analysis.SubjectRequestSelected, 0, analysis.AccessRequired, obj, true)
		}, "needs_evidence", ""},
	} {
		t.Run(tt.rule, func(t *testing.T) {
			version := tt.version
			if version == "" {
				version = analysispacks.AuthorizationProtocol
			}
			a := analysis.Assessment{QuestionVersion: version, Answers: map[string]string{"subject_control": tt.subject, "guard_adequacy": tt.guard, "access_adequacy": tt.access}}
			applyPolicy(tt.use(), &a)
			assertPolicy(t, a, tt.status, tt.gap)
		})
	}
}

func assertPolicy(t *testing.T, a analysis.Assessment, status, gap string) {
	t.Helper()
	if a.FindingStatus != status {
		t.Fatalf("status %q, want %q (%s; gaps %v)", a.FindingStatus, status, a.Reason, a.BlockingGaps)
	}
	if gap == "" {
		if status != "needs_evidence" && len(a.BlockingGaps) > 0 {
			t.Fatalf("unexpected gaps %v", a.BlockingGaps)
		}
		return
	}
	for _, g := range a.BlockingGaps {
		if g.Kind == gap {
			return
		}
	}
	t.Fatalf("gaps %v lack %s", a.BlockingGaps, gap)
}
