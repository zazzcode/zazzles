package judge

import (
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
)

func TestConfigurationPolicy(t *testing.T) {
	setting := analysis.Evidence{Kind: "setting", Text: "csrf_protection: false", Span: analysis.Span{File: "framework.yaml", StartLine: 4}}
	installed := analysis.Evidence{Kind: "config_installed", Text: "copied", Span: setting.Span}
	mitigation := analysis.Evidence{Kind: "mitigation", Text: "isCsrfTokenValid", Span: setting.Span}
	base := func() analysis.CandidateUse {
		return analysis.CandidateUse{
			Kind: analysis.ConfigurationKind, Sink: setting,
			Configuration: &analysis.ConfigurationFacts{Check: analysis.CheckCSRFDisabled, Setting: setting, Value: "false", Scope: "app", Joined: []analysis.Evidence{{Kind: "state_changing_entry", Text: "POST /item"}}},
			Completeness: &analysis.Completeness{ClaimKind: "configuration", Required: []string{"setting", "scope"}, Evidence: map[string][]analysis.Evidence{
				"setting": {setting}, "scope": {setting},
			}, Blockers: []analysis.Gap{}},
		}
	}
	for _, tt := range []struct {
		name, effect, weakness, mitigation, want, gap string
		installed                                     bool
		haveMitigation                                bool
		blocking                                      string
	}{
		{"confirmed none", "in_effect", "weakens", "none", "confirmed_vulnerability", "", false, false, ""},
		{"confirmed inadequate", "in_effect", "weakens", "inadequate", "confirmed_vulnerability", "", false, false, ""},
		{"protected not in effect", "not_in_effect", "weakens", "none", "protected_for_claim", "", false, false, ""},
		{"protected benign", "in_effect", "benign", "none", "protected_for_claim", "", false, false, ""},
		{"protected adequate", "in_effect", "weakens", "adequate", "protected_for_claim", "", false, true, ""},
		{"inconsistent adequate without mitigation", "in_effect", "weakens", "adequate", "needs_evidence", "configuration_answers_inconsistent", false, false, ""},
		{"inconsistent not in effect when installed", "not_in_effect", "weakens", "none", "needs_evidence", "configuration_answers_inconsistent", true, false, ""},
		{"blocking mapping", "in_effect", "weakens", "none", "needs_evidence", "deploy_mapping_unresolved", false, false, "deploy_mapping_unresolved"},
		{"blocking unread", "in_effect", "weakens", "none", "needs_evidence", "config_file_unread", false, false, "config_file_unread"},
		{"protocol missing", "in_effect", "weakens", "none", "needs_evidence", "configuration_protocol_missing", false, false, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			u := base()
			if tt.installed {
				u.Configuration.Joined = append(u.Configuration.Joined, installed)
			}
			if tt.haveMitigation {
				u.Configuration.Mitigations = []analysis.Evidence{mitigation}
			}
			if tt.blocking != "" {
				u.Gaps = []analysis.Gap{{Kind: tt.blocking}}
			}
			a := &analysis.Assessment{QuestionVersion: analysispacks.ConfigurationProtocol, Answers: map[string]string{
				"setting_effect": tt.effect, "weakness": tt.weakness, "mitigation": tt.mitigation,
			}}
			if tt.gap == "configuration_protocol_missing" {
				a.QuestionVersion = "other"
			}
			applyConfigurationPolicy(u, a)
			if a.FindingStatus != tt.want {
				t.Fatalf("status %s, want %s (%s)", a.FindingStatus, tt.want, a.Reason)
			}
			if tt.gap != "" {
				found := false
				for _, g := range a.BlockingGaps {
					if g.Kind == tt.gap {
						found = true
					}
				}
				if !found {
					t.Fatalf("gaps %+v, want %s", a.BlockingGaps, tt.gap)
				}
			}
		})
	}
}
