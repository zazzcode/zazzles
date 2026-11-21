package judge

import (
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

func TestBoundParametersOnlyIsNotConfirmed(t *testing.T) {
	for _, tt := range []struct {
		name string
		slot string
		gaps []analysis.Gap
		want string
	}{
		{"bound only", "sql_parameters", nil, "needs_evidence"},
		{"text slot", "sql_text", nil, "confirmed_vulnerability"},
		{"interpolated text", "sql_parameters", []analysis.Gap{{Kind: "query_text_interpolated"}}, "confirmed_vulnerability"},
	} {
		c := &analysis.Completeness{ClaimKind: "injection", Required: []string{"input_source", "sink_binding", "invoked_callable", "control_flow"}, Evidence: map[string][]analysis.Evidence{"input_source": {{Text: "$_POST['username']"}}, "sink_binding": {{Text: "PDO"}}, "control_flow": {{Text: "entry"}}, "invoked_callable": {{Text: "handler"}}}}
		use := analysis.CandidateUse{Kind: "sql_query_candidate", Completeness: c, Gaps: tt.gaps, APIModel: &analysis.APIModel{ID: "php-pdo-v1"},
			Dependencies: []analysis.Dependency{{Source: analysis.Evidence{Kind: "input_source"}, SinkSlot: tt.slot}}}
		a := analysis.Assessment{Status: "completed", Answers: map[string]string{"injection_protection": "vulnerable", "protection": "insufficient"}}
		applyPolicy(use, &a)
		if a.FindingStatus != tt.want {
			t.Fatalf("%s: %s %+v", tt.name, a.FindingStatus, a.BlockingGaps)
		}
	}
}
