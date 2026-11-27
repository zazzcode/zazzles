package judge

import (
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
)

// TestSQLJudgedLimitPolicy: a judged limit of a SQL record never lets the
// record be Protected; a vulnerable answer still Confirms.
func TestSQLJudgedLimitPolicy(t *testing.T) {
	loop := []analysis.Gap{{Kind: "php_loop_unresolved"}, {Kind: "php_loop_unresolved"}, {Kind: "work_limit"}}
	for _, tt := range []struct {
		name, answer string
		judged       []analysis.Gap
		want         string
		reason       string
	}{
		{"protected, judged limit", "protected", loop, "needs_evidence", "php_loop_unresolved, work_limit"},
		{"vulnerable, judged limit", "vulnerable", loop, "confirmed_vulnerability", ""},
		{"protected, no judged limit", "protected", nil, "protected_for_claim", ""},
		{"vulnerable, no judged limit", "vulnerable", nil, "confirmed_vulnerability", ""},
		{"uncertain, judged limit", "uncertain", loop, "needs_evidence", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ev := func(kind string) []analysis.Evidence { return []analysis.Evidence{{Kind: kind, Text: kind}} }
			use := analysis.CandidateUse{Kind: "sql_query_candidate", APIModel: analysispacks.PHPSQLContract("mysqli"),
				Completeness: &analysis.Completeness{ClaimKind: "injection", Required: []string{"input_source", "sink_binding", "invoked_callable", "control_flow"}, Blockers: []analysis.Gap{}, Judged: tt.judged,
					Evidence: map[string][]analysis.Evidence{"input_source": ev("input_source"), "sink_binding": ev("sink_binding"), "invoked_callable": ev("invoked_callable"), "control_flow": ev("control_flow")}}}
			a := analysis.Assessment{Status: "completed", Answers: map[string]string{"injection_protection": tt.answer}}
			applyPolicy(use, &a)
			if a.FindingStatus != tt.want {
				t.Fatalf("status %s (%s), want %s", a.FindingStatus, a.Reason, tt.want)
			}
			if tt.reason != "" && !strings.Contains(a.Reason, tt.reason) {
				t.Errorf("reason %q lacks %q", a.Reason, tt.reason)
			}
			if tt.want == "needs_evidence" && a.Protection != "uncertain" {
				t.Errorf("protection %s", a.Protection)
			}
		})
	}
}
