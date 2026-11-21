package judge

import (
	"context"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

func TestValidationDecidabilityGate(t *testing.T) {
	complete := selectedValidationUse(t)
	complete.Check = nil
	incomplete := complete
	incomplete.Completeness = &analysis.Completeness{ClaimKind: complete.Completeness.ClaimKind, Required: complete.Completeness.Required, Evidence: map[string][]analysis.Evidence{}}
	for role, ev := range complete.Completeness.Evidence {
		if role != "field_policy" {
			incomplete.Completeness.Evidence[role] = ev
		}
	}
	checked := incomplete
	checked.Check = &analysis.Check{ID: "signup-email"}
	answers := commandAnswers{"field_requirement": "established", "enforcement_coverage": "complete", "validation": "insufficient"}
	for _, tt := range []struct {
		name  string
		use   analysis.CandidateUse
		opts  ScheduleOptions
		calls int64
	}{
		{"complete evidence is judged", complete, ScheduleOptions{Limit: 5}, 1},
		{"missing gate evidence is not sent", incomplete, ScheduleOptions{Limit: 5}, 0},
		{"a --checks record is judged", checked, ScheduleOptions{Limit: 5}, 1},
		{"only input-validation judges every record", incomplete, ScheduleOptions{Limit: 5, OnlyFamilies: []string{"input-validation"}}, 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c, calls := commandStub(t, "openai", answers)
			u := tt.use
			u.ID = "v"
			r := &analysis.AnalysisReport{Uses: []analysis.CandidateUse{u}}
			failed := c.AssessScheduled(context.Background(), r, tt.opts)
			if calls.Load() != tt.calls {
				t.Fatalf("calls=%d want %d (%+v)", calls.Load(), tt.calls, r.Uses[0].Assessment)
			}
			a := r.Uses[0].Assessment
			if tt.calls == 0 {
				if failed || a.Status != "not_run" || !strings.HasPrefix(a.Reason, ValidationUndecidable+":") || len(a.BlockingGaps) == 0 {
					t.Fatalf("failed=%v gated assessment %+v", failed, a)
				}
				found := false
				for _, l := range r.Limitations {
					found = found || strings.Contains(l, "1 validation records were not sent")
				}
				if !found {
					t.Fatalf("limitation missing: %v", r.Limitations)
				}
			} else if a.Status != "completed" {
				t.Fatalf("judged assessment %+v", a)
			}
		})
	}
}
