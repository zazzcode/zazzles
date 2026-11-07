package report

import (
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
)

func TestAnalyzerPillsPreserveFindingStatus(t *testing.T) {
	for _, id := range []string{"sql-injection", "nosql-injection", "reflected-xss", "stored-xss", "dom-xss", "command-injection", "sensitive-data-logging"} {
		for _, tt := range []struct {
			status, label, tone string
			confirmed, review   int
		}{
			{"confirmed_vulnerability", "vulnerability", "confirmed-vulnerability", 1, 0},
			{"needs_evidence", "review", "review", 0, 1},
			{"protected_for_claim", "protected", "protected", 0, 0},
		} {
			t.Run(id+"/"+tt.status, func(t *testing.T) {
				pills := rowTypePills([]htmlItem{{Finding: analysis.Finding{
					TypeIDs: []string{id}, Status: tt.status,
				}}})
				if len(pills) != 1 {
					t.Fatalf("pills = %+v", pills)
				}
				p := pills[0]
				if p.Status != tt.label || p.Tone != tt.tone || p.Confirmed != tt.confirmed || p.Review != tt.review {
					t.Fatalf("pill contradicts finding status %s: %+v", tt.status, p)
				}
			})
		}
	}
}
