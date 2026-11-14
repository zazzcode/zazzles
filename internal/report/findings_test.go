package report

import (
	"github.com/zazzcode/zazzles/internal/analysis"
	"strings"
	"testing"
)

func TestDerivedProtectionKeepsProvenance(t *testing.T) {
	u := analysis.CandidateUse{Kind: "nosql_query_candidate", APIModel: &analysis.APIModel{ID: "mongoose-path-id-objectid-v1"}, Assessment: analysis.Assessment{Status: "completed", FindingStatus: "protected_for_claim", DeduplicatedFrom: "canonical-context"}}
	f := describe(u)
	if !strings.Contains(f.Uncertainty, "canonical-context") {
		t.Fatalf("missing derived protection provenance: %s", f.Uncertainty)
	}
}
