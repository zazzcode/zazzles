package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
)

func TestDerivedProtectionKeepsProvenance(t *testing.T) {
	u := analysis.CandidateUse{Kind: "nosql_query_candidate", APIModel: &analysis.APIModel{ID: "mongoose-path-id-objectid-v1"}, Assessment: analysis.Assessment{Status: "completed", FindingStatus: "protected_for_claim", DeduplicatedFrom: "canonical-context"}}
	f := describe(u)
	if !strings.Contains(f.Uncertainty, "canonical-context") {
		t.Fatalf("missing derived protection provenance: %s", f.Uncertainty)
	}
}

func TestRequestBudgetReported(t *testing.T) {
	omitted := []analysis.EvidenceOmission{{Kind: "helper_definition", Span: analysis.Span{File: "lib/a.ts", StartLine: 1, EndLine: 9}, Bytes: 400}}
	sent := describe(analysis.CandidateUse{Kind: "nosql_query_candidate", Assessment: analysis.Assessment{Status: "completed", FindingStatus: "needs_evidence", EvidenceOmissions: omitted}})
	if !strings.Contains(sent.Uncertainty, "1 context evidence item(s) were left out") {
		t.Fatalf("omission not reported: %s", sent.Uncertainty)
	}
	floor := describe(analysis.CandidateUse{Kind: "sql_query_candidate", Assessment: analysis.Assessment{Status: "not_run", FindingStatus: "needs_evidence", Reason: "evidence_too_large: the request needs 90000 bytes", EvidenceOmissions: omitted}})
	if !strings.Contains(floor.Uncertainty, "no request was sent (evidence_too_large: the request needs 90000 bytes)") || !strings.Contains(floor.Uncertainty, "left out") {
		t.Fatalf("floor reason not reported: %s", floor.Uncertainty)
	}
}

func TestOutboundObservationGrouping(t *testing.T) {
	sink := func(start int) analysis.Evidence {
		return analysis.Evidence{Kind: "outbound_http_candidate", Text: "fetch(hook)", Span: analysis.Span{File: "lib/hook.ts", StartLine: 3, StartByte: start, EndByte: start + 11}}
	}
	obs := func(id, entry string, start int, origin string) analysis.CandidateUse {
		return analysis.CandidateUse{ID: id, EntryID: entry, Kind: "outbound_http_candidate", Sink: sink(start), Outbound: &analysis.OutboundFacts{DestinationOrigin: origin}}
	}
	r := &analysis.AnalysisReport{Uses: []analysis.CandidateUse{
		obs("a", "e1", 10, analysis.DestinationEnvironment),
		obs("b", "e2", 10, analysis.DestinationEnvironment),
		obs("c", "e3", 10, analysis.DestinationEnvironment),
		obs("d", "e1", 90, analysis.DestinationEnvironment),
		obs("e", "e1", 200, analysis.DestinationRequest),
		obs("f", "e2", 200, analysis.DestinationRequest),
	}}
	Enrich(r)
	if len(r.Findings) != len(r.Uses) {
		t.Fatal("findings must stay parallel to uses")
	}
	shown := 0
	for _, f := range r.Findings {
		if f.GroupedInto == "" {
			shown++
		}
	}
	if shown != 4 || r.Findings[1].GroupedInto != r.Findings[0].ID || r.Findings[2].GroupedInto != r.Findings[0].ID {
		t.Fatalf("grouping: shown=%d %+v", shown, r.Findings)
	}
	if !strings.Contains(r.Findings[0].Summary, "3 entries reach this one call") || len(r.Findings[0].GroupedUseIDs) != 2 {
		t.Fatalf("representative: %s %v", r.Findings[0].Summary, r.Findings[0].GroupedUseIDs)
	}
	if r.Findings[3].GroupedInto != "" || r.Findings[4].GroupedInto != "" || r.Findings[5].GroupedInto != "" {
		t.Fatal("a distinct call or a request-derived destination was folded")
	}
	var text bytes.Buffer
	Text(&text, r)
	if strings.Count(text.String(), "Outbound request needs destination review") != 4 {
		t.Fatalf("text renderer shows folded records:\n%s", text.String())
	}
	sarif, _ := json.Marshal(SARIF(r))
	if strings.Count(string(sarif), `"scan.useId":`) != 4 {
		t.Fatal("SARIF shows folded records")
	}
}
