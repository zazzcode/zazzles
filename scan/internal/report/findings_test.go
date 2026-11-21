package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
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

func TestSinkGroups(t *testing.T) {
	sink := func(kind string, start int) analysis.Evidence {
		return analysis.Evidence{Kind: kind, Text: "render(page)", Span: analysis.Span{File: "lib/page.php", StartLine: 3, StartByte: start, EndByte: start + 11}}
	}
	dep := func(kind string) []analysis.Dependency {
		return []analysis.Dependency{{Source: analysis.Evidence{Kind: kind, Text: "v", Span: analysis.Span{File: "lib/page.php", StartLine: 1}}}}
	}
	obs := func(id, entry string, start int, origin string) analysis.CandidateUse {
		return analysis.CandidateUse{ID: id, EntryID: entry, Kind: "outbound_http_candidate", Sink: sink("outbound_http_candidate", start), Outbound: &analysis.OutboundFacts{DestinationOrigin: origin}}
	}
	sql := func(id, entry string, start int, deps []analysis.Dependency) analysis.CandidateUse {
		return analysis.CandidateUse{ID: id, EntryID: entry, Kind: "sql_query_candidate", Sink: sink("sql_query_candidate", start), Dependencies: deps, Gaps: []analysis.Gap{{Kind: "query_text_interpolated"}}}
	}
	entry := func(id string) analysis.EntryPoint {
		return testHTTPEntry(analysis.Route{ID: id, Method: "GET", PathPattern: "/" + id, Registration: analysis.Span{File: "routes.php", StartLine: len(id)}})
	}
	for _, tt := range []struct {
		name        string
		uses        []analysis.CandidateUse
		grouped     map[int]int // folded use index -> representative index
		shown       int
		summary     string
		fingerprint bool
	}{
		{"outbound observations fold by call site", []analysis.CandidateUse{
			obs("a", "e1", 10, analysis.DestinationEnvironment), obs("b", "e2", 10, analysis.DestinationEnvironment), obs("c", "e3", 10, analysis.DestinationEnvironment),
			obs("d", "e1", 90, analysis.DestinationEnvironment), obs("e", "e1", 200, analysis.DestinationRequest), obs("f", "e2", 200, analysis.DestinationRequest),
		}, map[int]int{1: 0, 2: 0}, 4, "3 entries reach this one call", false},
		{"one kind, sink and status fold across entries", []analysis.CandidateUse{
			sql("a", "e1", 10, dep("input_source")), sql("b", "e2", 10, dep("storage_source")), sql("c", "e2", 10, dep("input_source")), sql("d", "e1", 90, dep("input_source")),
		}, map[int]int{1: 0, 2: 0}, 2, "This row stands for 3 records from 2 entries", true},
		{"different statuses never share a row", []analysis.CandidateUse{
			sql("a", "e1", 10, dep("input_source")), sql("b", "e2", 10, nil), sql("c", "e3", 10, dep("input_source")), sql("d", "e4", 10, nil),
		}, map[int]int{2: 0, 3: 1}, 2, "status poor_practice", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := &analysis.AnalysisReport{Uses: tt.uses}
			for _, id := range []string{"e1", "e2", "e3", "e4"} {
				r.Entries = append(r.Entries, entry(id))
			}
			before, _ := json.Marshal(r.Uses)
			Enrich(r)
			if len(r.Findings) != len(r.Uses) {
				t.Fatal("findings must stay parallel to uses")
			}
			shown := 0
			for i, f := range r.Findings {
				rep, folded := tt.grouped[i]
				if folded != (f.GroupedInto != "") || folded && f.GroupedInto != r.Findings[rep].ID {
					t.Fatalf("record %d grouped_into=%q", i, f.GroupedInto)
				}
				if folded && f.Status != r.Findings[rep].Status {
					t.Fatal("a group mixed statuses")
				}
				if !folded {
					shown++
				}
			}
			if shown != tt.shown || !strings.Contains(r.Findings[0].Summary, tt.summary) {
				t.Fatalf("shown=%d summary=%s", shown, r.Findings[0].Summary)
			}
			var page bytes.Buffer
			if err := HTML(&page, r); err != nil {
				t.Fatal(err)
			}
			var text bytes.Buffer
			Text(&text, r)
			results := SARIF(r)["runs"].([]any)[0].(map[string]any)["results"].([]any)
			if len(results) != tt.shown || sarifRecords(results) != len(r.Uses) || strings.Count(text.String(), "entry=") != tt.shown {
				t.Fatalf("renderers: SARIF %d/%d text %d", len(results), sarifRecords(results), strings.Count(text.String(), "entry="))
			}
			first := results[0].(map[string]any)
			_, fp := first["partialFingerprints"]
			if fp != tt.fingerprint {
				t.Fatalf("group fingerprint present=%v", fp)
			}
			if tt.fingerprint {
				related := first["relatedLocations"].([]any)
				if !strings.Contains(fmt.Sprint(related), "grouped entry") {
					t.Fatalf("grouped entries are not related locations: %v", related)
				}
			}
			// Canonical JSON keeps every record with its own evidence and ID.
			data, _ := json.Marshal(struct {
				Uses     []analysis.CandidateUse `json:"uses"`
				Findings []analysis.Finding      `json:"findings"`
			}{r.Uses, r.Findings})
			var round struct {
				Uses     []analysis.CandidateUse `json:"uses"`
				Findings []analysis.Finding      `json:"findings"`
			}
			if err := json.Unmarshal(data, &round); err != nil {
				t.Fatal(err)
			}
			after, _ := json.Marshal(round.Uses)
			if !bytes.Equal(before, after) || len(round.Findings) != len(tt.uses) {
				t.Fatal("grouping changed or dropped a record")
			}
		})
	}
}

func TestConstructionFindingNeedsOrigin(t *testing.T) {
	dep := func(kind string) analysis.Dependency {
		return analysis.Dependency{Source: analysis.Evidence{Kind: kind, Text: "v", Span: analysis.Span{File: "db.php", StartLine: 1}}}
	}
	built := func(kind string, deps ...analysis.Dependency) analysis.CandidateUse {
		return analysis.CandidateUse{ID: "u", Kind: kind, Sink: analysis.Evidence{Span: analysis.Span{File: "db.php", StartLine: 9}},
			Dependencies: deps, Gaps: []analysis.Gap{{Kind: "query_text_interpolated"}}}
	}
	for _, tc := range []struct {
		name    string
		use     analysis.CandidateUse
		finding bool
	}{
		{"sql no dependency", built("sql_query_candidate"), false},
		{"sql constant only", built("sql_query_candidate", dep("constant")), false},
		{"nosql no dependency", built("nosql_query_candidate"), false},
		{"sql request dependency", built("sql_query_candidate", dep("input_source")), true},
		{"sql storage dependency", built("sql_query_candidate", dep("storage_source")), true},
	} {
		r := &analysis.AnalysisReport{Uses: []analysis.CandidateUse{tc.use}}
		Enrich(r)
		f := r.Findings[0]
		if got := f.RecordType == "finding" && f.Status == "poor_practice"; got != tc.finding {
			t.Fatalf("%s: finding=%v status=%s", tc.name, got, f.Status)
		}
		hasReason := false
		for _, b := range f.BlockingEvidence {
			hasReason = hasReason || b.Kind == "external_origin_not_established"
		}
		if hasReason == tc.finding || (!tc.finding && f.Status != "needs_review") {
			t.Fatalf("%s: status=%s reasons=%+v", tc.name, f.Status, f.BlockingEvidence)
		}
	}
}

// requestDependency is one request-origin dependency, the external origin a
// construction finding needs.
func requestDependency() []analysis.Dependency {
	return []analysis.Dependency{{Source: analysis.Evidence{Kind: "input_source", Text: "req.query.q", Span: analysis.Span{File: "handler.ts", StartLine: 1}}}}
}

// sarifRecords counts the records SARIF results stand for: each result plus
// the records grouped into it (grouped_use_ids).
func sarifRecords(results []any) int {
	n := 0
	for _, item := range results {
		n++
		props, _ := item.(map[string]any)["properties"].(map[string]any)
		switch f := props["scan.finding"].(type) {
		case analysis.Finding:
			n += len(f.GroupedUseIDs)
		case map[string]any:
			ids, _ := f["grouped_use_ids"].([]any)
			n += len(ids)
		}
	}
	return n
}
