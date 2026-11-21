package report

import (
	"bytes"
	"encoding/json"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"reflect"
	"strings"
	"testing"
)

func TestFindingTypesPreserveImplementedScope(t *testing.T) {
	cases := []struct {
		name, kind, gap string
		want            []string
	}{
		{"SQL with validation", "sql_query_candidate", "input_validation_absent", []string{"sql-injection", "input-validation"}},
		{"NoSQL document", "nosql_query_candidate", "query_document_unvalidated", []string{"nosql-injection"}},
		{"validation only", "input_validation_candidate", "input_validation_unresolved", []string{"input-validation"}},
		{"account", "account_creation_candidate", "", []string{"account-creation-validation", "input-validation"}},
		{"outbound", "outbound_http_candidate", "", []string{"outbound-request-safety"}},
		{"logging", "log_sink_candidate", "log_sensitive_field_hint", []string{"sensitive-data-logging"}},
		{"logging ignores validation gaps", "log_sink_candidate", "input_validation_absent", []string{"sensitive-data-logging"}},
		{"XSS", "xss_candidate", "", []string{"reflected-xss"}},
		{"unknown", "unrecognized_future_use", "", []string{"sensitive-operation-review"}},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			u := analysis.CandidateUse{Kind: tt.kind, Gaps: []analysis.Gap{{Kind: tt.gap}}, Assessment: analysis.Assessment{Status: "not_run"}}
			r := &analysis.AnalysisReport{Uses: []analysis.CandidateUse{u}}
			before, _ := json.Marshal(r.Uses)
			Enrich(r)
			if !reflect.DeepEqual(r.Findings[0].TypeIDs, tt.want) {
				t.Fatalf("types=%v", r.Findings[0].TypeIDs)
			}
			after, _ := json.Marshal(r.Uses)
			if !bytes.Equal(before, after) {
				t.Fatal("typing mutated evidence")
			}
			for _, id := range r.Findings[0].TypeIDs {
				if findingTypesByID[id].Coverage == "planned" || findingTypesByID[id].ID == "" {
					t.Fatalf("unsupported type %s", id)
				}
			}
		})
	}
	ids := map[string]bool{}
	for _, typ := range findingTypes {
		if ids[typ.ID] || typ.ID == "" || typ.Label == "" || typ.Description == "" || typ.Interpretation == "" || typ.Remediation == "" || typ.Coverage == "" {
			t.Fatalf("invalid glossary entry %+v", typ)
		}
		ids[typ.ID] = true
	}
	if findingTypesByID["reflected-xss"].Coverage != "bounded server response and template analysis" || findingTypesByID["sensitive-data-logging"].Coverage != "bounded analysis" {
		t.Fatal("glossary advertised planned detectors")
	}
}

func TestRowPillsAggregateTypesWithoutUpgradingStatus(t *testing.T) {
	items := []htmlItem{
		{Finding: analysis.Finding{TypeIDs: []string{"sql-injection", "input-validation"}, Status: "poor_practice"}},
		{Finding: analysis.Finding{TypeIDs: []string{"sql-injection", "input-validation"}, Status: "needs_evidence"}},
		{Finding: analysis.Finding{TypeIDs: []string{"nosql-injection"}, Status: "protected_for_claim"}},
	}
	pills := rowTypePills(items)
	if len(pills) != 3 {
		t.Fatalf("pills=%+v", pills)
	}
	for _, p := range pills {
		if p.ID == "sql-injection" && (p.Count != 2 || p.PoorPractice != 1 || p.Review != 1 || p.Status != "mixed status") {
			t.Fatalf("SQL pill=%+v", p)
		}
		if p.ID == "nosql-injection" && (p.Count != 1 || p.Status != "protected") {
			t.Fatalf("NoSQL pill=%+v", p)
		}
	}
}

func TestHTMLTypePanelsAndDistinctLocations(t *testing.T) {
	r := &analysis.AnalysisReport{SchemaVersion: 1, Entries: []analysis.EntryPoint{testHTTPEntry(analysis.Route{ID: "r", Method: "POST", PathPattern: "/search", Registration: analysis.Span{File: "server.ts", StartLine: 3}})}, Uses: []analysis.CandidateUse{{ID: "u", EntryID: "r", Kind: "sql_query_candidate", Sink: analysis.Evidence{Text: "db.query(sql)", Span: analysis.Span{File: "handler.ts", StartLine: 11}}, Dependencies: requestDependency(), Gaps: []analysis.Gap{{Kind: "query_text_interpolated"}, {Kind: "input_validation_absent"}}, Assessment: analysis.Assessment{Status: "not_run"}}}}
	var b bytes.Buffer
	if err := HTML(&b, r); err != nil {
		t.Fatal(err)
	}
	html := b.String()
	for _, want := range []string{`<span>Declaration location</span>`, `server.ts:3`, `Finding location · </span>handler.ts:11`, `class="type-pill poor-practice"`, `popovertarget="glossary-sql-injection"`, `id="glossary-sql-injection" class="glossary-panel" popover="auto"`, `popovertargetaction="hide"`, `aria-labelledby="glossary-heading-sql-injection"`, `SQL Injection <span class="pill-status">· poor practice`, `Input Validation <span class="pill-status">· review`, `Coverage: bounded server response and template analysis`, `id="finding-glossary"`} {
		if !strings.Contains(html, want) {
			t.Fatalf("missing %s", want)
		}
	}
	if strings.Contains(html, `popovertarget="glossary-reflected-xss" aria-label=`) {
		t.Fatal("XSS attached to a SQL-only row")
	}
	sarif := SARIF(r)
	data, err := json.Marshal(sarif)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte(`"scan.findingTypes"`)) || !bytes.Contains(data, []byte(`"type_ids":["sql-injection","input-validation"]`)) {
		t.Fatal("SARIF lost glossary context")
	}
}

func TestSQLBindingDoesNotColorInputValidationGreen(t *testing.T) {
	item := htmlItem{Finding: analysis.Finding{TypeIDs: []string{"sql-injection", "input-validation"}, RecordType: "protection", Status: "protected_for_claim"}, Use: analysis.CandidateUse{Kind: "sql_query_candidate", Assessment: analysis.Assessment{Status: "completed", FindingStatus: "protected_for_claim", Answers: map[string]string{"injection_protection": "protected", "validation": "uncertain"}}}}
	pills := rowTypePills([]htmlItem{item})
	for _, p := range pills {
		if p.ID == "input-validation" && (p.Tone != "review" || p.Protected != 0) {
			t.Fatal("SQL binding lent green status to inconclusive validation")
		}
		if p.ID == "sql-injection" && p.Tone != "protected" {
			t.Fatal("separate SQL protection facet lost")
		}
	}
}

func TestOwnValidationPracticeColorsValidationPill(t *testing.T) {
	item := htmlItem{Finding: analysis.Finding{TypeIDs: []string{"input-validation"}, RecordType: "finding", Status: "poor_practice"}, Use: analysis.CandidateUse{Kind: "input_validation_candidate", Completeness: &analysis.Completeness{ClaimKind: "validation"}, Assessment: analysis.Assessment{Status: "completed", Answers: map[string]string{"validation": "insufficient"}}}}
	pills := rowTypePills([]htmlItem{item})
	if len(pills) != 1 || pills[0].Tone != "poor-practice" {
		t.Fatal("independent validation defect lost its status")
	}
}
