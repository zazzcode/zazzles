package report

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	htmlstd "html"
	"strings"
	"testing"
)

func TestHTMLPinsOnlyBundledSortingScript(t *testing.T) {
	r := &analysis.AnalysisReport{Entries: []analysis.EntryPoint{testHTTPEntry(analysis.Route{ID: "r", Method: "GET", PathPattern: `/path/"<script>bad()</script>`})}}
	var out bytes.Buffer
	if err := HTML(&out, r); err != nil {
		t.Fatal(err)
	}
	html := out.String()
	start := strings.Index(html, "<script>")
	end := strings.Index(html, "</script>")
	if start < 0 || end < start || strings.Count(html, "<script>") != 1 {
		t.Fatal("expected one bundled script")
	}
	actual := html[start+len("<script>") : end]
	hash := sha256.Sum256([]byte(actual))
	if actual != sortSource || !strings.Contains(htmlstd.UnescapeString(html), "script-src 'sha256-"+base64.StdEncoding.EncodeToString(hash[:])+"'") {
		t.Fatal("script differs from the bundled source or CSP hash")
	}
	for _, want := range []string{`data-sort="path"`, `class="sort-button status-sort" data-sort="findings"`, `data-review="0" data-protected="0"`, `class="categories-heading"`, `data-path="/path/&#34;&lt;script&gt;bad()&lt;/script&gt;"`} {
		if !strings.Contains(html, want) {
			t.Fatalf("missing sort structure or escaped attribute: %s", want)
		}
	}
	if strings.Count(html, "data-sort=") != 2 || strings.Contains(html, "background:#f0f2f2") {
		t.Fatal("unexpected independent sort controls or shaded empty category")
	}
}

func TestInconclusiveDisplayPreservesRawAssessment(t *testing.T) {
	for _, value := range []string{"unknown", "uncertain", "needs_evidence"} {
		t.Run(value, func(t *testing.T) {
			if got := displayLabel(value); got != "Inconclusive" {
				t.Fatalf("displayLabel(%q) = %q", value, got)
			}
			u := analysis.CandidateUse{ID: "u", Kind: "outbound_http_candidate", Assessment: analysis.Assessment{
				Status: "completed", FindingStatus: "needs_evidence", Protection: value,
				Answers: map[string]string{"validation": value},
			}}
			r := &analysis.AnalysisReport{Uses: []analysis.CandidateUse{u}}
			before, _ := json.Marshal(r.Uses)
			var b bytes.Buffer
			if err := HTML(&b, r); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(b.String(), "Assessed injection/use protection: Inconclusive.") || !strings.Contains(b.String(), "Model validation answer: Inconclusive.") {
				t.Fatal("human-facing judgment was not translated")
			}
			after, _ := json.Marshal(r.Uses)
			if !bytes.Equal(before, after) {
				t.Fatal("display label changed raw assessment")
			}
		})
	}
	if displayLabel("not_run") != "Not assessed" || displayLabel("failed") != "Assessment failed" {
		t.Fatal("execution status confused with an inconclusive judgment")
	}
}

func TestHumanFindingsPreserveEvidenceAndSeparateUncertainty(t *testing.T) {
	cases := []struct{ name, kind, gap, text, record, title string }{
		{"SQL text", "sql_query_candidate", "query_text_interpolated", "db.query(`SELECT ${value}`)", "finding", "SQL query text"},
		{"ORM value", "sql_query_candidate", "query_text_interpolated", "Model.findAll({[Op.like]: `%${value}%`})", "analysis", "library review"},
		{"NoSQL expression", "nosql_query_candidate", "query_text_interpolated", "collection.find({$where: 'id == '+id})", "finding", "NoSQL $where"},
		{"NoSQL document", "nosql_query_candidate", "query_document_unvalidated", "collection.update({_id: req.body.id})", "analysis", "type constraints need review"},
		{"unknown validator", "input_validation_candidate", "input_validation_unresolved", "req.body.email", "analysis", "validation needs review"},
		{"no validator observed", "input_validation_candidate", "input_validation_absent", "req.body.email", "analysis", "evidence is incomplete"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			u := analysis.CandidateUse{ID: "u", EntryID: "r", Kind: tt.kind, Sink: analysis.Evidence{Text: tt.text}, Dependencies: requestDependency(), Gaps: []analysis.Gap{{Kind: tt.gap}}, Assessment: analysis.Assessment{Status: "not_run"}}
			before, _ := json.Marshal(u)
			r := &analysis.AnalysisReport{Uses: []analysis.CandidateUse{u}}
			Enrich(r)
			f := r.Findings[0]
			if f.RecordType != tt.record || !strings.Contains(f.Title, tt.title) || len(f.Recommendations.Actions) == 0 || !strings.Contains(f.Uncertainty, "not run") {
				t.Fatalf("finding=%+v", f)
			}
			after, _ := json.Marshal(r.Uses[0])
			if !bytes.Equal(before, after) {
				t.Fatal("presentation changed detector evidence")
			}
			if tt.gap == "input_validation_unresolved" && !strings.Contains(f.Validation, "not been established") {
				t.Fatal(f.Validation)
			}
		})
	}
}

func TestHumanFindingAssessmentStatus(t *testing.T) {
	for _, tt := range []struct{ assessment, finding, record string }{{"completed", "protected_for_claim", "protection"}, {"completed", "supported_potential", "analysis"}, {"failed", "protected_for_claim", "analysis"}, {"not_run", "supported_potential", "analysis"}} {
		u := analysis.CandidateUse{Kind: "outbound_http_candidate", Assessment: analysis.Assessment{Status: tt.assessment, FindingStatus: tt.finding}}
		f := describe(u)
		if f.RecordType != tt.record {
			t.Fatalf("%+v -> %+v", tt, f)
		}
	}
}

func TestStandaloneHTMLGroupsAndEscapesSavedEvidence(t *testing.T) {
	hostile := `<script>alert('source')</script><img src="https://example.invalid/beacon">`
	r := &analysis.AnalysisReport{SchemaVersion: 1, Root: hostile, Entries: []analysis.EntryPoint{
		testHTTPEntry(analysis.Route{ID: "one", Method: "GET", PathPattern: "/same", Registration: analysis.Span{File: hostile, StartLine: 1}}),
		testHTTPEntry(analysis.Route{ID: "two", Method: "POST", PathPattern: "/same"}),
		testHTTPEntry(analysis.Route{ID: "empty", Method: "GET", PathPattern: "/empty"}),
	}, Uses: []analysis.CandidateUse{
		{ID: "u1", EntryID: "one", Kind: "nosql_query_candidate", Sink: analysis.Evidence{Text: hostile}, Dependencies: requestDependency(), Gaps: []analysis.Gap{{Kind: "query_text_interpolated"}}},
		{ID: "u2", EntryID: "two", Kind: "input_validation_candidate"},
		{ID: "u3", EntryID: "missing", Kind: "outbound_http_candidate"},
	}}
	var b bytes.Buffer
	if err := HTML(&b, r); err != nil {
		t.Fatal(err)
	}
	html := b.String()
	for _, want := range []string{"GET /same", "POST /same", "GET /empty", "Unresolved entry", "No established findings", "Remediation", "$where", "default-src 'none'"} {
		if !strings.Contains(html, want) {
			t.Fatalf("missing %q", want)
		}
	}
	if strings.Count(html, `<details class="entry`) != 4 || strings.Count(html, `<article class="finding" `) != 3 {
		t.Fatal("lost or duplicated rows/findings")
	}
	for _, bad := range []string{"<img", "<link", "fetch(", "XMLHttpRequest"} {
		if strings.Contains(html, bad) {
			t.Fatalf("active or external content: %s", bad)
		}
	}
	if strings.Count(html, "<script>") != 1 || !strings.Contains(html, "<script>"+sortSource+"</script>") {
		t.Fatal("report included a script other than the bundled sorter")
	}
	if !strings.Contains(html, "&lt;script&gt;") {
		t.Fatal("hostile source was not escaped")
	}
	var next bytes.Buffer
	if err := HTML(&next, r); err != nil {
		t.Fatal(err)
	}
	if b.String() != next.String() {
		t.Fatal("unstable output")
	}
}

func TestPoorPracticeRemainsActionableAcrossModelOutcomes(t *testing.T) {
	for _, tt := range []struct{ status, finding, protection string }{
		{"not_run", "", ""}, {"failed", "", ""}, {"completed", "needs_evidence", "uncertain"}, {"completed", "supported_potential", "insufficient"}, {"completed", "protected_for_claim", "sufficient"},
	} {
		u := analysis.CandidateUse{ID: "u", Kind: "sql_query_candidate", Sink: analysis.Evidence{Text: "db.query(`SELECT ${value}`)"}, Dependencies: requestDependency(), Gaps: []analysis.Gap{{Kind: "query_text_interpolated"}}, Assessment: analysis.Assessment{Status: tt.status, FindingStatus: tt.finding, Protection: tt.protection}}
		original, _ := json.Marshal(u.Assessment)
		r := &analysis.AnalysisReport{Uses: []analysis.CandidateUse{u}}
		Enrich(r)
		f := r.Findings[0]
		if f.RecordType != "finding" || f.Status != "poor_practice" {
			t.Fatalf("%+v -> %+v", tt, f)
		}
		after, _ := json.Marshal(r.Uses[0].Assessment)
		if !bytes.Equal(original, after) {
			t.Fatal("changed raw assessment")
		}
		result := SARIF(r)["runs"].([]any)[0].(map[string]any)["results"].([]any)[0].(map[string]any)
		if result["kind"] != "fail" || result["level"] != "warning" {
			t.Fatal("SARIF hid actionable practice")
		}
	}
}

func TestHTMLDefaultsToGroupedCountsThenRoutePath(t *testing.T) {
	r := &analysis.AnalysisReport{Entries: []analysis.EntryPoint{
		testHTTPEntry(analysis.Route{ID: "z", Method: "DELETE", PathPattern: "/z"}),
		testHTTPEntry(analysis.Route{ID: "b", Method: "GET", PathPattern: "/b"}),
		testHTTPEntry(analysis.Route{ID: "a-post", Method: "POST", PathPattern: "/a"}),
		testHTTPEntry(analysis.Route{ID: "a-get", Method: "GET", PathPattern: "/a"}),
	}, Uses: []analysis.CandidateUse{
		{ID: "finding", EntryID: "z", Kind: "sql_query_candidate", Dependencies: requestDependency(), Gaps: []analysis.Gap{{Kind: "query_text_interpolated"}}},
		{ID: "orphan", EntryID: "unresolved", Kind: "outbound_http_candidate"},
		{ID: "review", EntryID: "a-post", Kind: "outbound_http_candidate"},
		{ID: "protected", EntryID: "b", Kind: "outbound_http_candidate", Assessment: analysis.Assessment{Status: "completed", FindingStatus: "protected_for_claim"}},
	}}
	var out bytes.Buffer
	if err := HTML(&out, r); err != nil {
		t.Fatal(err)
	}
	previous := -1
	for _, id := range []string{"z", "a-post", "unresolved", "b", "a-get"} {
		position := strings.Index(out.String(), `id="`+id+`"`)
		if position <= previous {
			t.Fatalf("route %s missing or out of order", id)
		}
		previous = position
	}
}

func TestConfirmedInjectionKeepsValidationAsReviewCategory(t *testing.T) {
	u := analysis.CandidateUse{ID: "u", EntryID: "r", Kind: "sql_query_candidate", Sink: analysis.Evidence{Text: "query text"}, Dependencies: requestDependency(), Gaps: []analysis.Gap{{Kind: "query_text_interpolated"}, {Kind: "input_validation_absent"}}, APIModel: &analysis.APIModel{ID: "sequelize-raw-query-v1"}, Completeness: &analysis.Completeness{ClaimKind: "injection"}, Assessment: analysis.Assessment{Status: "completed", FindingStatus: "confirmed_vulnerability", Answers: map[string]string{"injection_protection": "vulnerable"}}}
	f := describe(u)
	if f.Status != "confirmed_vulnerability" || f.RecordType != "finding" {
		t.Fatalf("finding=%+v", f)
	}
	pills := rowTypePills([]htmlItem{{Finding: f, Use: u}})
	for _, p := range pills {
		if p.ID == "sql-injection" && p.Tone != "confirmed-vulnerability" {
			t.Fatal(p)
		}
		if p.ID == "input-validation" && p.Status != "review" {
			t.Fatal("injection confirmation leaked into validation", p)
		}
	}
}

func TestInconclusiveRenderingNeverUsesProtectedBadge(t *testing.T) {
	u := analysis.CandidateUse{ID: "x", Kind: "xss_candidate", XSS: &analysis.XSSFacts{Type: "stored", OutputContext: "html_text", Protection: "encoded", OriginResolved: true}, Assessment: analysis.Assessment{Status: "completed", FindingStatus: "needs_evidence", Protection: "uncertain", Answers: map[string]string{"xss_exposure": "unknown"}}}
	r := &analysis.AnalysisReport{Uses: []analysis.CandidateUse{u}}
	var out bytes.Buffer
	if err := HTML(&out, r); err != nil {
		t.Fatal(err)
	}
	if r.Findings[0].RecordType != "analysis" || r.Findings[0].Status != "needs_evidence" {
		t.Fatalf("inconclusive claim remains Protected: %+v", r.Findings[0])
	}
	if strings.Contains(out.String(), `class="badge protection status-needs_evidence"`) {
		t.Fatal("Inconclusive badge inherits green protection styling")
	}
}
