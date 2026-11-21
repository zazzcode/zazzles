package report

import (
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"strings"
	"testing"
)

func TestSourceSpecificSQLiteRemediation(t *testing.T) {
	for _, tt := range []struct{ name, source, wantSQL, wantParams string }{
		{"fstring with LIKE", `query = f"SELECT name FROM files WHERE owner = {owner} AND name LIKE '%{search}%'"`, "owner = ? AND name LIKE ?", `owner, "%" + str(search) + "%"`},
		{"percent value", `cur.execute("select * from accounts where name = '%s'" % name)`, "name = ?", "name,"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			u := analysis.CandidateUse{Kind: "sql_query_candidate", APIModel: &analysis.APIModel{Library: "sqlite3"}, Sink: analysis.Evidence{Text: tt.source, Span: analysis.Span{File: "app.py", StartLine: 18}}, Dependencies: requestDependency(), Gaps: []analysis.Gap{{Kind: "query_text_interpolated"}}}
			f := describe(u)
			g := f.Recommendations
			if !strings.Contains(g.Example, tt.wantSQL) || !strings.Contains(g.Example, tt.wantParams) || strings.Contains(g.Example, "sequelize") {
				t.Fatalf("wrong driver/source repair %+v", g)
			}
		})
	}
	if _, _, ok := pythonSQLValueCandidate(`q=f"SELECT * FROM {table}"`); ok {
		t.Fatal("dynamic table name treated as a bindable value")
	}
}
func TestProtectedAndReviewDoNotPrescribeUnprovenFixes(t *testing.T) {
	protected := analysis.CandidateUse{Kind: "xss_candidate", Sink: analysis.Evidence{Text: "{{ user.team }}", Span: analysis.Span{File: "profile.html", StartLine: 46}}, XSS: &analysis.XSSFacts{Protection: "encoded", OutputContext: "html_text", OriginResolved: true}}
	f := describe(protected)
	if f.Recommendations.Example != "" || !strings.Contains(f.Recommendations.Title, "Preserve") {
		t.Fatal("Protected output receives repair template")
	}
	protected.Assessment = analysis.Assessment{Status: "completed", FindingStatus: "needs_evidence", Protection: "uncertain"}
	f = describe(protected)
	if !strings.Contains(f.Recommendations.Title, "Resolve") || f.Recommendations.Example != "" {
		t.Fatal("Review output prescribes a patch")
	}
}
func TestRawTemplateAndDOMRepairsNameExactOperation(t *testing.T) {
	for _, source := range []string{`{{ user.country | safe }}`, `$comments.append('<li>' + comment + '</li>')`} {
		u := analysis.CandidateUse{Kind: "xss_candidate", Sink: analysis.Evidence{Text: source, Span: analysis.Span{File: "view.html", StartLine: 12}}, XSS: &analysis.XSSFacts{Type: "reflected", Protection: "raw", OutputContext: "html_text", OriginResolved: true}}
		g := describe(u).Recommendations
		if g.Example == "" || !strings.Contains(strings.Join(g.Actions, " "), "view.html:12") {
			t.Fatalf("source-specific repair missing %+v", g)
		}
	}
}

func TestProtectedDisplayCannotOverrideCanonicalBlocker(t *testing.T) {
	u := analysis.CandidateUse{Kind: "xss_candidate", XSS: &analysis.XSSFacts{Protection: "encoded", OutputContext: "html_text"}, Completeness: &analysis.Completeness{Blockers: []analysis.Gap{{Kind: "unresolved_helper"}}}, Assessment: analysis.Assessment{Status: "completed", FindingStatus: "protected_for_claim"}}
	f := describe(u)
	if f.RecordType == "protection" || f.Status != "needs_evidence" || f.Title == "Context-appropriate rendering protection is present" {
		t.Fatalf("unsafe display: %+v", f)
	}
}

func TestProtectedSQLHeadingAndValidationScope(t *testing.T) {
	u := analysis.CandidateUse{Kind: "sql_query_candidate", Gaps: []analysis.Gap{{Kind: "input_validation_absent", Detail: "No complete policy established"}}, Assessment: analysis.Assessment{Status: "completed", FindingStatus: "protected_for_claim", Answers: map[string]string{"injection_protection": "protected", "validation": "insufficient"}, Protection: "sufficient"}}
	f := describe(u)
	if f.RecordType != "protection" || f.Title != "SQL values remain separate from query syntax" {
		t.Fatalf("contradictory SQL heading: %+v", f)
	}
	if strings.Contains(f.Validation, "No validator call") || !strings.Contains(f.Validation, "not an independent field-policy finding") {
		t.Fatal("coarse SQL record claimed an absent guard or independent validation defect")
	}
}
