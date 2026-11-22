package report

import (
	"bytes"
	"encoding/json"
	"html"
	"slices"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
)

func TestAuthorizationFindingsReport(t *testing.T) {
	ssrf := analysis.CandidateUse{ID: "use:ssrf", EntryID: "entry:ssrf", Kind: "ssrf_candidate",
		Assessment: analysis.Assessment{Status: "completed", FindingStatus: "confirmed_vulnerability", RequestDigest: "saved-request"}}
	address := analysis.CandidateUse{ID: "use:address", EntryID: "entry:address", Kind: analysis.AuthorizationKind,
		Authorization: &analysis.AuthorizationFacts{
			Guards: []analysis.AuthorizationGuard{{Kind: analysis.GuardAddress}}, ServerSideRequests: []string{ssrf.ID},
		}}
	r := &analysis.AnalysisReport{
		Uses: []analysis.CandidateUse{ssrf, address},
		Entries: []analysis.EntryPoint{
			{ID: ssrf.EntryID, Kind: "http", Name: "POST /fetch", Access: &analysis.EntryAccess{Authentication: analysis.AccessRequired, Roles: []string{"ROLE_STAFF"}}},
			{ID: address.EntryID, Kind: "http", Name: "POST /internal", Access: &analysis.EntryAccess{Authentication: analysis.AccessNone}},
		},
	}
	Enrich(r)
	if got := r.Findings[0].RelatedFindings; !slices.Equal(got, []string{r.Findings[1].ID}) {
		t.Errorf("SSRF related findings = %v, want %s", got, r.Findings[1].ID)
	}
	if got := r.Findings[1].RelatedFindings; !slices.Equal(got, []string{r.Findings[0].ID}) {
		t.Errorf("authorization related findings = %v, want %s", got, r.Findings[0].ID)
	}
	if got := r.Uses[0].Assessment.RequestDigest; got != ssrf.Assessment.RequestDigest {
		t.Errorf("saved SSRF request digest changed: %q", got)
	}
	var page bytes.Buffer
	if err := HTML(&page, r); err != nil {
		t.Fatal(err)
	}
	for _, detail := range []string{"required ROLE_STAFF", "none none"} {
		if !strings.Contains(page.String(), "<strong>Access</strong>: <code>"+detail+"</code>") {
			t.Errorf("HTML entry view missing Access detail %q", detail)
		}
	}
}

// Stubbed Confirmed candidates reach the JSON, SARIF and HTML reports with
// their type, CWE and guidance.
func TestApplicationFindingsReport(t *testing.T) {
	for _, tt := range []struct {
		kind, typeID, cwe, file, label string
		line                           int
		use                            func(*analysis.CandidateUse)
	}{
		{analysis.ExposureKind, "information-exposure", "CWE-200", "public/diag.php", "Information Exposure", 2, func(u *analysis.CandidateUse) {
			u.Exposure = &analysis.ExposureFacts{Operation: "phpinfo", Subject: analysis.ExposureConfiguration, EntryServed: "yes"}
			u.Assessment.QuestionVersion = analysispacks.ExposureProtocol
		}},
		{analysis.MassAssignmentKind, "mass-assignment", "CWE-915", "src/Entity/Account.php", "Mass Assignment", 29, func(u *analysis.CandidateUse) {
			u.MassAssignment = &analysis.MassAssignmentFacts{Shape: analysis.MassAssignmentPropertyWrite, TargetClass: `App\Entity\Account`, TargetStored: "yes", SecurityFields: []analysis.SecurityField{}}
			u.Assessment.QuestionVersion = analysispacks.MassAssignmentProtocol
		}},
		{analysis.AuthorizationKind, "missing-authorization", "CWE-639", "src/Controller/AdminController.php", "Missing Authorization", 32, func(u *analysis.CandidateUse) {
			u.Authorization = &analysis.AuthorizationFacts{Facets: []string{analysis.FacetObjectLevel}, SubjectClass: `App\Entity\User`, SubjectProvenance: analysis.SubjectRequestSelected, Operation: analysis.StateChange{Operation: "update"}, MethodSafe: "no"}
			u.Assessment.QuestionVersion = analysispacks.AuthorizationProtocol
		}},
		{analysis.AuthorizationKind, "missing-authorization", "CWE-862", "src/Controller/FeatureController.php", "Missing Authorization", 25, func(u *analysis.CandidateUse) {
			u.Authorization = &analysis.AuthorizationFacts{Facets: []string{analysis.FacetFunctionLevel}, SubjectClass: `App\Entity\Feature`, SubjectProvenance: analysis.SubjectCreated, Operation: analysis.StateChange{Operation: "update"}, MethodSafe: "no"}
			u.Assessment.QuestionVersion = analysispacks.AuthorizationProtocol
		}},
		{analysis.AuthorizationKind, "address-based-access", "CWE-291", "src/Controller/LocalController.php", "Address-Based Access", 77, func(u *analysis.CandidateUse) {
			u.Authorization = &analysis.AuthorizationFacts{Facets: []string{analysis.FacetFunctionLevel}, SubjectClass: `App\Entity\User`, SubjectProvenance: analysis.SubjectRequestSelected, Operation: analysis.StateChange{Operation: "update"}, MethodSafe: "yes", Guards: []analysis.AuthorizationGuard{{Kind: analysis.GuardAddress, Evidence: analysis.Evidence{Span: analysis.Span{File: "src/Controller/LocalController.php"}}}}}
			u.Assessment.QuestionVersion = analysispacks.AuthorizationProtocol
		}},
	} {
		t.Run(tt.typeID+"/"+tt.cwe, func(t *testing.T) {
			span := analysis.Span{File: tt.file, StartLine: tt.line, EndLine: tt.line, StartByte: 6, EndByte: 20}
			u := analysis.CandidateUse{ID: "use:1", EntryID: "entry:1", Kind: tt.kind, Sink: analysis.Evidence{Kind: tt.kind, Text: "sink", Span: span, SHA256: "h"},
				Dependencies: []analysis.Dependency{}, Context: []analysis.Evidence{}, Gaps: []analysis.Gap{},
				Assessment: analysis.Assessment{Status: "completed", FindingStatus: "confirmed_vulnerability", Reason: "stubbed"}}
			tt.use(&u)
			r := &analysis.AnalysisReport{Uses: []analysis.CandidateUse{u}}
			Enrich(r)
			f := r.Findings[0]
			if !slices.Equal(f.TypeIDs, []string{tt.typeID}) || f.Status != "confirmed_vulnerability" || f.RecordType != "finding" {
				t.Fatalf("finding %+v", f)
			}
			if !slices.ContainsFunc(r.FindingTypes, func(ft analysis.FindingType) bool { return ft.ID == tt.typeID }) {
				t.Fatal("finding type not listed")
			}
			raw, err := json.Marshal(SARIF(r))
			if err != nil {
				t.Fatal(err)
			}
			var sarif struct {
				Runs []struct {
					Tool struct {
						Driver struct {
							Rules []struct {
								Properties struct {
									Tags []string `json:"tags"`
								} `json:"properties"`
							} `json:"rules"`
						} `json:"driver"`
					} `json:"tool"`
					Results []struct {
						Locations []struct {
							PhysicalLocation struct {
								ArtifactLocation struct {
									URI string `json:"uri"`
								} `json:"artifactLocation"`
								Region struct {
									StartLine int `json:"startLine"`
								} `json:"region"`
							} `json:"physicalLocation"`
						} `json:"locations"`
					} `json:"results"`
				} `json:"runs"`
			}
			if err := json.Unmarshal(raw, &sarif); err != nil {
				t.Fatal(err)
			}
			tagged := false
			for _, rule := range sarif.Runs[0].Tool.Driver.Rules {
				tagged = tagged || slices.Contains(rule.Properties.Tags, tt.cwe)
			}
			if !tagged {
				t.Fatalf("no SARIF rule tagged %s: %s", tt.cwe, raw)
			}
			located := false
			for _, res := range sarif.Runs[0].Results {
				for _, l := range res.Locations {
					located = located || strings.HasSuffix(l.PhysicalLocation.ArtifactLocation.URI, tt.file) && l.PhysicalLocation.Region.StartLine == tt.line
				}
			}
			if !located {
				t.Fatalf("no SARIF result at %s:%d", tt.file, tt.line)
			}
			var page bytes.Buffer
			if err := HTML(&page, r); err != nil {
				t.Fatal(err)
			}
			text := html.UnescapeString(page.String())
			if !strings.Contains(text, tt.label) || !strings.Contains(text, guidance(u).Title) {
				t.Fatalf("HTML lacks the type label %q or the guidance %q", tt.label, guidance(u).Title)
			}
		})
	}
}
