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

// One stubbed Confirmed candidate per family reaches the JSON, SARIF and HTML
// reports with its type, CWE and guidance.
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
	} {
		t.Run(tt.typeID, func(t *testing.T) {
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
