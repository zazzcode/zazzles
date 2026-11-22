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

// One stubbed Confirmed candidate of each account kind reaches the JSON,
// SARIF and HTML reports with its type, CWE and guidance. A password-hash
// record anchored at a YAML line renders with that file and line.
func TestAccountFindingsReport(t *testing.T) {
	e := analysis.Evidence{Span: analysis.Span{File: "src/Controller/JoinController.php", StartLine: 24}}
	for _, tt := range []struct {
		kind, typeID, cwe, file, label string
		line                           int
		use                            func(*analysis.CandidateUse)
	}{
		{analysis.AccountEnumerationKind, "account-enumeration", "CWE-204", "src/Controller/JoinController.php", "Account Enumeration", 24, func(u *analysis.CandidateUse) {
			u.Enumeration = &analysis.EnumerationFacts{Lookup: analysis.EnumerationLookup{Class: `App\Entity\Account`, Evidence: e, Branch: e},
				Found: []analysis.BranchResponse{{Kind: analysis.ResponseFlash, Literal: "A"}}, NotFound: []analysis.BranchResponse{{Kind: analysis.ResponseRedirect, Literal: "home"}}}
		}},
		{analysis.RecoveryDeliveryKind, "weak-password-recovery", "CWE-640", "src/Service/ResetMailer.php", "Weak Password Recovery", 28, func(u *analysis.CandidateUse) {
			u.Recovery = &analysis.RecoveryFacts{SecretSource: e, SecretStrength: analysis.SecretCSPRNG, Recipient: e, RecipientOrigin: analysis.RecipientRequestValue,
				RecipientValidated: analysis.RecipientPartial, RecipientCount: analysis.RecipientCountRequest, ShapeUses: []analysis.Evidence{e, e}, Content: e, MailContract: "api.symfony-mailer-v1"}
			u.APIModel = analysispacks.AccountContract(analysispacks.SymfonyMailerContract)
		}},
		{analysis.PasswordHashKind, "weak-password-hash", "CWE-916", "src/Controller/ProfileController.php", "Weak Password Hash", 20, func(u *analysis.CandidateUse) {
			u.PasswordHash = &analysis.PasswordHashFacts{Algorithm: "md5", Basis: analysis.BasisCredentialField, BasisEvidence: []analysis.Evidence{e}, Salted: "no", Iterated: "no"}
			u.APIModel = analysispacks.AccountContract(analysispacks.PHPPasswordDigest)
		}},
		{analysis.PasswordHashKind, "weak-password-hash", "CWE-916", "config/packages/security.yaml", "Weak Password Hash", 6, func(u *analysis.CandidateUse) {
			u.PasswordHash = &analysis.PasswordHashFacts{Algorithm: "md5", Basis: analysis.BasisConfiguration, BasisEvidence: []analysis.Evidence{e}, Salted: "no", Iterated: "no", HasherClass: `App\Security\LegacyDigest`}
			u.APIModel = analysispacks.AccountContract(analysispacks.PHPPasswordDigest)
		}},
	} {
		t.Run(tt.typeID+" "+tt.file, func(t *testing.T) {
			span := analysis.Span{File: tt.file, StartLine: tt.line, EndLine: tt.line, StartByte: 6, EndByte: 20}
			u := analysis.CandidateUse{ID: "use:1", EntryID: "entry:1", Kind: tt.kind, Sink: analysis.Evidence{Kind: tt.kind, Text: "sink", Span: span, SHA256: "h"},
				Dependencies: []analysis.Dependency{}, Context: []analysis.Evidence{}, Gaps: []analysis.Gap{},
				Assessment: analysis.Assessment{Status: "completed", FindingStatus: "confirmed_vulnerability", Reason: "stubbed", QuestionVersion: analysispacks.AccountProtocol}}
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
