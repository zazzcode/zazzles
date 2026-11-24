package langjs

import (
	"path/filepath"
	"sort"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

type configurationWant struct {
	file   string
	line   int
	check  string
	value  string
	entry  string
	access string // authentication of the mount, as joined evidence ("" for a cookie setting)
}

// TestExpressConfiguration covers D-9: a serve-index mount (with and without an
// authentication middleware before it), express.static alone, and session
// cookie options that are false in the literal, through a variable, or true.
func TestExpressConfiguration(t *testing.T) {
	for _, tt := range []struct {
		name string
		dir  string
		want []configurationWant
	}{
		{"primary", "configuration-express/primary", []configurationWant{
			{"server.ts", 8, analysis.CheckSessionCookieScript, "false", "USE /variable", ""},
			{"server.ts", 8, analysis.CheckSessionCookieTransport, "false", "USE /variable", ""},
			{"server.ts", 11, analysis.CheckDirectoryListing, "serve-index", "USE /public-files", analysis.AccessNone},
			{"server.ts", 12, analysis.CheckDirectoryListing, "serve-index", "USE /private-files", analysis.AccessRequired},
			{"server.ts", 14, analysis.CheckSessionCookieScript, "false", "USE /literal", ""},
			{"server.ts", 14, analysis.CheckSessionCookieTransport, "false", "USE /literal", ""},
		}},
		{"transfer", "configuration-express/transfer", []configurationWant{
			{"index.js", 7, analysis.CheckSessionCookieScript, "false", "USE /", ""},
			{"index.js", 10, analysis.CheckDirectoryListing, "serve-index", "USE /browse", analysis.AccessRequired},
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			report, err := Analyze(filepath.Join("testdata", tt.dir), "")
			if err != nil {
				t.Fatal(err)
			}
			var got []configurationWant
			for _, u := range report.Uses {
				if u.Kind != analysis.ConfigurationKind {
					continue
				}
				f := u.Configuration
				if f == nil {
					t.Fatal("configuration use without facts")
				}
				if u.Components == nil || u.Components.Failure != "" {
					t.Fatalf("no component selection: %+v", u.Components)
				}
				if u.Completeness == nil || len(u.Completeness.Evidence["setting"]) == 0 || len(u.Completeness.Evidence["scope"]) == 0 {
					t.Fatalf("configuration use at line %d lacks setting or scope evidence", u.Sink.Span.StartLine)
				}
				entry, access := "", ""
				for _, e := range report.Entries {
					if e.ID == u.EntryID {
						entry = e.Name
					}
				}
				for _, j := range f.Joined {
					if j.Kind == "mount_access" {
						access = "none"
						if containsText(j.ModelText, "authentication: required") {
							access = analysis.AccessRequired
						}
					}
				}
				got = append(got, configurationWant{u.Sink.Span.File, u.Sink.Span.StartLine, f.Check, f.Value, entry, access})
			}
			sort.Slice(got, func(i, j int) bool {
				if got[i].line != got[j].line {
					return got[i].line < got[j].line
				}
				return got[i].check < got[j].check
			})
			want := append([]configurationWant{}, tt.want...)
			sort.Slice(want, func(i, j int) bool {
				if want[i].line != want[j].line {
					return want[i].line < want[j].line
				}
				return want[i].check < want[j].check
			})
			if len(got) != len(want) {
				t.Fatalf("recorded %d configuration candidates, want %d: %+v", len(got), len(want), got)
			}
			for i := range got {
				if got[i] != want[i] {
					t.Errorf("candidate %d = %+v, want %+v", i, got[i], want[i])
				}
			}
		})
	}
}
