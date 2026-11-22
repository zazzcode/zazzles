package langphp

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
)

// Expected anchors are computed by hand from the fixture files.
func TestPHPExposure(t *testing.T) {
	const controller = "src/Controller/Diagnostics.php"
	type exposureCase struct {
		id, root, file string
		line           int
		record         bool
		entry          string
		operation      string
		subject        string
		flag           string
		guards         int
		gap            string
	}
	symfony := filepath.Join("testdata", "symfony", "exposure")
	plain := filepath.Join("testdata", "exposure")
	cases := []exposureCase{
		{"EX-01", symfony, controller, 15, true, "GET /diag/info", "phpinfo", analysis.ExposureConfiguration, "", 0, ""},
		{"EX-02", symfony, controller, 22, true, "GET /diag/modules", "phpinfo", analysis.ExposureConfiguration, "INFO_MODULES", 0, ""},
		{"EX-03", symfony, controller, 29, true, "GET /diag/server", "var_dump", analysis.ExposureEnvironment, "", 0, ""},
		{"EX-04", symfony, controller, 36, true, "GET /diag/env", "print_r", analysis.ExposureEnvironment, "", 0, ""},
		{"EX-05", symfony, controller, 42, true, "GET /diag/trace", "debug_print_backtrace", analysis.ExposureStack, "", 0, ""},
		{"EX-06", symfony, controller, 52, true, "GET /diag/admin", "phpinfo", analysis.ExposureConfiguration, "", 1, ""},
		{"EX-07", symfony, controller, 60, false, "", "", "", "", 0, ""},
		{"EX-08", symfony, controller, 67, false, "", "", "", "", 0, ""},
		{"EX-09", plain, "info.php", 2, true, "FILE /info.php", "phpinfo", analysis.ExposureConfiguration, "", 0, ""},
		{"EX-10", plain, "uname.php", 2, true, "FILE /uname.php", "php_uname", analysis.ExposureRuntimeState, "", 0, ""},
		{"EX-11", plain, "lib/diagnostics.php", 4, false, "", "", "", "", 0, ""},
		{"EX-12", symfony, controller, 74, true, "GET /diag/dump", "dump", analysis.ExposureRuntimeState, "", 0, analysis.ExposureEnvironmentDependent},
		{"EX-13", symfony, "templates/uname.html.twig", 1, true, "GET /diag/uname", "php_uname", analysis.ExposureRuntimeState, "", 0, ""},
	}
	reports := map[string]*analysis.AnalysisReport{}
	for _, root := range []string{symfony, plain} {
		r, err := Analyze(root, "")
		if err != nil {
			t.Fatal(err)
		}
		reports[root] = r
	}
	expected := map[string]int{}
	for _, tt := range cases {
		if tt.record {
			expected[tt.root]++
		}
	}
	for root, r := range reports {
		got := 0
		for _, u := range r.Uses {
			if u.Kind == analysis.ExposureKind {
				got++
			}
		}
		if got != expected[root] {
			t.Errorf("%s: %d exposure candidates, want %d", root, got, expected[root])
		}
	}
	for _, tt := range cases {
		t.Run(tt.id, func(t *testing.T) {
			r := reports[tt.root]
			entries := map[string]string{}
			for _, e := range r.Entries {
				entries[e.ID] = e.Name
			}
			var found []analysis.CandidateUse
			for _, u := range r.Uses {
				if u.Kind == analysis.ExposureKind && u.Sink.Span.File == tt.file && u.Sink.Span.StartLine == tt.line {
					found = append(found, u)
				}
			}
			if !tt.record {
				if len(found) != 0 {
					t.Fatalf("unexpected exposure candidate at %s:%d", tt.file, tt.line)
				}
				return
			}
			if len(found) != 1 {
				t.Fatalf("%d candidates at %s:%d, want 1", len(found), tt.file, tt.line)
			}
			u := found[0]
			x := u.Exposure
			if x == nil {
				t.Fatal("missing exposure facts")
			}
			if err := x.Validate(); err != nil {
				t.Fatal(err)
			}
			if entries[u.EntryID] != tt.entry || x.Operation != tt.operation || x.Subject != tt.subject || x.Flag != tt.flag || x.EntryServed != "yes" {
				t.Fatalf("got entry %q facts %+v", entries[u.EntryID], *x)
			}
			if len(x.Guards) != tt.guards {
				t.Fatalf("guards %v, want %d", x.Guards, tt.guards)
			}
			if u.APIModel == nil || u.APIModel.ID != analysispacks.PHPDiagnosticOutput {
				t.Fatalf("contract %v", u.APIModel)
			}
			c := u.Completeness
			if c == nil || c.ClaimKind != "exposure" {
				t.Fatal("missing exposure completeness")
			}
			for _, role := range analysispacks.ExposureRoles() {
				if len(c.Evidence[role]) == 0 {
					t.Fatalf("missing evidence role %s", role)
				}
			}
			blockers := fmt.Sprint(c.Blockers)
			if tt.gap == "" && len(c.Blockers) != 0 || tt.gap != "" && (len(c.Blockers) != 1 || c.Blockers[0].Kind != tt.gap) {
				t.Fatalf("blockers %s, want %q", blockers, tt.gap)
			}
			if u.Components == nil || u.Components.Failure != "" {
				t.Fatalf("component selection %+v", u.Components)
			}
		})
	}
}
