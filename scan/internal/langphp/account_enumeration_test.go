package langphp

import (
	"fmt"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

// accountUses returns the uses of kind under the named entry.
func accountUses(r *analysis.AnalysisReport, kind, entry string) []analysis.CandidateUse {
	id := ""
	for _, e := range r.Entries {
		if e.Name == entry {
			id = e.ID
		}
	}
	var out []analysis.CandidateUse
	for _, u := range r.Uses {
		if u.Kind == kind && (entry == "" || u.EntryID == id) {
			out = append(out, u)
		}
	}
	return out
}

func responseList(side []analysis.BranchResponse) string {
	parts := make([]string, 0, len(side))
	for _, r := range side {
		parts = append(parts, r.Kind+":"+r.Literal)
	}
	return strings.Join(parts, "|")
}

func accountSummary(r *analysis.AnalysisReport, kind string) string {
	var b strings.Builder
	names := map[string]string{}
	for _, e := range r.Entries {
		names[e.ID] = e.Name
	}
	for _, u := range r.Uses {
		if u.Kind == kind {
			fmt.Fprintf(&b, "%s %s:%d\n", names[u.EntryID], u.Sink.Span.File, u.Sink.Span.StartLine)
		}
	}
	return b.String()
}

func blockerKinds(u analysis.CandidateUse) []string {
	var out []string
	if u.Completeness != nil {
		for _, g := range u.Completeness.Blockers {
			out = append(out, g.Kind)
		}
	}
	return out
}

// Enumeration cases: Symfony, transfer and plain-PHP lookups by request values.
func TestAccountEnumeration(t *testing.T) {
	type want struct {
		line            int
		found, notFound string
		blocker         string
	}
	reports := fixtureReports{}
	for _, tt := range []struct {
		id, root, entry string
		want            []want
	}{
		{"EN-01", "testdata/symfony/account", "POST /join", []want{{24, "flash:That address is taken|redirect:join", "redirect:home", ""}}},
		{"EN-02", "testdata/symfony/account", "POST /join/both", []want{{39, "flash:Address taken|redirect:join", "redirect:home", ""}, {44, "flash:Nickname taken|redirect:join", "redirect:home", ""}}},
		{"EN-03", "testdata/symfony/account", "POST /forgot", []want{{15, "flash:Check your inbox|redirect:forgot", "flash:No such address|redirect:forgot", ""}}},
		{"EN-04", "testdata/symfony/account", "POST /forgot/quiet", nil},
		{"EN-05", "testdata/symfony/account", "POST /staff/join", nil},
		{"EN-06", "testdata/symfony/account", "POST /office/join", []want{{66, "flash:That address is taken|redirect:join", "redirect:home", "access_rule_condition_unmodeled"}}},
		{"EN-07", "testdata/symfony/account", "POST /join/linked", nil},
		{"EN-08", "testdata/symfony/account", "POST /product/check", nil},
		{"EN-09", "testdata/symfony/account", "POST /join/relay", []want{{101, "response_unresolved:", "redirect:home", analysis.ResponseUnresolved}}},
		{"EN-10", "testdata/symfony/account", "POST /sign/check", nil},
		{"EN-11", "testdata/symfony/account-transfer", "POST /api/members", []want{{31, "body:['error' => 'handle exists']|status:409", "body:['created' => true]|status:201", ""}}},
		{"EN-12", "testdata/symfony/account-transfer", "POST /api/members/probe", nil},
		{"EN-13", "testdata/account-plain", "FILE /join.php", []want{{4, "body:That address has an account", "body:Choose a password", ""}}},
		{"EN-14", "testdata/account-plain", "FILE /stock.php", nil},
		{"EN-15", "testdata/account-plain", "FILE /login.php", nil},
		{"EN-16", "testdata/symfony/account", "POST /sign/magic", nil},
		{"EN-17", "testdata/symfony/account", "POST /member/lookup", []want{{28, "redirect:member", "flash:No such member|redirect:home", ""}}},
		{"EN-18", "testdata/account-plain-variable", "FILE /signin.php", nil},
		{"EN-19", "testdata/account-plain-variable", "FILE /lookup.php", nil},
		{"EN-20", "testdata/account-plain-variable", "FILE /append.php", nil},
	} {
		t.Run(tt.id, func(t *testing.T) {
			r := reports.get(t, tt.root)
			uses := accountUses(r, analysis.AccountEnumerationKind, tt.entry)
			if len(uses) != len(tt.want) {
				t.Fatalf("%d candidates, want %d; all:\n%s", len(uses), len(tt.want), accountSummary(r, analysis.AccountEnumerationKind))
			}
			for i, w := range tt.want {
				u := uses[i]
				f := u.Enumeration
				if f == nil || u.Sink.Span.StartLine != w.line {
					t.Fatalf("candidate %d at %d, want %d (%+v)", i, u.Sink.Span.StartLine, w.line, f)
				}
				if got := responseList(f.Found); got != w.found {
					t.Fatalf("found %q, want %q", got, w.found)
				}
				if got := responseList(f.NotFound); got != w.notFound {
					t.Fatalf("not_found %q, want %q", got, w.notFound)
				}
				if err := f.Validate(); err != nil {
					t.Fatal(err)
				}
				blockers := blockerKinds(u)
				if w.blocker == "" && len(blockers) > 0 || w.blocker != "" && !strings.Contains(strings.Join(blockers, ","), w.blocker) {
					t.Fatalf("blockers %v, want %q", blockers, w.blocker)
				}
				if !hasInputDependency(u) {
					t.Fatal("candidate has no request source dependency")
				}
				if u.EntryFacts == nil && u.Completeness.Evidence["entry_access"] == nil {
					t.Fatal("no entry access evidence")
				}
			}
		})
	}
}

// fixtureReports analyzes each fixture root once per test.
type fixtureReports map[string]*analysis.AnalysisReport

func (c fixtureReports) get(t *testing.T, root string) *analysis.AnalysisReport {
	t.Helper()
	if c[root] == nil {
		c[root] = phpAnalyze(t, root, "")
	}
	return c[root]
}

func hasInputDependency(u analysis.CandidateUse) bool {
	for _, d := range u.Dependencies {
		if d.Source.Kind == "input_source" {
			return true
		}
	}
	return false
}
