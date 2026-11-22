package langphp

import (
	"path/filepath"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

func TestSymfonyAccess(t *testing.T) {
	cases := []struct {
		id, entry, auth string
		roles           []string
		gap             string
		sourceText      string
		sourceKind      string
	}{
		{"ar01", "ANY /manage/items", analysis.AccessRequired, []string{"ROLE_STAFF"}, "", "^/manage", "access_rule"},
		{"ar02", "ANY /items", analysis.AccessNone, nil, "", "no rule matched", "access_rule"},
		{"ar03", "ANY /manage/public/info", analysis.AccessNone, nil, "", "^/manage/public", "access_rule"},
		{"ar04", "ANY /manage/public/info", analysis.AccessRequired, []string{"ROLE_STAFF"}, "", "^/manage", "access_rule"},
		{"ar05", "ANY /both/x", analysis.AccessRequired, []string{"ROLE_A", "ROLE_B"}, "", "", "access_rule"},
		{"ar06", "GET /api/x", analysis.AccessNone, nil, "", "no rule matched", "access_rule"},
		{"ar06", "POST /api/x", analysis.AccessRequired, []string{"ROLE_API"}, "", "^/api", "access_rule"},
		{"ar07", "ANY /internal/x", analysis.AccessUnresolved, nil, "access_rule_condition_unmodeled", "", ""},
		{"ar08", "ANY /secret", analysis.AccessUnresolved, nil, "access_rule_unresolved", "", ""},
		{"ar09", "ANY /desk/home", analysis.AccessUnresolved, nil, "access_rule_unresolved", "", ""},
		{"ar10", "ANY /item/{id}/edit", analysis.AccessRequired, []string{"ROLE_X"}, "", "^/item", "access_rule"},
		{"ar11", "ANY /item/{id}", analysis.AccessUnresolved, nil, "access_rule_unresolved", "", ""},
		{"ar12", "ANY /health/live", analysis.AccessNone, nil, "", "^/health", "firewall"},
		{"ar13", "ANY /health/live", analysis.AccessUnresolved, nil, "symfony_config_unread", "", ""},
		{"ar14", "ANY /desk/home", analysis.AccessRequired, []string{"ROLE_MEMBER"}, "", "", "role_hierarchy"},
	}
	for _, tt := range cases {
		t.Run(tt.id+" "+tt.entry, func(t *testing.T) {
			root := filepath.Join("testdata", "symfony", "access", tt.id)
			report := phpAnalyze(t, root, "")
			entry := accessEntry(t, report, tt.entry)
			if entry.Access == nil {
				t.Fatal("missing access")
			}
			if entry.Access.Authentication != tt.auth {
				t.Fatalf("authentication %s, want %s (gaps %v)", entry.Access.Authentication, tt.auth, entry.Access.Gaps)
			}
			if stringsJoin(entry.Access.Roles) != stringsJoin(tt.roles) {
				t.Fatalf("roles %v, want %v", entry.Access.Roles, tt.roles)
			}
			if tt.gap != "" && !hasGap(entry.Access.Gaps, tt.gap) {
				t.Fatalf("gaps %v, want %s", entry.Access.Gaps, tt.gap)
			}
			if tt.sourceKind != "" && !accessSource(entry.Access, tt.sourceKind, tt.sourceText) {
				t.Fatalf("sources %+v, want kind %s text %q", entry.Access.Sources, tt.sourceKind, tt.sourceText)
			}
		})
	}
}

func TestSymfonyAccessChecks(t *testing.T) {
	cases := []struct {
		id, entry, auth string
		roles           []string
		gap             string
		sources         int
	}{
		{"ac01", "ANY /desk/a", analysis.AccessRequired, []string{"ROLE_STAFF"}, "", 1},
		{"ac01", "ANY /desk/b", analysis.AccessRequired, []string{"ROLE_STAFF"}, "", 1},
		{"ac02", "ANY /desk/a", analysis.AccessRequired, []string{"ROLE_STAFF"}, "", 1},
		{"ac02", "ANY /desk/b", analysis.AccessNone, nil, "", 1},
		{"ac03", "ANY /desk/a", analysis.AccessRequired, []string{"ROLE_STAFF"}, "", 1},
		{"ac04", "ANY /desk/a", analysis.AccessRequired, []string{"ROLE_STAFF"}, "", 1},
		{"ac05", "ANY /desk/a", analysis.AccessNone, nil, "", 1},
		{"ac06", "ANY /desk/a", analysis.AccessUnresolved, nil, "voter_unmodeled", 1},
		{"ac07", "ANY /desk/a", analysis.AccessUnresolved, nil, "access_expression_unmodeled", 1},
		{"ac08", "ANY /desk/a", analysis.AccessRequired, []string{"ROLE_STAFF"}, "", 2},
	}
	for _, tt := range cases {
		t.Run(tt.id+" "+tt.entry, func(t *testing.T) {
			root := filepath.Join("testdata", "symfony", "access", tt.id)
			report := phpAnalyze(t, root, "")
			entry := accessEntry(t, report, tt.entry)
			if entry.Access == nil {
				t.Fatal("missing access")
			}
			if entry.Access.Authentication != tt.auth {
				t.Fatalf("authentication %s, want %s gaps %v sources %v", entry.Access.Authentication, tt.auth, entry.Access.Gaps, entry.Access.Sources)
			}
			if stringsJoin(entry.Access.Roles) != stringsJoin(tt.roles) {
				t.Fatalf("roles %v, want %v", entry.Access.Roles, tt.roles)
			}
			if tt.gap != "" && !hasGap(entry.Access.Gaps, tt.gap) {
				t.Fatalf("gaps %v, want %s", entry.Access.Gaps, tt.gap)
			}
			if tt.sources > 0 && len(entry.Access.Sources) < tt.sources {
				t.Fatalf("sources %d, want at least %d (%v)", len(entry.Access.Sources), tt.sources, entry.Access.Sources)
			}
		})
	}
}

func accessEntry(t *testing.T, report *analysis.AnalysisReport, name string) analysis.EntryPoint {
	t.Helper()
	for _, e := range report.Entries {
		if e.Name == name {
			return e
		}
	}
	var names []string
	for _, e := range report.Entries {
		names = append(names, e.Name)
	}
	t.Fatalf("no entry %s in %v", name, names)
	return analysis.EntryPoint{}
}

func hasGap(gaps []analysis.Gap, kind string) bool {
	for _, g := range gaps {
		if g.Kind == kind {
			return true
		}
	}
	return false
}

func accessSource(a *analysis.EntryAccess, kind, text string) bool {
	for _, s := range a.Sources {
		if s.Kind != kind {
			continue
		}
		if text == "" || s.Text == text || containsText(s.Text, text) {
			return true
		}
	}
	return false
}

func containsText(s, part string) bool {
	return len(part) > 0 && len(s) >= len(part) && (s == part || len(s) > 0 && (stringIndex(s, part) >= 0))
}

func stringIndex(s, part string) int {
	for i := 0; i+len(part) <= len(s); i++ {
		if s[i:i+len(part)] == part {
			return i
		}
	}
	return -1
}

func stringsJoin(v []string) string {
	out := ""
	for i, s := range v {
		if i > 0 {
			out += ","
		}
		out += s
	}
	return out
}
