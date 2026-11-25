package langjs

import (
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

// TestExpressAuthorizationReads covers hardening 3 D-7: a read of an owned
// record that a request key selects and the entry sends is an authorization
// candidate with the read facet. A model with no association to an account
// model, a result that is not sent, a key that goes through a server-side
// keyed store and a selector that a constant narrows record nothing. An owner
// key taken from a verified token claim is a guard and does not suppress the
// record.
func TestExpressAuthorizationReads(t *testing.T) {
	for _, tt := range []struct {
		name string
		dir  string
		want []authzWant
	}{
		{"primary", "authorization-reads/primary", []authzWant{
			{"GET /lockers/:id", "model:Locker", "read", ""},
			{"GET /lockers/:id/key", "model:Locker", "read", ""},
			{"GET /lockers", "model:Locker", "read", ""},
			{"GET /mine/:id", "model:Locker", "read", "ownership_check/query_scope"},
			// No listed authentication middleware: req.auth is a request member like any other.
			{"GET /open/:id", "model:Locker", "read", ""},
			// A comparison of a member of the result that decides whether the
			// response is sent is a guard: an ownership check against a verified
			// token claim, unclassified against anything else. A comparison with a
			// literal is not a guard.
			{"GET /checked/:id", "model:Locker", "read", "ownership_check/result_comparison"},
			{"GET /branch/:id", "model:Locker", "read", "ownership_check/result_comparison"},
			{"GET /loose/:id", "model:Locker", "read", "guard_unclassified/result_comparison"},
			{"GET /state/:id", "model:Locker", "read", ""},
			// A destructured request parameter names the claim member directly.
			{"GET /packed/:id", "model:Locker", "read", "ownership_check/query_scope"},
			// The write on the found instance carries the claim; no second record for its read.
			{"PUT /lockers/:id", "model:Locker", "update", ""},
		}},
		{"transfer", "authorization-reads/transfer", []authzWant{
			{"GET /diaries/:ref", "model:Diary", "read", ""},
			{"GET /diary", "model:Diary", "read", ""},
			{"GET /own/:ref", "model:Diary", "read", "ownership_check/query_scope"},
			{"GET /checked/:ref", "model:Diary", "read", "ownership_check/result_comparison"},
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			report, err := Analyze(filepath.Join("testdata", tt.dir), "")
			if err != nil {
				t.Fatal(err)
			}
			var got []authzWant
			for _, u := range report.Uses {
				if u.Kind != analysis.AuthorizationKind {
					continue
				}
				f := u.Authorization
				if f == nil {
					t.Fatal("authorization use without facts")
				}
				if err := f.Validate(); err != nil {
					t.Fatal(err)
				}
				entry := ""
				for _, e := range report.Entries {
					if e.ID == u.EntryID {
						entry = e.Name
					}
				}
				if f.Operation.Operation == "read" {
					if strings.Join(f.Facets, ",") != analysis.FacetObjectLevel+","+analysis.FacetDataExposure || f.SubjectProvenance != analysis.SubjectRequestSelected {
						t.Fatalf("%s: read facts %+v", entry, f)
					}
					for _, role := range []string{"subject_selection", "protected_operation", "entry_access", "control_flow", "owner_association", "response_emission"} {
						if len(u.Completeness.Evidence[role]) == 0 {
							t.Fatalf("%s: missing evidence role %s", entry, role)
						}
					}
					if u.Components == nil || u.Components.Failure != "" {
						t.Fatalf("%s: no component selection: %+v", entry, u.Components)
					}
				}
				var guards []string
				blocked := false
				for _, gap := range u.Completeness.Blockers {
					blocked = blocked || gap.Kind == analysis.GuardUnclassified
				}
				for _, g := range f.Guards {
					guards = append(guards, g.Kind+"/"+g.Form)
					// A guard the scanner cannot classify keeps the claim in Review.
					if (g.Kind == analysis.GuardUnclassified) != blocked {
						t.Fatalf("%s: guard %s with unclassified blocker = %v", entry, g.Kind, blocked)
					}
				}
				got = append(got, authzWant{entry, f.SubjectClass, f.Operation.Operation, strings.Join(guards, ",")})
			}
			sort.Slice(got, func(i, j int) bool { return got[i].entry < got[j].entry })
			want := append([]authzWant{}, tt.want...)
			sort.Slice(want, func(i, j int) bool { return want[i].entry < want[j].entry })
			if len(got) != len(want) {
				t.Fatalf("recorded %d authorization candidates, want %d: %+v", len(got), len(want), got)
			}
			for i := range got {
				if got[i] != want[i] {
					t.Errorf("candidate %d = %+v, want %+v", i, got[i], want[i])
				}
			}
		})
	}
}
