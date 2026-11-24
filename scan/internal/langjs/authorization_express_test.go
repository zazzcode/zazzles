package langjs

import (
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

type authzWant struct {
	entry     string
	subject   string
	operation string
	guards    string // comma-joined "kind/form" of the recorded guards
}

// TestExpressAuthorization covers D-3: one candidate per operation with a
// request-selected key; a guard when another key of the selector is scoped to
// the caller, and none otherwise; no record for a record selected through a
// server-side lookup or for a selector built only from constants.
func TestExpressAuthorization(t *testing.T) {
	for _, tt := range []struct {
		name string
		dir  string
		want []authzWant
	}{
		{"primary", "authorization-express/primary", []authzWant{
			{"PUT /invoices/:id", "model:Invoice", "update", ""},
			{"DELETE /invoices/:id", "model:Invoice", "delete", ""},
			{"POST /invoices/:id/bump", "model:Invoice", "update", ""},
			{"POST /invoices/:id/drop", "model:Invoice", "update", ""},
			{"PATCH /invoices/:id", "model:Invoice", "update", ""},
			{"DELETE /invoices/:id/row", "model:Invoice", "delete", ""},
			{"PUT /invoices/:id/save", "model:Invoice", "update", ""},
			{"PUT /mine/:id", "model:Invoice", "update", "ownership_check/query_scope"},
			{"PUT /claimed/:id", "model:Invoice", "update", "ownership_check/query_scope"},
			{"PUT /unclaimed/:id", "model:Invoice", "update", ""},
		}},
		{"transfer", "authorization-express/transfer", []authzWant{
			{"POST /memo/edit", "collection:memo", "update", ""},
			{"POST /memo/drop", "collection:memo", "delete", ""},
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
				if f.SubjectProvenance != analysis.SubjectRequestSelected || len(f.Facets) != 1 || f.Facets[0] != analysis.FacetObjectLevel {
					t.Fatalf("unexpected facts %+v", f)
				}
				if u.Components == nil || u.Components.Failure != "" {
					t.Fatalf("no component selection: %+v", u.Components)
				}
				for _, role := range []string{"subject_selection", "protected_operation", "entry_access", "control_flow"} {
					if len(u.Completeness.Evidence[role]) == 0 {
						t.Fatalf("missing evidence role %s", role)
					}
				}
				entry := ""
				for _, e := range report.Entries {
					if e.ID == u.EntryID {
						entry = e.Name
					}
				}
				var guards []string
				for _, g := range f.Guards {
					guards = append(guards, g.Kind+"/"+g.Form)
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
