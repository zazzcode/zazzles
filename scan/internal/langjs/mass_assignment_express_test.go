package langjs

import (
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

func massEntries(t *testing.T, dir string) (*analysis.AnalysisReport, map[string][]analysis.CandidateUse) {
	t.Helper()
	report, err := Analyze(filepath.Join("testdata", dir), "")
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]string{}
	for _, e := range report.Entries {
		names[e.ID] = e.Name
	}
	out := map[string][]analysis.CandidateUse{}
	for _, u := range report.Uses {
		if u.Kind == analysis.MassAssignmentKind {
			out[names[u.EntryID]] = append(out[names[u.EntryID]], u)
		}
	}
	return report, out
}

func checkMassUse(t *testing.T, u analysis.CandidateUse) {
	t.Helper()
	f := u.MassAssignment
	if f == nil {
		t.Fatal("mass assignment use without facts")
	}
	if err := f.Validate(); err != nil {
		t.Fatal(err)
	}
	if u.Components == nil || u.Components.Failure != "" {
		t.Fatalf("no component selection: %+v", u.Components)
	}
	for _, role := range []string{"input_source", "key_origin", "property_write", "target_class", "control_flow"} {
		if len(u.Completeness.Evidence[role]) == 0 {
			t.Fatalf("missing evidence role %s", role)
		}
	}
}

// TestExpressMassAssignment covers D-4: a whole request bag reaching a model
// write with no field list records a candidate; a fields option or an object
// literal of named properties records none.
func TestExpressMassAssignment(t *testing.T) {
	for _, tt := range []struct {
		name   string
		dir    string
		target string
		want   []string
		hints  []string
	}{
		{"primary", "mass-assignment-express/primary", "Profile", []string{
			"POST /p/create", "POST /p/build", "POST /p/bulk", "PUT /p/:id", "PATCH /p/:id", "PATCH /p/:id/set", "POST /p/assign", "POST /p/spread",
		}, []string{"role", "balance"}},
		{"transfer", "mass-assignment-express/transfer", "Member", []string{"POST /m/new", "POST /m/make", "PUT /m/:id", "PUT /m/:id/flat"}, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, got := massEntries(t, tt.dir)
			var names []string
			for name, uses := range got {
				names = append(names, name)
				for _, u := range uses {
					checkMassUse(t, u)
					f := u.MassAssignment
					if f.Shape != analysis.MassAssignmentPropertyWrite || f.TargetClass != tt.target || f.TargetStored != "yes" {
						t.Errorf("%s: unexpected facts %+v", name, f)
					}
					var hints []string
					for _, sf := range f.SecurityFields {
						for _, r := range sf.Roles {
							if r == analysis.RoleNameHint {
								hints = append(hints, strings.TrimPrefix(sf.StorageKey, "js-attribute:"+tt.target+"."))
							}
						}
					}
					sort.Strings(hints)
					want := append([]string{}, tt.hints...)
					sort.Strings(want)
					if strings.Join(hints, ",") != strings.Join(want, ",") {
						t.Errorf("%s: name hints %v, want %v", name, hints, want)
					}
				}
			}
			sort.Strings(names)
			want := append([]string{}, tt.want...)
			sort.Strings(want)
			if strings.Join(names, "|") != strings.Join(want, "|") {
				t.Fatalf("entries with a candidate:\n got %v\nwant %v", names, want)
			}
		})
	}
}

// TestExpressGeneratedResources covers D-5: a finale-rest resource in a loop
// over a literal array, one mass-assignment candidate per create and update
// endpoint and one authorization candidate per update and delete endpoint,
// with the access of the chain registered for that path. A computed model
// records a gap and no candidate. excludeAttributes limits reads only, so it
// is not a write guard.
func TestExpressGeneratedResources(t *testing.T) {
	report, mass := massEntries(t, "mass-assignment-express/resources")
	var names []string
	for name, uses := range mass {
		names = append(names, name)
		for _, u := range uses {
			checkMassUse(t, u)
			if len(u.MassAssignment.KeyGuards) != 0 {
				t.Errorf("%s: excludeAttributes recorded as a key guard", name)
			}
		}
	}
	sort.Strings(names)
	want := []string{"POST /api/Tags", "POST /api/Tickets", "PUT /api/Tags/:id", "PUT /api/Tickets/:id"}
	if strings.Join(names, "|") != strings.Join(want, "|") {
		t.Fatalf("mass-assignment entries:\n got %v\nwant %v", names, want)
	}
	for _, e := range report.Entries {
		if e.Name == "POST /api/Tickets" && e.Access != nil && e.Access.Authentication == analysis.AccessRequired {
			continue
		}
	}
	required := false
	for _, e := range report.Entries {
		if e.Name == "POST /api/Tickets" && e.Location.Span.StartLine == 20 && e.Access != nil && e.Access.Authentication == analysis.AccessRequired {
			required = true
		}
	}
	if !required {
		t.Error("the generated create of Ticket must carry the access of the chain registered for its path")
	}
	var authz []string
	for _, u := range report.Uses {
		if u.Kind != analysis.AuthorizationKind {
			continue
		}
		for _, e := range report.Entries {
			if e.ID == u.EntryID && u.Authorization.SubjectProvenance == analysis.SubjectRequestSelected {
				authz = append(authz, e.Name)
			}
		}
	}
	sort.Strings(authz)
	wantAuthz := []string{"DELETE /api/Tags/:id", "DELETE /api/Tickets/:id", "PUT /api/Tags/:id", "PUT /api/Tickets/:id"}
	if strings.Join(authz, "|") != strings.Join(wantAuthz, "|") {
		t.Fatalf("authorization entries:\n got %v\nwant %v", authz, wantAuthz)
	}
	gap := false
	for _, g := range report.Gaps {
		if g.Kind == "generated_resource_unresolved" && g.At.StartLine == 24 {
			gap = true
		}
	}
	if !gap {
		t.Error("a resource with a computed model must record gap generated_resource_unresolved")
	}
}
