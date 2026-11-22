package langphp

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
)

// Expected anchors are computed by hand from the mass-assignment fixtures.
func TestMassAssignment(t *testing.T) {
	first := filepath.Join("testdata", "symfony", "mass-assignment")
	transfer := filepath.Join("testdata", "symfony", "mass-assignment-transfer")
	plain := filepath.Join("testdata", "mass-assignment-plain")
	const (
		account    = "src/Entity/Account.php"
		controller = "src/Controller/AccountController.php"
		profile    = "src/Controller/ProfileController.php"
		target     = `App\Entity\Account`
	)
	accountRoles := map[string]string{
		"php-sql:account.login":  analysis.RoleLoginIdentifier,
		"php-sql:account.secret": analysis.RoleCredential,
		"php-sql:account.grants": analysis.RoleSource,
	}
	type massCase struct {
		id, root, entry string
		record          bool
		sink            string
		line            int
		sourceLine      int
		shape, class    string
		stored          string
		guards          []string
		gap             string
		roles           map[string]string
	}
	cases := []massCase{
		{"MA-01", first, "POST /account/{account}/edit", true, account, 29, 19, analysis.MassAssignmentPropertyWrite, target, "yes", nil, "", accountRoles},
		{"MA-02", first, "POST /account/import", true, controller, 28, 27, analysis.MassAssignmentPropertyWrite, target, "yes", nil, "", accountRoles},
		{"MA-03", first, "POST /account/{account}/setters", true, controller, 37, 36, analysis.MassAssignmentSetterCall, target, "yes", nil, "", accountRoles},
		{"MA-04", first, "POST /account/{account}/accessor", true, controller, 46, 45, analysis.MassAssignmentAccessor, target, "yes", nil, "", accountRoles},
		{"MA-05", first, "POST /account/{account}/limited", true, account, 29, 54, analysis.MassAssignmentPropertyWrite, target, "yes", []string{analysis.KeyAllowList}, "", accountRoles},
		{"MA-06", first, "POST /account/{account}/known", true, account, 37, 62, analysis.MassAssignmentPropertyWrite, target, "yes", []string{analysis.KeyExistenceCheck}, "", accountRoles},
		{"MA-07", first, "POST /account/{account}/named", false, "", 0, 0, "", "", "", nil, "", nil},
		{"MA-08", first, "POST /account/{account}/literal", false, "", 0, 0, "", "", "", nil, "", nil},
		{"MA-09", first, "POST /account/{account}/defaults", false, "", 0, 0, "", "", "", nil, "", nil},
		{"MA-10", first, "POST /account/{account}/form", true, controller, 95, 95, analysis.MassAssignmentForm, target, "yes", nil, analysis.MassAssignmentFormUnmodeled, accountRoles},
		{"MA-11", first, "POST /account/decode", true, controller, 102, 102, analysis.MassAssignmentSerializer, target, "yes", nil, analysis.MassAssignmentSerializerUnmodeled, accountRoles},
		{"MA-12", first, "POST /draft", true, controller, 111, 110, analysis.MassAssignmentPropertyWrite, `App\Model\Draft`, "no", nil, "", map[string]string{}},
		{"MA-13", transfer, "PUT /profile/{member}/apply", true, profile, 18, 16, analysis.MassAssignmentSetterCall, `App\Entity\Member`, "yes", nil, "", map[string]string{
			"php-sql:member.staff_level": analysis.RoleSource, "php-sql:member.nickname": analysis.RoleLoginIdentifier}},
		{"MA-14", transfer, "PUT /profile/{member}/motto", false, "", 0, 0, "", "", "", nil, "", nil},
		{"MA-15", plain, "FILE /profile.php", true, "profile.php", 6, 5, analysis.MassAssignmentPropertyWrite, "Profile", "unresolved", nil, analysis.SecurityFieldsUnresolved, map[string]string{
			"php-object:Profile.role": analysis.RoleNameHint, "php-object:Profile.password": analysis.RoleNameHint}},
		{"MA-16", plain, "FILE /rename.php", false, "", 0, 0, "", "", "", nil, "", nil},
	}
	reports := map[string]*analysis.AnalysisReport{}
	for _, root := range []string{first, transfer, plain} {
		r, err := Analyze(root, "")
		if err != nil {
			t.Fatal(err)
		}
		reports[root] = r
	}
	want := map[string]int{}
	for _, tt := range cases {
		if tt.record {
			want[tt.root]++
		}
	}
	for root, r := range reports {
		got := 0
		for _, u := range r.Uses {
			if u.Kind == analysis.MassAssignmentKind {
				got++
			}
		}
		if got != want[root] {
			t.Errorf("%s: %d mass-assignment candidates, want %d", root, got, want[root])
		}
	}
	for _, tt := range cases {
		t.Run(tt.id, func(t *testing.T) {
			r := reports[tt.root]
			names := map[string]string{}
			for _, e := range r.Entries {
				names[e.ID] = e.Name
			}
			if !slices.Contains(mapValues(names), tt.entry) {
				t.Fatalf("entry %s not discovered", tt.entry)
			}
			var found []analysis.CandidateUse
			for _, u := range r.Uses {
				if u.Kind == analysis.MassAssignmentKind && names[u.EntryID] == tt.entry {
					found = append(found, u)
				}
			}
			if !tt.record {
				if len(found) != 0 {
					t.Fatalf("unexpected candidate at %s:%d", found[0].Sink.Span.File, found[0].Sink.Span.StartLine)
				}
				return
			}
			if len(found) != 1 {
				t.Fatalf("%d candidates under %s, want 1", len(found), tt.entry)
			}
			u := found[0]
			x := u.MassAssignment
			if u.Sink.Span.File != tt.sink || u.Sink.Span.StartLine != tt.line {
				t.Fatalf("sink %s:%d, want %s:%d", u.Sink.Span.File, u.Sink.Span.StartLine, tt.sink, tt.line)
			}
			if x == nil {
				t.Fatal("missing mass-assignment facts")
			}
			if err := x.Validate(); err != nil {
				t.Fatal(err)
			}
			if x.Shape != tt.shape || x.TargetClass != tt.class || x.TargetStored != tt.stored {
				t.Fatalf("facts %+v", *x)
			}
			var kinds []string
			for _, g := range x.KeyGuards {
				kinds = append(kinds, g.Kind)
			}
			if !slices.Equal(kinds, tt.guards) {
				t.Fatalf("key guards %v, want %v", kinds, tt.guards)
			}
			if tt.id == "MA-05" && !strings.Contains(x.KeyGuards[0].Text, "'name', 'bio'") {
				t.Fatalf("allow-list evidence %q lacks the literal list", x.KeyGuards[0].Text)
			}
			roles := map[string]string{}
			for _, f := range x.SecurityFields {
				roles[f.StorageKey] = strings.Join(f.Roles, ",")
			}
			if len(roles) != len(tt.roles) {
				t.Fatalf("security fields %v, want %v", roles, tt.roles)
			}
			for key, role := range tt.roles {
				if roles[key] != role {
					t.Fatalf("security fields %v, want %v", roles, tt.roles)
				}
			}
			witness := false
			for _, d := range u.Dependencies {
				if d.Source.Kind == "input_source" && d.Source.Span.StartLine == tt.sourceLine {
					witness = true
				}
			}
			if !witness {
				t.Fatalf("no request source at line %d: %+v", tt.sourceLine, u.Dependencies)
			}
			c := u.Completeness
			if c == nil || c.ClaimKind != "mass_assignment" {
				t.Fatal("missing completeness")
			}
			if tt.gap == "" || tt.gap == analysis.SecurityFieldsUnresolved {
				for _, role := range analysispacks.MassAssignmentRoles() {
					if len(c.Evidence[role]) == 0 {
						t.Fatalf("missing evidence role %s", role)
					}
				}
			}
			gaps := map[string]bool{}
			for _, g := range append(append(append([]analysis.Gap{}, u.Gaps...), c.Blockers...), c.Coverage...) {
				gaps[g.Kind] = true
			}
			if tt.gap != "" && !gaps[tt.gap] {
				t.Fatalf("gaps %v lack %s", gaps, tt.gap)
			}
			for _, framework := range []string{analysis.MassAssignmentFormUnmodeled, analysis.MassAssignmentSerializerUnmodeled, analysis.MassAssignmentPayloadUnmodeled} {
				if framework != tt.gap && gaps[framework] {
					t.Fatalf("unexpected gap %s", framework)
				}
			}
			if u.Components == nil || u.Components.Failure != "" {
				t.Fatalf("component selection %+v", u.Components)
			}
		})
	}
}

func mapValues(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	return out
}
