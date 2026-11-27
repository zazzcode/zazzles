package langjs

import (
	"sort"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

// roleMap returns "field" -> roles of one record's census.
func roleMap(u analysis.CandidateUse) map[string]string {
	out := map[string]string{}
	for _, f := range u.MassAssignment.SecurityFields {
		out[f.StorageKey[strings.LastIndex(f.StorageKey, ".")+1:]] = strings.Join(f.Roles, ",")
	}
	return out
}

func oneMass(t *testing.T, got map[string][]analysis.CandidateUse, entry string) analysis.CandidateUse {
	t.Helper()
	uses := got[entry]
	if len(uses) != 1 {
		t.Fatalf("%s: %d mass-assignment records, want 1", entry, len(uses))
	}
	checkMassUse(t, uses[0])
	return uses[0]
}

// TestOwnerReference covers S-1: the foreign key of a declared association to
// an account model carries owner_reference, with the association as evidence.
func TestOwnerReference(t *testing.T) {
	_, seq := massEntries(t, "mass-assignment/owner/sequelize")
	_, mongo := massEntries(t, "mass-assignment/owner/mongoose")
	for _, tt := range []struct {
		name  string
		got   map[string][]analysis.CandidateUse
		entry string
		field string
		roles string // roles of field; "" means the field has no census entry
	}{
		{"belongs_to_default_key", seq, "POST /ships", "captainId", "owner_reference"},
		{"foreign_key_literal", seq, "POST /crates", "ownerId", "name_hint,owner_reference"},
		{"foreign_key_name_object", seq, "POST /barrels", "accountId", "owner_reference"},
		{"as_replaces_target_name", seq, "POST /flags", "skipperId", "owner_reference"},
		{"mongoose_ref", mongo, "POST /notes", "author", "owner_reference"},
		{"mongoose_ref_new", mongo, "POST /notes/new", "author", "owner_reference"},
		{"no_credential_model", seq, "POST /buoys", "portId", ""},
		{"mongoose_no_credential_model", mongo, "POST /tags", "place", ""},
		{"name_hint_without_association", seq, "POST /charts", "userId", "name_hint"},
		{"non_literal_foreign_key", seq, "POST /ropes", "holderId", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			u := oneMass(t, tt.got, tt.entry)
			if got := roleMap(u)[tt.field]; got != tt.roles {
				t.Fatalf("%s roles %q, want %q (census %v)", tt.field, got, tt.roles, roleMap(u))
			}
			for _, f := range u.MassAssignment.SecurityFields {
				if len(f.Evidence) != len(f.Roles) {
					t.Errorf("%s: %d evidence items for %d roles", f.StorageKey, len(f.Evidence), len(f.Roles))
				}
				for i, r := range f.Roles {
					if r == analysis.RoleOwnerReference && f.Evidence[i].Kind != "owner_association" {
						t.Errorf("%s: owner_reference evidence kind %q", f.StorageKey, f.Evidence[i].Kind)
					}
				}
			}
			unresolved := false
			for _, g := range u.Gaps {
				unresolved = unresolved || g.Kind == analysis.OwnerReferenceUnresolved
			}
			if want := tt.name == "non_literal_foreign_key"; unresolved != want {
				t.Errorf("owner_reference_unresolved gap %v, want %v", unresolved, want)
			}
		})
	}
}

// TestMassOverwrittenHandwritten covers S-2: attributes that a registered
// stage or the handler assigns on its straight-line path before a handwritten
// whole-body write are left out with chain_overwrite evidence.
func TestMassOverwrittenHandwritten(t *testing.T) {
	_, got := massEntries(t, "mass-assignment/owner/overwrite")
	for _, tt := range []struct {
		entry string
		left  bool // captainId stays among the mapped fields and carries the role
	}{
		{"POST /ships", false},
		{"POST /crates", false},
		{"POST /barrels", false},
		{"POST /kegs", true},
		{"POST /sacks", true},
	} {
		t.Run(strings.TrimPrefix(tt.entry, "POST /"), func(t *testing.T) {
			u := oneMass(t, got, tt.entry)
			mapped := strings.Join(u.MassAssignment.MappedFields, ",")
			hasRole := roleMap(u)["captainId"] == "owner_reference"
			var overwrites int
			for _, ev := range u.Completeness.Evidence["control_flow"] {
				if ev.Kind == "chain_overwrite" {
					overwrites++
				}
			}
			if tt.left {
				if !strings.Contains(mapped, "captainId") || !hasRole || overwrites != 0 {
					t.Fatalf("captainId must stay in: mapped %q role %v overwrites %d", mapped, hasRole, overwrites)
				}
				return
			}
			if strings.Contains(mapped, "captainId") || hasRole || overwrites != 1 {
				t.Fatalf("captainId must be left out: mapped %q role %v overwrites %d", mapped, hasRole, overwrites)
			}
			if !strings.Contains(u.Completeness.Evidence["input_source"][0].ModelText, "overwrites some request fields") {
				t.Errorf("missing overwrite note: %q", u.Completeness.Evidence["input_source"][0].ModelText)
			}
		})
	}
	var names []string
	for name := range got {
		names = append(names, name)
	}
	sort.Strings(names)
	if len(names) != 5 {
		t.Errorf("records for %v", names)
	}
}
