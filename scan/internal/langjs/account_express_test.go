package langjs

import (
	"path/filepath"
	"sort"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

type hashWant struct {
	file, algorithm, basis string
	line                   int
}

// TestExpressPasswordHash covers D-7 weak password hashing: a fast digest whose
// result a model accessor stores or a SQL statement compares, followed through
// one helper. A strong hash, and a digest that reaches no credential, record
// nothing.
func TestExpressPasswordHash(t *testing.T) {
	for _, tt := range []struct {
		name string
		dir  string
		want []hashWant
	}{
		{"primary", "account-express/primary", []hashWant{
			{"digests.ts", "md5", analysis.BasisCredentialField, 4},
			{"digests.ts", "sha256", analysis.BasisSQLCredentialColumn, 6},
		}},
		{"transfer", "account-express/transfer", []hashWant{
			{"store.js", "sha1", analysis.BasisCredentialField, 4},
			{"store.js", "sha256", analysis.BasisCredentialField, 11},
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			report, err := Analyze(filepath.Join("testdata", tt.dir), "")
			if err != nil {
				t.Fatal(err)
			}
			var got []hashWant
			for _, u := range report.Uses {
				if u.Kind != analysis.PasswordHashKind {
					continue
				}
				f := u.PasswordHash
				if f == nil {
					t.Fatal("password hash use without facts")
				}
				if err := f.Validate(); err != nil {
					t.Fatal(err)
				}
				if u.Components == nil || u.Components.Failure != "" {
					t.Fatalf("no component selection: %+v", u.Components)
				}
				for _, role := range []string{"digest_operation", "password_basis", "sink_binding"} {
					if len(u.Completeness.Evidence[role]) == 0 {
						t.Fatalf("missing evidence role %s", role)
					}
				}
				got = append(got, hashWant{u.Sink.Span.File, f.Algorithm, f.Basis, u.Sink.Span.StartLine})
			}
			sort.Slice(got, func(i, j int) bool { return got[i].line < got[j].line })
			if len(got) != len(tt.want) {
				t.Fatalf("recorded %d password hash candidates, want %d: %+v", len(got), len(tt.want), got)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("candidate %d = %+v, want %+v", i, got[i], tt.want[i])
				}
			}
		})
	}
}

type enumWant struct {
	file  string
	line  int
	entry string
}

// TestExpressAccountEnumeration covers D-7 account enumeration: a lookup by a
// request value on an entry with no authentication whose branches answer
// differently. Same responses, an authenticated entry and a login record
// nothing.
func TestExpressAccountEnumeration(t *testing.T) {
	for _, tt := range []struct {
		name string
		dir  string
		want []enumWant
	}{
		{"primary", "account-express/primary", []enumWant{{"lookups.ts", 13, "GET /ticket-owner"}}},
		{"transfer", "account-express/transfer", []enumWant{{"app.js", 13, "GET /exists"}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			report, err := Analyze(filepath.Join("testdata", tt.dir), "")
			if err != nil {
				t.Fatal(err)
			}
			var got []enumWant
			for _, u := range report.Uses {
				if u.Kind != analysis.AccountEnumerationKind {
					continue
				}
				if u.Enumeration == nil {
					t.Fatal("enumeration use without facts")
				}
				if err := u.Enumeration.Validate(); err != nil {
					t.Fatal(err)
				}
				if u.Components == nil || u.Components.Failure != "" {
					t.Fatalf("no component selection: %+v", u.Components)
				}
				for _, role := range []string{"input_source", "account_lookup", "result_branch", "entry_access"} {
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
				got = append(got, enumWant{u.Sink.Span.File, u.Sink.Span.StartLine, entry})
			}
			if len(got) != len(tt.want) {
				t.Fatalf("recorded %d enumeration candidates, want %d: %+v", len(got), len(tt.want), got)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("candidate %d = %+v, want %+v", i, got[i], tt.want[i])
				}
			}
		})
	}
}
