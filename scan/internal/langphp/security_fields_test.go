package langphp

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

// Expected anchors are computed by hand from the security-fields fixture.
func TestSecurityFields(t *testing.T) {
	root := filepath.Join("testdata", "symfony", "security-fields")
	s, err := newPHPSet(root)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	if len(s.symfony) != 1 {
		t.Fatalf("%d Symfony projects", len(s.symfony))
	}
	p := s.symfony[0]
	census := s.securityFields(p)
	type role struct {
		role, file string
		line       int
	}
	cases := []struct {
		id, key string
		roles   []role
	}{
		{"SF-01", "php-sql:account.secret_hash", []role{{analysis.RoleCredential, "src/Entity/Account.php", 30}}},
		{"SF-02", "php-sql:account.handle", []role{{analysis.RoleLoginIdentifier, "config/packages/security.yaml", 6}}},
		{"SF-03", "php-sql:member.mail", []role{{analysis.RoleLoginIdentifier, "src/Entity/Member.php", 18}}},
		{"SF-04", "php-sql:account.grants", []role{{analysis.RoleSource, "src/Entity/Account.php", 40}}},
		{"SF-05", "php-sql:account.staff_level", []role{{analysis.RoleSource, "src/Entity/Account.php", 48}}},
		{"SF-06", "php-sql:member.tier", []role{{analysis.RoleSource, "src/Entity/Member.php", 23}}},
		{"SF-07", "php-sql:product.owner_id", []role{{analysis.RoleNameHint, "src/Entity/Product.php", 13}}},
		{"SF-09", "php-sql:vault.digest", []role{{analysis.RoleCredential, "src/Controller/VaultController.php", 16}}},
	}
	want := map[string]bool{"php-sql:partner.code": true}
	for _, tt := range cases {
		want[tt.key] = true
		t.Run(tt.id, func(t *testing.T) {
			field, ok := census[tt.key]
			if !ok {
				t.Fatalf("no census entry for %s; census %v", tt.key, census)
			}
			if len(field.roles) != len(tt.roles) || len(field.evidence) != len(field.roles) {
				t.Fatalf("roles %v evidence %d, want %v", field.roles, len(field.evidence), tt.roles)
			}
			for i, r := range tt.roles {
				e := field.evidence[i]
				if field.roles[i] != r.role || e.Span.File != r.file || e.Span.StartLine != r.line {
					t.Fatalf("role %s at %s:%d, want %s at %s:%d", field.roles[i], e.Span.File, e.Span.StartLine, r.role, r.file, r.line)
				}
			}
		})
	}
	t.Run("SF-07 price has no role", func(t *testing.T) {
		if _, ok := census["php-sql:product.price"]; ok {
			t.Fatal("price has a census role")
		}
	})
	t.Run("no other fields", func(t *testing.T) {
		for key := range census {
			if !want[key] {
				t.Errorf("unexpected census entry %s %v", key, census[key].roles)
			}
		}
	})
	t.Run("SF-08", func(t *testing.T) {
		gaps := s.securityGaps(p)
		if len(gaps) != 1 || gaps[0].Kind != analysis.SecurityFieldsUnresolved || gaps[0].At.File != "src/Entity/Partner.php" || gaps[0].At.StartLine != 21 {
			t.Fatalf("gaps %v", gaps)
		}
		if roles := census["php-sql:partner.code"].roles; strings.Join(roles, ",") != analysis.RoleLoginIdentifier {
			t.Fatalf("partner.code roles %v", roles)
		}
	})
	t.Run("deterministic", func(t *testing.T) {
		again, err := newPHPSet(root)
		if err != nil {
			t.Fatal(err)
		}
		defer again.close()
		if !reflect.DeepEqual(again.securityFields(again.symfony[0]), census) || !reflect.DeepEqual(s.securityFields(p), census) {
			t.Fatal("census differs between calls")
		}
	})
}
