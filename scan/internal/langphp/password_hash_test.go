package langphp

import (
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

// Password-hashing cases: each password basis and the digests never recorded.
func TestPasswordHash(t *testing.T) {
	type want struct {
		file, algorithm, basis, salted, hasher, gap string
		line                                        int
	}
	reports := fixtureReports{}
	for _, tt := range []struct {
		id, root string
		want     []want
		none     []string // entries with no record
	}{
		{"PH-01", "testdata/symfony/account", []want{{"src/Controller/ProfileController.php", "md5", analysis.BasisCredentialField, "no", "", "", 20}}, nil},
		{"PH-02", "testdata/symfony/account", []want{{"src/Controller/ProfileController.php", "sha1", analysis.BasisCredentialField, "yes", "", "", 31}}, nil},
		{"PH-03", "testdata/symfony/account", []want{{"src/Controller/ProfileController.php", "sha256", analysis.BasisCredentialField, "no", "", "", 40}}, nil},
		{"PH-04", "testdata/symfony/account", []want{{"src/Security/LegacyDigest.php", "md5", analysis.BasisHasherClass, "no", `App\Security\LegacyDigest`, "", 10}}, nil},
		{"PH-05", "testdata/symfony/account", []want{{"config/packages/security.yaml", "sha1", analysis.BasisConfiguration, "no", "", "", 3}}, nil},
		{"PH-06", "testdata/symfony/account", []want{{"config/packages/security.yaml", "md5", analysis.BasisConfiguration, "no", `App\Security\LegacyDigest`, "", 6}}, nil},
		{"PH-07", "testdata/symfony/account", nil, []string{"POST /profile/adaptive"}},
		{"PH-08", "testdata/symfony/account", nil, []string{"POST /profile/operator"}},
		{"PH-09", "testdata/symfony/account", nil, []string{"POST /profile/names"}},
		{"PH-10", "testdata/symfony/account-transfer", []want{{"src/Crypto/ShaHasher.php", "sha1", analysis.BasisHasherClass, "no", `App\Crypto\ShaHasher`, "", 10},
			{"config/packages/security.yaml", "sha1", analysis.BasisConfiguration, "no", `App\Crypto\ShaHasher`, "", 4}}, nil},
		{"PH-11", "testdata/account-plain", []want{{"register.php", "md5", analysis.BasisSQLCredentialColumn, "no", "", "", 4}}, []string{"FILE /signin.php"}},
		{"PH-12", "testdata/symfony/account", []want{{"src/Controller/ProfileController.php", "crypt", analysis.BasisCredentialField, "no", "", analysis.PasswordDigestUnmodeled, 80}}, nil},
		{"PH-13", "testdata/symfony/account-defaults", []want{{"src/Security/QuickDigest.php", "md5", analysis.BasisHasherClass, "no", `App\Security\QuickDigest`, "", 10},
			{"config/packages/security.yaml", "md5", analysis.BasisConfiguration, "no", "", "", 3},
			{"config/packages/security.yaml", "md5", analysis.BasisConfiguration, "no", `App\Security\QuickDigest`, "", 5}}, nil},
		{"PH-14", "testdata/account-plain-variable", []want{{"change.php", "md5", analysis.BasisSQLCredentialColumn, "no", "", "", 4}}, []string{"FILE /signin.php"}},
	} {
		t.Run(tt.id, func(t *testing.T) {
			r := reports.get(t, tt.root)
			all := accountUses(r, analysis.PasswordHashKind, "")
			for _, entry := range tt.none {
				if n := len(accountUses(r, analysis.PasswordHashKind, entry)); n != 0 {
					t.Fatalf("%s has %d records:\n%s", entry, n, accountSummary(r, analysis.PasswordHashKind))
				}
			}
			for _, w := range tt.want {
				var got *analysis.CandidateUse
				for i := range all {
					if all[i].Sink.Span.File == w.file && all[i].Sink.Span.StartLine == w.line {
						got = &all[i]
					}
				}
				if got == nil {
					t.Fatalf("no record at %s:%d:\n%s", w.file, w.line, accountSummary(r, analysis.PasswordHashKind))
				}
				f := got.PasswordHash
				if f.Algorithm != w.algorithm || f.Basis != w.basis || f.Salted != w.salted || f.Iterated != "no" || f.HasherClass != w.hasher {
					t.Fatalf("facts %+v", f)
				}
				if err := f.Validate(); err != nil {
					t.Fatal(err)
				}
				blockers := strings.Join(blockerKinds(*got), ",")
				if w.gap == "" && blockers != "" || w.gap != "" && !strings.Contains(blockers, w.gap) {
					t.Fatalf("blockers %q, want %q", blockers, w.gap)
				}
				if got.APIModel == nil || got.APIModel.ID != "php-password-digest-v1" {
					t.Fatalf("contract %+v", got.APIModel)
				}
			}
		})
	}
	t.Run("only the listed records", func(t *testing.T) {
		r := reports.get(t, "testdata/symfony/account")
		if n := len(accountUses(r, analysis.PasswordHashKind, "")); n != 7 {
			t.Fatalf("%d records, want 7:\n%s", n, accountSummary(r, analysis.PasswordHashKind))
		}
	})
}
