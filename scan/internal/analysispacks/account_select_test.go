package analysispacks

import (
	"reflect"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

func accountUse(kind, file, contract string) analysis.CandidateUse {
	u := analysis.CandidateUse{Kind: kind, EntryKind: "http", Sink: analysis.Evidence{Span: analysis.Span{File: file}},
		Completeness: &analysis.Completeness{ClaimKind: "account", Evidence: map[string][]analysis.Evidence{"sink_binding": {{Kind: "sink_binding"}}}}}
	if contract != "" {
		u.APIModel = AccountContract(contract)
	}
	return u
}

// The account family selects per kind: its own pack, an optional operation
// contract, and the question subset of the kind.
func TestAccountFamilySelect(t *testing.T) {
	family := FamilyForName("account")
	if family == nil || !ValidCLIFamily("account") {
		t.Fatal("account family is not registered")
	}
	for _, id := range []string{SymfonyMailerContract, PHPMailContract, PHPPasswordDigest} {
		if m := AccountContract(id); m == nil || m.Semantics == "" || m.Reference == "" {
			t.Fatalf("contract %s lacks semantics or reference", id)
		}
	}
	for _, tt := range []struct {
		use       analysis.CandidateUse
		questions []string
		contract  string
	}{
		{accountUse(analysis.AccountEnumerationKind, "src/Controller/JoinController.php", ""), []string{"response_difference", "existence_disclosure"}, ""},
		{accountUse(analysis.RecoveryDeliveryKind, "src/Service/Notifier.php", SymfonyMailerContract), []string{"recipient_control", "validation_coverage", "secret_quality"}, "api." + SymfonyMailerContract},
		{accountUse(analysis.RecoveryDeliveryKind, "forgot.php", PHPMailContract), []string{"recipient_control", "validation_coverage", "secret_quality"}, "api." + PHPMailContract},
		{accountUse(analysis.PasswordHashKind, "src/Security/ShaHasher.php", PHPPasswordDigest), []string{"password_input", "hash_strength"}, "api." + PHPPasswordDigest},
		{accountUse(analysis.PasswordHashKind, "config/packages/security.yaml", PHPPasswordDigest), []string{"password_input", "hash_strength"}, "api." + PHPPasswordDigest},
	} {
		s, err := Select(tt.use)
		if err != nil {
			t.Fatalf("%s %s: %v", tt.use.Kind, tt.use.Sink.Span.File, err)
		}
		if s.Pack.ID != "pack.account" || ProtocolFor(tt.use.Kind) != AccountProtocol {
			t.Fatalf("selection %+v", s)
		}
		hasContract := false
		for _, c := range s.Components {
			if c.ID == tt.contract {
				hasContract = true
			}
		}
		if (tt.contract != "") != hasContract {
			t.Fatalf("%s contract selection %+v", tt.use.Kind, s.Components)
		}
		tt.use.Components = s
		m, err := ForUse(tt.use)
		if err != nil {
			t.Fatalf("material %s: %v", tt.use.Kind, err)
		}
		var names []string
		for _, q := range m.Questions {
			names = append(names, q.Name)
			if len(m.Choices[q.Name]) == 0 {
				t.Fatalf("question %s has no choices", q.Name)
			}
		}
		if !reflect.DeepEqual(names, tt.questions) {
			t.Fatalf("%s questions %v, want %v", tt.use.Kind, names, tt.questions)
		}
	}
	// An enumeration record never carries a contract outside the mail and digest contracts.
	bad := accountUse(analysis.AccountEnumerationKind, "a.php", "")
	bad.APIModel = &analysis.APIModel{ID: "php-account-lookup-v1", Library: "php"}
	if _, err := Select(bad); err == nil {
		t.Fatal("unregistered account contract was accepted")
	}
}
