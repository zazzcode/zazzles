package langphp

import (
	"encoding/json"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

// Recovery entropy: bits come from literal arguments and the modeled
// transforms, and a weak source stays unknown.
func TestRecoveryEntropy(t *testing.T) {
	r, _, _ := observeAccount(t, "testdata/symfony/account")
	for _, tt := range []struct {
		entry, bits, strength string
	}{
		{"POST /entropy/narrow", "3.1", analysis.SecretCSPRNG},
		{"POST /entropy/hex", "128", analysis.SecretCSPRNG},
		{"POST /entropy/slice", "32", analysis.SecretCSPRNG},
		{"POST /entropy/digest", "128", analysis.SecretCSPRNG},
		{"POST /entropy/uuid", "122", analysis.SecretCSPRNG},
		{"POST /entropy/weak", `"unknown"`, analysis.SecretWeak},
		{"POST /entropy/digest-slice", "24", analysis.SecretCSPRNG},
		{"POST /entropy/raw-digest-slice", `"unknown"`, analysis.SecretCSPRNG},
		{"POST /entropy/twice", "32", analysis.SecretCSPRNG},
	} {
		t.Run(tt.entry, func(t *testing.T) {
			uses := accountUses(r, analysis.RecoveryDeliveryKind, tt.entry)
			if len(uses) != 1 {
				t.Fatalf("%d records, want 1:\n%s", len(uses), accountSummary(r, analysis.RecoveryDeliveryKind))
			}
			f := uses[0].Recovery
			if f.SecretStrength != tt.strength {
				t.Fatalf("strength %s, want %s", f.SecretStrength, tt.strength)
			}
			raw, err := json.Marshal(f.SecretBits)
			if err != nil {
				t.Fatal(err)
			}
			if string(raw) != tt.bits {
				t.Fatalf("secret_bits %s, want %s", raw, tt.bits)
			}
		})
	}
}
