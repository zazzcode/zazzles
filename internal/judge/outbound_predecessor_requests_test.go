package judge

import (
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
)

func TestOutboundPredecessorRequests(t *testing.T) {
	_, xss := parsedXSS(t, map[string]string{"client.js": `document.body.innerHTML=location.hash`})
	uses := map[string]analysis.CandidateUse{"sql": selectedSQLUse(t), "nosql": selectedNoSQLUse(t), "validation": selectedValidationUse(t), "xss": xss}
	for family, u := range uses {
		u = predecessorNodeUse(u)
		for _, provider := range []string{"openai", "jev"} {
			c, _ := New(provider, "fixture-model", "key")
			p, err := c.payload(u)
			if err != nil {
				t.Fatal(err)
			}
			want := map[string]string{
				"sql/openai":        "63b82d25814d6b4042c3458d39d2157101f77bd8ceae7d742783e8c1b157460d",
				"sql/jev":           "f81a71325d91b097298d6a5105f212129261524de848ed53ec99f9feaea1f9ac",
				"nosql/openai":      "7e4b4543a716f04a71184afb0bfe0c094134ae184c0a2e214ebb10f0d1738382",
				"nosql/jev":         "e936284fd52ad16eb2197adf0ea79d1b7e58e1f1a44ae1138dea57baf7c45107",
				"validation/openai": "eb9a101c64059673445447b39a43707f6edc158c238f1a6eed9b0c3a15e7ee3a",
				"validation/jev":    "2d71889f6cb884563022d98d13f8512639a656161fa5ed0233e865e63f804727",
				"xss/openai":        "5c1d0a056d4c55b9a47f4a88e1aa3bfb8753475508c84c5d4c6a574e769b8aa5",
				"xss/jev":           "d0ce5f2d9b295938f7816645e050bdb1d46caaf24b2862ea7ce1e04eade4ceda",
			}[family+"/"+provider]
			if got := fmt.Sprintf("%x", sha256.Sum256(p)); got != want {
				t.Fatalf("%s/%s request bytes changed: %s", family, provider, got)
			}
		}
	}
}
