package judge

import (
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
)

// SQL and NoSQL were re-recorded when fixed scanner facts became guidance-owned
// fact codes (W6); validation and XSS requests carry no coded fact and are unchanged.
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
				"sql/openai":        "487985b5394b8f9b1f13c787681dbb93c5f8dfc96e998a93d7ab096a3f0409f9",
				"sql/jev":           "4c53bd3f42190180b1545b5be7b800f3fffba0cc44e7db6f85cfedbb98451cf4",
				"nosql/openai":      "e4d62deca443f4534fb054701704c160b4a0c739d02598c28f2cc211cc89fec6",
				"nosql/jev":         "6c1afb05b1efd9434b88fcb3cf941e2a1f0b35a62988cb63c89cce17dc445131",
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
