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
				"sql/openai":        "cc5d9438867c14316df7bbb2ac441e4143e107b90fe0a9e155e4c4ab54f36fa0",
				"sql/jev":           "5a239fd5268db1cf0dd284ce72094d725298e866148140c2efa059472e575d7b",
				"nosql/openai":      "45dacb566a83935984190704101dca2e3bebb8d83e76b68e4c684b436d441a6d",
				"nosql/jev":         "86b33c964d607de01da80bf6df286df3e563ca5546521ccb813fa9e8d0aaedaa",
				"validation/openai": "8d697510453a70d924951b4c0fd932becdc6655b52de605ffaed6230bb609fdb",
				"validation/jev":    "5e8f4916be5915ece2bf01a309f8becd20974f4dc45ebe405298030cddeb4f7c",
				"xss/openai":        "cb98157b641e7101d0000ad6c8554c18ae475050d78e0a20dac7907862f73f59",
				"xss/jev":           "b0fa1f76e006cfaa5c20038ce878760d2b0d4d1078c22c4b938edb3788d08f63",
			}[family+"/"+provider]
			if got := fmt.Sprintf("%x", sha256.Sum256(p)); got != want {
				t.Fatalf("%s/%s request bytes changed: %s", family, provider, got)
			}
		}
	}
}
