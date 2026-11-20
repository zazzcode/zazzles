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
				"sql/openai":        "c9e59f38716b4b550e54085890b3433f7234ffc1c87930926980055f182efdc6",
				"sql/jev":           "233c2739e43d10c9879902f7612b03f663fd59d5121f1b3ad2135ec696c5a98c",
				"nosql/openai":      "f6d1f8d414ad287d1e8d84b8f0fd9b302fd198f0550fade74f9d84c41dd81863",
				"nosql/jev":         "e9175cacd0439ed2442e45fd2d8f1f551ddbfafda254774ecc08bc3da7dfbe85",
				"validation/openai": "a0e68b91fa1130def02f353557585831f8f01f72943375a4da6f43220c957ab8",
				"validation/jev":    "3ae363a467e936e8bc8ee839e643cee1ddd55026ddcf28404da6bc2bdf7fb133",
				"xss/openai":        "a51c6f991aa48a629d9d619632a26af6b52af512fa4de66bcb11d1a4d8cc2316",
				"xss/jev":           "c8f081996879795ce9aa1975e3adebd8fdecb09163a9e88f2f7c582a54f10943",
			}[family+"/"+provider]
			if got := fmt.Sprintf("%x", sha256.Sum256(p)); got != want {
				t.Fatalf("%s/%s request bytes changed: %s", family, provider, got)
			}
		}
	}
}
