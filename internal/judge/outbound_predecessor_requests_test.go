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
				"sql/openai":        "7a300eb2c03a3f8aafe938021ecbd67fa2f31cebd577de9593fbfe0c55474b3b",
				"sql/jev":           "f0bde8a39adae7ad273a5e8e3e48d33111684ee356a49caa8b572aadd2b941f2",
				"nosql/openai":      "c140c28a363f77d83f290a1e341f986430abc029a65ee9451dead18131da8b94",
				"nosql/jev":         "07d9901363d870c7db6db3fa43aa798016a2422552a101659ce7523cc77b9d7c",
				"validation/openai": "179c3c875bd0ce4d6a344a063254cce6b3222be2226e83c441be676f83ce3684",
				"validation/jev":    "130289061e1ca2efd3163eb79e30ac57890750514e342d789e986c1700d66736",
				"xss/openai":        "03cf9c3473fe14ffd06de73e018430817b04c0e6ab1cefb73367737dfae4245c",
				"xss/jev":           "4a4ebf2e0bf8380defbca3e86a6c75b71c3911794ea57d6c2768778329fb1008",
			}[family+"/"+provider]
			if got := fmt.Sprintf("%x", sha256.Sum256(p)); got != want {
				t.Fatalf("%s/%s request bytes changed: %s", family, provider, got)
			}
		}
	}
}
