package judge

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"testing"

	"github.com/zazzcode/zazzles/internal/parse"
)

// TestCommandPredecessorRequests freezes the effective decision-request bytes
// of every existing family on current parsed fixtures. The digests were
// recorded from the pre-command commit e12873c; command candidates are a new
// family and are excluded from the comparison.
func TestCommandPredecessorRequests(t *testing.T) {
	type baseline struct {
		count  int
		digest string
	}
	want := map[string]baseline{
		"string-flow":                 {1, "6f9b69d1d97fc527823f4fbc55e28b09f1c46ae489bc6fcd34eebd06329758b6"},
		"javascript/grpc":             {7, "88a94875ce7eb996d9fc55a25b1130bf94e142624e7f0b99b68a6cb54e7a6318"},
		"typescript/grpc":             {7, "7db64bd3d2e9db24f0364638bbf40602a4d669c49402fdc43adf9eaaeaf1046f"},
		"javascript/graphql":          {7, "b551545c156b7e9f558a4ff418dc7920432044aa6c17c08e4361627611be5295"},
		"typescript/graphql":          {7, "ec6afb13620aa35ad4cb794743157383bb5d70a42a18de75cf3282f2380d4df0"},
		"javascript/dynamic-dispatch": {4, "e0424db9e36013a6ecf84c4d8026dbb29ef92503666c205bf47908ab1752dea3"},
		"typescript/dynamic-dispatch": {4, "d3c570ca16b55796754ecec6876571e76ac4de98c29c2760943453cc11b78b43"},
		"python/routes":               {5, "c4ab83af8da35abce5bf61b3961bd27c8ea8b58a6d0d7f7c1c8409d8a6bd6e40"},
		"python/dynamic-vulnpy":       {31, "7861d772b7f3271c186ca93e9cf5d240857f393b9d65c592dbb30e6ff8718cb9"},
		"javascript/xss-fetch":        {5, "cd41f16976985b7ab9b8fa2b9cc8ee247f1384cf330d22221868508f97221743"},
		"javascript/outbound":         {5, "6723d63a902d3864956e8349eb61bb047c3c59e2f766b00fd3642aff8a7ada1c"},
	}
	c, _ := New("openai", "fixture-model", "k")
	for fixture, expected := range want {
		t.Run(fixture, func(t *testing.T) {
			r, err := parse.Analyze("../parse/testdata/"+fixture, "")
			if err != nil {
				t.Fatal(err)
			}
			lines := []string{}
			for _, u := range r.Uses {
				if u.Kind == "command_execution_candidate" {
					continue
				}
				u = predecessorNodeUse(u)
				p, err := c.payload(u)
				if err != nil {
					lines = append(lines, u.ID+" noreq")
					continue
				}
				lines = append(lines, fmt.Sprintf("%s %x", u.ID, sha256.Sum256(p)))
			}
			sort.Strings(lines)
			all := ""
			for _, l := range lines {
				all += l + "\n"
			}
			if got := fmt.Sprintf("%x", sha256.Sum256([]byte(all))); len(lines) != expected.count || got != expected.digest {
				t.Fatalf("predecessor request bytes changed: %d candidates, digest %s", len(lines), got)
			}
		})
	}
}
