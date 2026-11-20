package judge

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"testing"

	"github.com/zazzcode/zazzles/internal/pipeline"
)

// TestCommandPredecessorRequests freezes existing-family requests after the
// coordinated v7 representation and component protocol upgrade. The GraphQL and
// gRPC fixtures were re-recorded for modeled JavaScript conditionals: their
// guarded resolvers lose the generic control-flow gaps. Candidate counts
// stay fixed; observation-only records still have no request. Evidence
// resolution re-recorded the GraphQL and gRPC fixtures: their SQL records with
// an unknown_transfer flow gap gain a flow-gap question (W2), and path, SQL
// and XSS records whose gaps name an unresolved symbol gain the
// one-evidence-request question (W5); no other family's request changed.
// Their flow-gap citation labels later gained the referenced evidence text
// (flow-gap-v2).
func TestCommandPredecessorRequests(t *testing.T) {
	type baseline struct {
		count  int
		digest string
	}
	want := map[string]baseline{
		"string-flow":                 {1, "6f9b69d1d97fc527823f4fbc55e28b09f1c46ae489bc6fcd34eebd06329758b6"},
		"javascript/grpc":             {7, "c32c39ba4c1d68920468006300ab2497c2ff48c897d48d23c7b8143d1016a3c4"},
		"typescript/grpc":             {7, "b224faba4c62ea83ff27ae0f4774e6bd8a5d089cf3ebe300ff4b75afd571cf48"},
		"javascript/graphql":          {7, "783ee024e8cf8b2e4302f33c6a6bc3b1f4cbf087d0920d072efc48beaa09a330"},
		"typescript/graphql":          {7, "5ecf0074a0c9f88ec6778464a6e7b5a86e051968dee4585a4e8494b0440b87e7"},
		"javascript/dynamic-dispatch": {4, "fec97a09525dd0b5e68af6ed380988a0f872ab6cfe7f108726fa96750012254a"},
		"typescript/dynamic-dispatch": {4, "a160c63e817184f8e4447e63bca7b9fed68a29780f9f6124f542174f0c4ad8c3"},
		"python/routes":               {5, "175efac48fdf545ec7a8381fa0d3b3063fa27e9f202c10b1d4c2da8435450c25"},
		"python/dynamic-vulnpy":       {31, "ecad7e229950d6a70ba89796812da6d19288cdc9c177745e1d97de6ea85694f3"},
		"javascript/xss-fetch":        {5, "f74d892028f3f2c669b2cc34212231958046e766c9bc9ea124f83c4cacb67c79"},
		"javascript/outbound":         {4, "7616f13e1350e438c8ff872759a2b58a948bf45f08379401a1f0a6c5c341718b"},
	}
	c, _ := New("openai", "fixture-model", "k")
	for fixture, expected := range want {
		t.Run(fixture, func(t *testing.T) {
			r, err := pipeline.Analyze(fixtureRoot(fixture), "")
			if err != nil {
				t.Fatal(err)
			}
			lines := []string{}
			for _, u := range r.Uses {
				if u.Kind == "command_execution_candidate" || u.Kind == "ssrf_candidate" {
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
