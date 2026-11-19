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
// an unknown_transfer flow gap gain a flow-gap question (W2); no other
// family's request changed.
func TestCommandPredecessorRequests(t *testing.T) {
	type baseline struct {
		count  int
		digest string
	}
	want := map[string]baseline{
		"string-flow":                 {1, "6f9b69d1d97fc527823f4fbc55e28b09f1c46ae489bc6fcd34eebd06329758b6"},
		"javascript/grpc":             {7, "e55614184d97a48072283a380da73814aff20b44f8336e78af21195918390e67"},
		"typescript/grpc":             {7, "d3dcb90b00d7303a328537cf161e9dbaffbbc1c961ad6941229ec7d9e0c54374"},
		"javascript/graphql":          {7, "0f7aebc5b7fbf28d9bbb15f151afc3bcea09925c9399c1757ca18fd7f02d6015"},
		"typescript/graphql":          {7, "d6ba084abbfb83d088d92fd869953739cd1d1883a34f7c4b79c7acb5b86e0121"},
		"javascript/dynamic-dispatch": {4, "d38d7e7d24b6eb0393ff8b8ecd3cf554d4001fbe24344e36ed2585e0ac2d0dbc"},
		"typescript/dynamic-dispatch": {4, "f2b4f8d1d09947b7ce06283a7edfb7cab0a4164a64fd54450ad81da09e56e9f1"},
		"python/routes":               {5, "2ce7531c60f7d221060704bbe570cdd3f07cac5a245916fe547846bfe9099e58"},
		"python/dynamic-vulnpy":       {31, "d9cbf34138ecfa3b558df97719b5c38b79669ac4c623e92f5eef255ba033fb20"},
		"javascript/xss-fetch":        {5, "f88b981603f5431ae1dbc62aa89840fdea7b2aaaa27b3d1f8a6da0a7bdfbe2b2"},
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
