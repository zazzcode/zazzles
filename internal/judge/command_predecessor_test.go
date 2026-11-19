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
		"javascript/grpc":             {7, "e1d52c0d9f093e55489bed11b751c3fdd44a122c7158a9831ed5a58540dd0d28"},
		"typescript/grpc":             {7, "6f91be19e5680169710eb5bd45981da1288763c2515f830857ed807a4f08f80c"},
		"javascript/graphql":          {7, "3ac164030f1e80f31f278c9b7b9ed534abb6dcd904a744c697a4117d70f926ee"},
		"typescript/graphql":          {7, "1caa30da0cf53348cf2261195f452cbcca1ec63b56eb7eaf3605103184a98891"},
		"javascript/dynamic-dispatch": {4, "8c9274aff93dd8fbe2b4c3de1fccd90916d270df060983505c73705d093934b3"},
		"typescript/dynamic-dispatch": {4, "e8f515e38a9504b4a8970c969f6178d7ffdea0c09aeb7a61943eeba002018719"},
		"python/routes":               {5, "2ce7531c60f7d221060704bbe570cdd3f07cac5a245916fe547846bfe9099e58"},
		"python/dynamic-vulnpy":       {31, "d9d3c4965996054bf1fe667ed2c4a7f990a1f64ed32cf7248938caa661370412"},
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
