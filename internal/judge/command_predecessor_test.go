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
func TestCommandPredecessorRequests(t *testing.T) {
	type baseline struct {
		count  int
		digest string
	}
	want := map[string]baseline{
		"string-flow":                 {1, "6f9b69d1d97fc527823f4fbc55e28b09f1c46ae489bc6fcd34eebd06329758b6"},
		"javascript/grpc":             {7, "bc435d37f6a2374e501c14e7b29a14dfee7abf3a6881898ee4aa440f59f3b108"},
		"typescript/grpc":             {7, "512696c5dd17b9b7ec5b440d836b23eb0c7bdce4e4d2566d2cce1a789e09204d"},
		"javascript/graphql":          {7, "d4a695d871ec5e44cd1e3f760930a0ddd79681c598ddbfbe36c5f9667680971b"},
		"typescript/graphql":          {7, "a932ff110ab2b1c87adec509a7e3576c05b5640b2edc691695f482864423acbf"},
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
