package judge

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"testing"

	"github.com/zazzcode/zazzles/internal/parse"
)

// TestCommandPredecessorRequests freezes existing-family requests after the
// coordinated v7 representation and component protocol upgrade. Candidate counts
// stay fixed; observation-only records still have no request.
func TestCommandPredecessorRequests(t *testing.T) {
	type baseline struct {
		count  int
		digest string
	}
	want := map[string]baseline{
		"string-flow":                 {1, "6f9b69d1d97fc527823f4fbc55e28b09f1c46ae489bc6fcd34eebd06329758b6"},
		"javascript/grpc":             {7, "85d7ccc338aa644833a5c0389a45ff34e899aaf59b9a31e64c4f531da26af9ec"},
		"typescript/grpc":             {7, "2aa415f952b010e817657ecc147869a96d001dcb4a6ead665af5f2188f83cceb"},
		"javascript/graphql":          {7, "36af2c45c83be79cfe29ebfc3ca607017ced56bf43bb33cd929337d44b8ad27f"},
		"typescript/graphql":          {7, "a8b7629d33c019d7bc359c5cfc693a1f4ba70b67d7646ecec930630269fce41e"},
		"javascript/dynamic-dispatch": {4, "d38d7e7d24b6eb0393ff8b8ecd3cf554d4001fbe24344e36ed2585e0ac2d0dbc"},
		"typescript/dynamic-dispatch": {4, "f2b4f8d1d09947b7ce06283a7edfb7cab0a4164a64fd54450ad81da09e56e9f1"},
		"python/routes":               {5, "2ce7531c60f7d221060704bbe570cdd3f07cac5a245916fe547846bfe9099e58"},
		"python/dynamic-vulnpy":       {31, "c511526614a93ba654d051f6929efb1f70f3d91a234ab94628e48f1da0d66542"},
		"javascript/xss-fetch":        {5, "f88b981603f5431ae1dbc62aa89840fdea7b2aaaa27b3d1f8a6da0a7bdfbe2b2"},
		"javascript/outbound":         {4, "7616f13e1350e438c8ff872759a2b58a948bf45f08379401a1f0a6c5c341718b"},
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
