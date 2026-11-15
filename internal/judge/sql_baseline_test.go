package judge

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/zazzcode/zazzles/internal/analysispacks"
	"github.com/zazzcode/zazzles/internal/parse"
	"testing"
)

func TestSQLDiscoveryBaseline(t *testing.T) {
	for _, fixture := range []string{"string-flow", "javascript/grpc", "typescript/grpc", "javascript/graphql", "typescript/graphql", "javascript/dynamic-dispatch", "typescript/dynamic-dispatch", "python/routes", "python/dynamic-vulnpy"} {
		t.Run(fixture, func(t *testing.T) {
			r, err := parse.Analyze("../parse/testdata/"+fixture, "")
			if err != nil {
				t.Fatal(err)
			}
			r.SchemaVersion = 3
			// Command-injection candidates are a later family: this baseline freezes the
			// predecessor families, which must be byte-identical without them.
			predecessors := r.Uses[:0:0]
			for _, u := range r.Uses {
				if u.Kind != "command_execution_candidate" {
					predecessors = append(predecessors, u)
				}
			}
			r.Uses = predecessors
			for i := range r.Uses {
				r.Uses[i].InputFacts = nil
				r.Uses[i].Components = nil
			}
			b, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			// E4 phase-2 Python file APIs retarget dynamic-vulnpy discovery bytes.
			want := map[string]string{"string-flow": "29d18dfada4c95b83b4193120a424c60931dee7d28b2d6baa94854f65f3aa678", "javascript/grpc": "4645b5ef4d70f6f68159de2dda8892468e03d2f4ca19050e93cc6ebb1a529bbb", "typescript/grpc": "cca68722db414ff52330afd2f7b35839ed7758831c316b32b60c029296e7f9e8", "javascript/graphql": "c647efd74977cd26e7ffc0c8b80417a65d3202ae814a636b996b1ae063292d85", "typescript/graphql": "f2f7c8402f2fd9f6b6e2e235a96f87441c9df0ea2e63b26b1f295c51ebaa6c3f", "javascript/dynamic-dispatch": "471fc8521bf45156f051a78bd473f83a6833ceffaf02f58150d4a7cde44b6149", "typescript/dynamic-dispatch": "1be3480bfda34ac31cc98ba352d58e5968597c5699e3b854517e04a8eaff4057", "python/routes": "316264120785de023f0109f279b23333b7305a841e022d6f55a887b470ed6d59", "python/dynamic-vulnpy": "4b41af25756fa1614ff4f6035486502176e08dc3c83e3e46a3e9ae720d875af7"}[fixture]
			if got := fmt.Sprintf("%x", sha256.Sum256(b)); got != want {
				t.Fatalf("source/evidence/outcome baseline drift: got %s want %s", got, want)
			}
			for i := range r.Uses {
				analysispacks.Attach(&r.Uses[i])
			}
			c, _ := New("openai", "fixture-model", "test-key")
			for _, u := range r.Uses {
				if u.Kind == "sql_query_candidate" {
					p, e := c.payload(u)
					if e != nil {
						if u.Components == nil || u.Components.Failure == "" {
							t.Fatal(e)
						}
						continue
					}
					fmt.Printf("PAYLOAD %s %s %d\n", fixture, u.ID, len(p))
				}
			}
		})
	}
}
