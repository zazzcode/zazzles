package judge

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
	"github.com/zazzcode/zazzles/scan/internal/pipeline"
	"testing"
)

func TestSQLDiscoveryBaseline(t *testing.T) {
	for _, fixture := range []string{"string-flow", "javascript/grpc", "typescript/grpc", "javascript/graphql", "typescript/graphql", "javascript/dynamic-dispatch", "typescript/dynamic-dispatch", "python/routes", "python/dynamic-vulnpy"} {
		t.Run(fixture, func(t *testing.T) {
			r, err := pipeline.Analyze(fixtureRoot(fixture), "")
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
			// Phase 3B: fixtures moved to internal/langpy and internal/langjs; only the embedded root changed.
			want := map[string]string{"string-flow": "6532de02838598882eba7d94e2a40347e26de5175ee0f1e46eca2d477d6a93f5", "javascript/grpc": "51b3df7ddd4e269670f7681d0906eff1a4a157bf646880285c621b213cd7a03a", "typescript/grpc": "0a2ec5eae8d42c17ba20d4587a9e8cc86af7607e68214482b7a8101acda4205d", "javascript/graphql": "ff2b873f82443caa554a287e04469623543d8906bfd3658c14b8922fa9b17690", "typescript/graphql": "ff659ac9870f7f4abf4b82c93c56fbe921c150e6f570f6bd22f6c0128f9b58cb", "javascript/dynamic-dispatch": "b913c276015ce03f7f967e99ccc95c0b213eb6181305f4da0b10c9596e8f865d", "typescript/dynamic-dispatch": "0e900af57689751d80cad49dd04011b3ff66bc7f91b729fef6ef1be318bbcf04", "python/routes": "4ffe0196011022054bd1698b551c8791ecc3074ac7fefe81ef283d269d63505c", "python/dynamic-vulnpy": "5e9e6b1b86e88165865fce51a4b2adca2f9d9e38df69978b4ec77b29ffa4f137"}[fixture]
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
