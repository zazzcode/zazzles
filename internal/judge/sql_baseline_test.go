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
				r.Uses[i].Components = nil
			}
			b, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			want := map[string]string{"string-flow": "222829966d4b67220bccafe997e4963231a07479c319f6ff8864f2a42e4addd7", "javascript/grpc": "b4d677bd55f62db3d096c0bfe711a93b371c3e7da69b77bc3a18c0b9e0810907", "typescript/grpc": "c6adea365797449ca58145442963d38fad78dd6f7cb00ecf82572b7d2e310c3e", "javascript/graphql": "6f5cf75324ead9ceaa9207cdcb410208c453522f74fe574fb7c371fa80e2525b", "typescript/graphql": "55c27f6544e5ed10bf2288fd9246f0509d20b587f531f7374da4f0557ba0e6e7", "javascript/dynamic-dispatch": "471fc8521bf45156f051a78bd473f83a6833ceffaf02f58150d4a7cde44b6149", "typescript/dynamic-dispatch": "1be3480bfda34ac31cc98ba352d58e5968597c5699e3b854517e04a8eaff4057", "python/routes": "316264120785de023f0109f279b23333b7305a841e022d6f55a887b470ed6d59", "python/dynamic-vulnpy": "30691993b4c00533fc9c0d14535c545dfd4129020e19924ca6f52508f9396f95"}[fixture]
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
