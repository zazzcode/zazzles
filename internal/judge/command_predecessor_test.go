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
		"javascript/grpc":             {7, "e64335dd05c1dc3e1096c9abb4cdb503adc78228ae07eb8e82e3d81de3ca6fbf"},
		"typescript/grpc":             {7, "5c9521a5235e04a2550e8d678f8437910421ad11530ba5d6d3152e1fa37b735e"},
		"javascript/graphql":          {7, "7445b5e70d2f6fa6a8d8c0f4b458b6a375864aafad68c370da898cb26865da8a"},
		"typescript/graphql":          {7, "f2d3c9ce3efcf846047b47bb7fe21d9c95d8e2699c7a639c9169ae4f9ce89bc7"},
		"javascript/dynamic-dispatch": {4, "480efe80084653aae9840b3889570520d9c7cc88afc4577114ce3aca0f465ca1"},
		"typescript/dynamic-dispatch": {4, "6dc83c5bc5b58dac19e9d2e1fd54eab0a7242632863d2abd2b9ba6e3c26882b0"},
		"python/routes":               {5, "a64fe783f17078a275a5b3ef7ef3f04bf2929b31bf9a65380148ddace80f27ad"},
		"python/dynamic-vulnpy":       {31, "4685616050e8858f0dcd2eda6b21dbd4ba66dc06f3b82e4b92a02b947c091736"},
		"javascript/xss-fetch":        {5, "4dc77d57af759f54da6d700b9020125c50921424e3ce06deabded130a3de4e62"},
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
