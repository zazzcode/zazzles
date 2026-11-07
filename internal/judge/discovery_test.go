package judge

import (
	"context"
	"encoding/json"
	"github.com/zazzcode/zazzles/internal/analysis"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestModelDiscoveryProtocol(t *testing.T) {
	for _, choice := range []string{"route", "unknown", "not_route", "protected"} {
		t.Run(choice, func(t *testing.T) {
			calls := 0
			stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				json.NewEncoder(w).Encode(map[string]any{"model": "fixture-model", "answers": []map[string]string{{"name": "route_binding", "type": "choice", "choice": choice}}})
			}))
			defer stub.Close()
			c, _ := New("openai", "fixture-model", "key")
			c.UseEndpoint(stub.URL, stub.Client())
			p := analysis.DiscoveryProposal{ID: "p", Registration: analysis.Evidence{Text: "wrapper('/x',handler)", SHA256: strings.Repeat("a", 64)}, Handler: analysis.Evidence{Text: "{return 'x'}", SHA256: strings.Repeat("b", 64)}}
			got, tr := c.DiscoverTrace(context.Background(), p)
			if calls != 1 || got.State != "provisional" || got.VerifiedEntryID != "" {
				t.Fatal("discovery promoted unverified input")
			}
			if choice == "protected" {
				if got.ModelChoice != "" {
					t.Fatal("invalid choice accepted")
				}
			} else if got.ModelChoice != choice {
				t.Fatalf("choice=%+v", got)
			}
			replay := c.ReplayDiscovery(p, tr)
			if replay.ModelChoice != got.ModelChoice || calls != 1 {
				t.Fatal("replay altered result or made a call")
			}
			p.Handler.Text = "changed"
			if c.ReplayDiscovery(p, tr).ModelChoice != "" {
				t.Fatal("changed evidence replayed")
			}
		})
	}
}
