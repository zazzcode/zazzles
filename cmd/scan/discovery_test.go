package main

import (
	"bytes"
	"encoding/json"
	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/judge"
	reportpkg "github.com/zazzcode/zazzles/internal/report"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNodeDiscoveryCLI(t *testing.T) {
	t.Setenv("SCAN_FINDINGS_DIR", "")
	t.Setenv("OPENAI_API_KEY", "synthetic-key")
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "server.js"), []byte(`function handler(req,res){res.send('ok')};exposeHTTP('/one',handler);exposeHTTP('/two',handler);`), 0600); err != nil {
		t.Fatal(err)
	}
	calls := 0
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		json.NewEncoder(w).Encode(map[string]any{"model": "fixture-model", "answers": []map[string]string{{"name": "route_binding", "type": "choice", "choice": "route"}}})
	}))
	defer stub.Close()
	old := newJudgeClient
	defer func() { newJudgeClient = old }()
	newJudgeClient = func(provider, model, key string) (*judge.Client, error) {
		c, e := judge.New(provider, model, key)
		if e == nil {
			c.UseEndpoint(stub.URL, stub.Client())
		}
		return c, e
	}
	for _, enabled := range []bool{false, true} {
		var out, errOut bytes.Buffer
		args := []string{"--analyze", "--json", "--judge", "openai", "--judge-model", "fixture-model"}
		if enabled {
			args = append(args, "--discover-routes", "--discovery-limit", "1")
		}
		args = append(args, root)
		code := run(args, &out, &errOut)
		var r analysis.AnalysisReport
		if err := json.Unmarshal(out.Bytes(), &r); err != nil {
			t.Fatalf("invalid report: %v %s", err, errOut.String())
		}
		if !enabled {
			if calls != 0 || len(r.Discovery) != 0 {
				t.Fatal("discovery ran without opt-in")
			}
			continue
		}
		if code != exitError || calls != 1 || len(r.Discovery) != 2 || len(r.Entries) != 0 || len(r.Uses) != 0 {
			t.Fatalf("code=%d calls=%d proposals=%d entries=%d uses=%d", code, calls, len(r.Discovery), len(r.Entries), len(r.Uses))
		}
		for _, p := range r.Discovery {
			if p.State != "provisional" || p.VerifiedEntryID != "" {
				t.Fatal("model manufactured trusted entry")
			}
		}
		var page bytes.Buffer
		if err := reportpkg.HTML(&page, &r); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(page.String(), "Route discovery proposals") {
			t.Fatal("HTML hid provisional coverage")
		}
		s := reportpkg.SARIF(&r)
		runs := s["runs"].([]any)
		props := runs[0].(map[string]any)["properties"].(map[string]any)
		if props["scan.discoveryProposals"] == nil {
			t.Fatal("SARIF omitted proposals")
		}
	}
}
func TestDiscoveryFlagBounds(t *testing.T) {
	for _, args := range [][]string{{"--analyze", "--discover-routes", "."}, {"--list", "--discover-routes", "."}, {"--analyze", "--judge", "openai", "--discover-routes", "--discovery-limit", "0", "."}, {"--analyze", "--discovery-limit", "1", "."}} {
		var out, errOut bytes.Buffer
		if run(args, &out, &errOut) != exitUsage {
			t.Fatalf("invalid discovery flags accepted: %v", args)
		}
	}
}
