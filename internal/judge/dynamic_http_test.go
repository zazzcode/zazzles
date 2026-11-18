package judge

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/pipeline"
)

func TestDynamicPythonVulnPyTraces(t *testing.T) {
	r, err := pipeline.Analyze("../langpy/testdata/dynamic-vulnpy", "")
	if err != nil {
		t.Fatal(err)
	}
	paths := map[string]string{}
	for _, e := range r.Entries {
		if e.HTTP != nil {
			paths[e.ID] = e.HTTP.Path
		}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var body struct {
			Input     string `json:"input"`
			Questions []struct {
				Name string `json:"name"`
			} `json:"questions"`
		}
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		var evidence struct {
			Version    int `json:"evidence_version"`
			Invocation struct {
				Closures []struct {
					Constant *string `json:"constant"`
				} `json:"closures"`
			} `json:"invocation"`
		}
		var envelope struct {
			Use json.RawMessage `json:"use"`
		}
		if err := json.Unmarshal([]byte(body.Input), &envelope); err != nil {
			t.Error(err)
		}
		if err := json.Unmarshal(envelope.Use, &evidence); err != nil {
			t.Error(err)
		}
		if evidence.Version != 7 || len(evidence.Invocation.Closures) == 0 || !strings.Contains(body.Input, "closure_capture") && strings.Contains(body.Input, "sql_query_candidate") {
			t.Error("dynamic prompt lost closure/trace witnesses")
		}
		answers := []map[string]string{}
		choices := map[string]string{"validation": "uncertain", "protection": "insufficient", "injection_protection": "vulnerable", "output_context": "html_text", "encoding_adequacy": "not_present", "sanitizer_effectiveness": "absent", "xss_all_paths_protected": "no", "xss_exposure": "vulnerable"}
		for _, q := range body.Questions {
			answers = append(answers, map[string]string{"name": q.Name, "type": "choice", "choice": choices[q.Name]})
		}
		json.NewEncoder(w).Encode(map[string]any{"model": "fixture-model", "answers": answers})
	}))
	defer server.Close()
	client, err := New("openai", "fixture-model", "synthetic-test-key")
	if err != nil {
		t.Fatal(err)
	}
	client.endpoint = server.URL
	client.http = server.Client()
	assessed := 0
	for _, u := range r.Uses {
		if !strings.HasPrefix(paths[u.EntryID], "/vulnpy/") || u.Kind != "sql_query_candidate" && !(u.XSS != nil && strings.Contains(paths[u.EntryID], "/xss/raw")) {
			continue
		}
		got, trace := client.AssessTrace(context.Background(), u)
		assessed++
		if got.Status != "completed" || got.FindingStatus != "confirmed_vulnerability" {
			t.Errorf("%s %s: %+v", paths[u.EntryID], u.Kind, got)
		}
		if trace.RequestBytes > 64<<10 {
			t.Fatal("dynamic request exceeds existing evidence limit")
		}
		if replay := client.Replay(u, trace); replay.Status != "completed" {
			t.Fatal("exact replay rejected")
		}
		changed := u
		ctx := *u.InvocationFacts
		ctx.Closures = append([]analysis.InputBinding{}, ctx.Closures...)
		value := "different"
		ctx.Closures[0].Constant = &value
		changed.InvocationFacts = &ctx
		if replay := client.Replay(changed, trace); replay.Status != "failed" {
			t.Fatal("changed constant closure replayed historical answer")
		}
	}
	if assessed != 12 {
		t.Fatalf("local stub assessed %d required traces", assessed)
	}
}
