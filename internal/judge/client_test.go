package judge

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
)

func TestProviders(t *testing.T) {
	for _, provider := range []string{"openai", "jev"} {
		t.Run(provider, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer test-key" {
					t.Error("missing authentication")
				}
				var body map[string]json.RawMessage
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
				}
				field := "input"
				if provider == "jev" {
					field = "state"
				}
				if len(body[field]) == 0 || len(body["questions"]) == 0 || !strings.Contains(string(body[field]), "id: javascript") || !strings.Contains(string(body["questions"]), "analysis guidelines") {
					t.Error("wrong provider request shape")
				}
				var input map[string]json.RawMessage
				var source string
				if err := json.Unmarshal(body[field], &source); err != nil {
					t.Error(err)
					return
				}
				if err := json.Unmarshal([]byte(source), &input); err != nil {
					t.Error(err)
					return
				}
				if len(input["analysis_guidelines"]) == 0 || len(input["practice"]) != 0 {
					t.Error("guideline metadata uses the wrong input key")
				}
				if provider == "openai" {
					w.Write([]byte(`{"model":"test-model","answers":[{"name":"validation","type":"choice","choice":"insufficient"},{"name":"protection","type":"choice","choice":"sufficient"}],"usage":{"input_tokens":12}}`))
				} else {
					w.Write([]byte(`{"model":"test-model","answers":{"validation":{"type":"choice","choice":"insufficient"},"protection":{"type":"choice","choice":"sufficient"}},"usage":{"input_tokens":12}}`))
				}
			}))
			defer server.Close()
			client, err := New(provider, "test-model", "test-key")
			if err != nil {
				t.Fatal(err)
			}
			client.endpoint = server.URL
			client.http = server.Client()
			use := analysis.CandidateUse{Sink: analysis.Evidence{Span: analysis.Span{File: "server.ts"}}, Gaps: []analysis.Gap{{Kind: "unresolved_flow"}}}
			got := client.Assess(context.Background(), use)
			if got.Status != "completed" || got.Answers["protection"] != "sufficient" || got.Protection != "uncertain" || got.Provider != provider || got.Usage["input_tokens"] != 12 {
				t.Fatalf("assessment=%+v", got)
			}
		})
	}
}

func TestInvalidResponses(t *testing.T) {
	tests := []struct {
		name, body string
		code       int
	}{
		{"missing", `{"model":"m","answers":[]}`, 200},
		{"duplicate", `{"model":"m","answers":[{"name":"protection","type":"choice","choice":"sufficient"},{"name":"protection","type":"choice","choice":"sufficient"}]}`, 200},
		{"refusal", `{"model":"m","answers":[{"name":"protection","type":"refusal"},{"name":"validation","type":"choice","choice":"sufficient"}]}`, 200},
		{"unknown choice", `{"model":"m","answers":[{"name":"protection","type":"choice","choice":"safe"},{"name":"validation","type":"choice","choice":"sufficient"}]}`, 200},
		{"malformed", "{", 200},
		{"error body", "secret server error text", 400}, // non-retried; must not leak the body
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(tt.code); w.Write([]byte(tt.body)) }))
			defer s.Close()
			c, _ := New("openai", "", "test-key")
			c.endpoint = s.URL
			c.http = s.Client()
			a := c.Assess(context.Background(), analysis.CandidateUse{})
			if a.Status != "failed" || a.Protection == "sufficient" || strings.Contains(a.Reason, "secret") {
				t.Fatalf("assessment=%+v", a)
			}
		})
	}
}

func TestConfigurationAndCancellation(t *testing.T) {
	for _, p := range []string{"openai", "jev", "other"} {
		if _, err := New(p, "m", ""); err == nil {
			t.Fatalf("missing key accepted for %s", p)
		}
	}
	if _, err := New("jev", "", "key"); err == nil {
		t.Fatal("unpinned Jev model accepted")
	}
	c, _ := New("openai", "", "key")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if a := c.Assess(ctx, analysis.CandidateUse{}); a.Status != "failed" {
		t.Fatalf("canceled assessment=%+v", a)
	}
	a := c.Assess(context.Background(), analysis.CandidateUse{Sink: analysis.Evidence{Text: strings.Repeat("x", 65<<10)}})
	if a.Status != "not_run" {
		t.Fatalf("oversized evidence=%+v", a)
	}
}

func TestJevDuplicateAnswers(t *testing.T) {
	c, _ := New("jev", "test-model", "key")
	_, _, _, err := c.decodeQuestions([]byte(`{"model":"m","answers":{"validation":{"type":"choice","choice":"sufficient"},"validation":{"type":"choice","choice":"insufficient"},"protection":{"type":"choice","choice":"uncertain"}}}`), questions)
	if err == nil {
		t.Fatal("duplicate Jev answer was accepted")
	}
}
