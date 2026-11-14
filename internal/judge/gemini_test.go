package judge

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
)

func TestGeminiProtocolAndReplay(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != "POST" || r.Header.Get("x-goog-api-key") != "test-key" || r.Header.Get("Authorization") != "" {
			t.Error("incorrect Google authentication or method")
		}
		var body struct {
			Model, Input string
			Questions    map[string]struct {
				Type, Instructions string
				Criteria           map[string]string
			}
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body.Model != "gemini-decision-1" || body.Input == "" || len(body.Questions) != 2 {
			t.Errorf("wrong request: %+v", body)
		}
		for _, q := range body.Questions {
			if q.Type != "choice" || len(q.Criteria) == 0 {
				t.Error("missing choice criteria")
			}
		}
		w.Write([]byte(`{"answers":{"validation":{"type":"choice","choice":"insufficient","confidence":0.8,"probabilities":{"insufficient":0.8,"sufficient":0.1,"uncertain":0.1}},"protection":{"type":"choice","choice":"sufficient","confidence":0.9,"probabilities":{"sufficient":0.9,"insufficient":0.05,"uncertain":0.05}}},"usage":{"total_input_tokens":12,"total_output_tokens":0,"total_tokens":12,"input_tokens_by_modality":[{"modality":"text","tokens":12}]}}`))
	}))
	defer server.Close()
	c, err := New("gemini", "", "test-key")
	if err != nil {
		t.Fatal(err)
	}
	c.UseEndpoint(server.URL, server.Client())
	use := analysis.CandidateUse{Sink: analysis.Evidence{Span: analysis.Span{File: "server.ts"}}, Gaps: []analysis.Gap{{Kind: "unresolved_flow"}}}
	a, tr := c.AssessTrace(context.Background(), use)
	if a.Status != "completed" || a.Model != "gemini-decision-1" || a.Provider != "gemini" || a.Usage["input_tokens"] != 12 || a.Protection != "uncertain" {
		t.Fatalf("assessment=%+v", a)
	}
	d := a.AnswerDetails["protection"]
	if d.Confidence == nil || *d.Confidence != .9 || len(d.Probabilities) != 3 || d.Probabilities[0].Value != "insufficient" {
		t.Fatalf("scores=%+v", d)
	}
	if got := c.Replay(use, tr); got.Status != "completed" {
		t.Fatalf("replay=%+v", got)
	}
	use.Sink.Text = "changed source"
	if got := c.Replay(use, tr); got.Status != "failed" {
		t.Fatal("stale replay accepted")
	}
	if calls != 1 {
		t.Fatalf("calls=%d", calls)
	}
}

func TestGeminiRejectsInvalidResponses(t *testing.T) {
	valid := `{"type":"choice","choice":"sufficient"}`
	for name, body := range map[string]string{
		"wrong model":       `{"model":"other","answers":{"validation":` + valid + `,"protection":` + valid + `}}`,
		"missing":           `{"answers":{"validation":` + valid + `}}`,
		"duplicate":         `{"answers":{"validation":` + valid + `,"validation":` + valid + `}}`,
		"bad choice":        `{"answers":{"validation":{"type":"choice","choice":"safe"},"protection":` + valid + `}}`,
		"bad confidence":    `{"answers":{"validation":{"type":"choice","choice":"sufficient","confidence":2},"protection":` + valid + `}}`,
		"bad probabilities": `{"answers":{"validation":{"type":"choice","choice":"sufficient","probabilities":{"sufficient":-0.1}},"protection":` + valid + `}}`,
		"malformed":         `{`,
	} {
		t.Run(name, func(t *testing.T) {
			c, err := New("gemini", "", "test-key")
			if err != nil {
				t.Fatal(err)
			}
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) }))
			defer s.Close()
			c.UseEndpoint(s.URL, s.Client())
			if a := c.Assess(context.Background(), analysis.CandidateUse{}); a.Status != "failed" {
				t.Fatalf("assessment=%+v", a)
			}
		})
	}
}

func TestGeminiConfigurationAndHTTPFailure(t *testing.T) {
	if _, err := New("gemini", "gemini-flash", "key"); err == nil {
		t.Fatal("other Google model accepted")
	}
	if _, err := New("gemini", "", ""); err == nil {
		t.Fatal("missing key accepted")
	}
	c, err := New("gemini", "", "key")
	if err != nil {
		t.Fatal(err)
	}
	if c.endpoint != "https://generativelanguage.googleapis.com/v1beta/decisions" {
		t.Fatal(c.endpoint)
	}
	calls := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(429)
		w.Write([]byte("private error"))
	}))
	defer s.Close()
	c.UseEndpoint(s.URL, s.Client())
	if a := c.Assess(context.Background(), analysis.CandidateUse{}); a.Status != "failed" || a.Reason != "judge HTTP 429" {
		t.Fatalf("assessment=%+v", a)
	}
	if calls != 1 {
		t.Fatal("retried failure")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if a := c.Assess(ctx, analysis.CandidateUse{}); a.Status != "failed" {
		t.Fatal("canceled request succeeded")
	}
}

func TestGeminiAllAnalyzerProtocols(t *testing.T) {
	_, xss := parsedXSS(t, map[string]string{"client.js": `document.body.innerHTML=location.hash`})
	uses := []analysis.CandidateUse{selectedSQLUse(t), selectedNoSQLUse(t), selectedValidationUse(t), commandFixtureUse(t, "javascript"), logClaim("log_sensitive_field_hint"), xss}
	c, err := New("gemini", "", "test-key")
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var body struct {
			Model, Input string
			Questions    map[string]struct {
				Type     string
				Criteria map[string]string
			}
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		if body.Model != "gemini-decision-1" || body.Input == "" {
			t.Error("wrong shared provider input")
		}
		answers := map[string]any{}
		for name, q := range body.Questions {
			choice := "unknown"
			if _, ok := q.Criteria[choice]; !ok {
				choice = "uncertain"
			}
			if _, ok := q.Criteria[choice]; !ok {
				keys := []string{}
				for key := range q.Criteria {
					keys = append(keys, key)
				}
				sort.Strings(keys)
				choice = keys[0]
			}
			probabilities := map[string]float64{}
			for key := range q.Criteria {
				probabilities[key] = 0
			}
			probabilities[choice] = 1
			answers[name] = map[string]any{"type": "choice", "choice": choice, "confidence": 1, "probabilities": probabilities}
		}
		json.NewEncoder(w).Encode(map[string]any{"answers": answers, "usage": map[string]int64{"total_input_tokens": 20, "total_output_tokens": 0, "total_tokens": 20}})
	}))
	defer s.Close()
	c.UseEndpoint(s.URL, s.Client())
	for _, use := range uses {
		t.Run(use.Kind, func(t *testing.T) {
			a, tr := c.AssessTrace(context.Background(), use)
			if a.Status != "completed" || a.Provider != "gemini" || a.Model != "gemini-decision-1" || len(a.Answers) != len(questionsFor(use)) {
				t.Fatalf("assessment=%+v", a)
			}
			if got := c.Replay(use, tr); got.Status != "completed" {
				t.Fatalf("replay=%+v", got)
			}
		})
	}
	if calls != len(uses) {
		t.Fatalf("calls=%d", calls)
	}
}

func TestGeminiDiscovery(t *testing.T) {
	c, err := New("gemini", "", "key")
	if err != nil {
		t.Fatal(err)
	}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if len(body["input"]) == 0 || len(body["state"]) != 0 {
			t.Error("wrong discovery input field")
		}
		w.Write([]byte(`{"answers":{"route_binding":{"type":"choice","choice":"route","confidence":0.9,"probabilities":{"route":0.9,"not_route":0.05,"unknown":0.05}}}}`))
	}))
	defer s.Close()
	c.UseEndpoint(s.URL, s.Client())
	p := analysis.DiscoveryProposal{ID: "p", Registration: analysis.Evidence{Text: "wrapper('/x', handler)", SHA256: strings.Repeat("a", 64)}, Handler: analysis.Evidence{Text: "return 'x'", SHA256: strings.Repeat("b", 64)}}
	got, tr := c.DiscoverTrace(context.Background(), p)
	if got.ModelStatus != "completed" || got.ModelChoice != "route" || got.State != "provisional" || got.VerifiedEntryID != "" {
		t.Fatalf("discovery=%+v", got)
	}
	if replay := c.ReplayDiscovery(p, tr); replay.ModelChoice != "route" {
		t.Fatalf("replay=%+v", replay)
	}
}
