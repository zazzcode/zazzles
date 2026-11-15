package judge

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
)

func logClaim(gaps ...string) analysis.CandidateUse {
	u := analysis.CandidateUse{Kind: "log_sink_candidate", Sink: analysis.Evidence{Span: analysis.Span{File: "server.ts"}},
		Context:      []analysis.Evidence{{Kind: "logger_binding", Text: "global console.log"}},
		Dependencies: []analysis.Dependency{{Source: analysis.Evidence{Kind: "input_source", Text: "req.body.password"}}}}
	for _, g := range gaps {
		u.Gaps = append(u.Gaps, analysis.Gap{Kind: g})
	}
	analysispacks.Attach(&u)
	return u
}

func TestLogPolicy(t *testing.T) {
	cases := []struct {
		name                               string
		use                                analysis.CandidateUse
		class, content, redaction, verdict string
		want                               string
	}{
		{"consistent exposure", logClaim("log_sensitive_field_hint"), "credential", "yes", "no", "vulnerable", "confirmed_vulnerability"},
		{"personal data exposure", logClaim("log_request_line_hint"), "personal_data", "yes", "not_applicable", "vulnerable", "confirmed_vulnerability"},
		{"name-only class", logClaim("log_sensitive_field_hint"), "unknown", "yes", "no", "vulnerable", "needs_evidence"},
		{"possible redaction", logClaim("log_transform_unresolved"), "credential", "yes", "unknown", "vulnerable", "needs_evidence"},
		{"contradicts non-content facts", logClaim("log_non_content_only"), "credential", "yes", "no", "vulnerable", "needs_evidence"},
		{"non-content protected", logClaim("log_non_content_only"), "credential", "no", "not_applicable", "protected", "protected_for_claim"},
		{"unsupported protection", logClaim("log_sensitive_field_hint"), "credential", "yes", "no", "protected", "needs_evidence"},
		{"not sensitive", logClaim("log_sensitive_field_hint"), "other", "yes", "no", "not_applicable", "not_applicable"},
		{"inconclusive", logClaim("log_sensitive_field_hint"), "credential", "unknown", "unknown", "unknown", "needs_evidence"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			a := analysis.Assessment{Status: "completed", Answers: map[string]string{"data_class": tt.class, "content_exposure": tt.content, "redaction": tt.redaction, "log_exposure": tt.verdict}}
			applyPolicy(tt.use, &a)
			if a.FindingStatus != tt.want {
				t.Fatalf("got %s: %+v", a.FindingStatus, a)
			}
		})
	}
	t.Run("missing binding blocks", func(t *testing.T) {
		u := logClaim("log_sensitive_field_hint")
		u.Context = nil
		a := analysis.Assessment{Answers: map[string]string{"data_class": "credential", "content_exposure": "yes", "redaction": "no", "log_exposure": "vulnerable"}}
		applyPolicy(u, &a)
		if a.FindingStatus != "needs_evidence" || len(a.BlockingGaps) == 0 {
			t.Fatalf("binding not required: %+v", a)
		}
	})
}

func TestLogQuestionsPayloadAndDecoding(t *testing.T) {
	u := logClaim("log_sensitive_field_hint")
	c, _ := New("openai", "test-model", "test-key")
	payload, err := c.payload(u)
	if err != nil {
		t.Fatal(err)
	}
	var body struct {
		Input     string           `json:"input"`
		Questions []map[string]any `json:"questions"`
	}
	if err := json.Unmarshal(payload, &body); err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for _, q := range body.Questions {
		names = append(names, q["name"].(string))
	}
	if strings.Join(names, ",") != "data_class,content_exposure,redaction,log_exposure" {
		t.Fatalf("questions=%v", names)
	}
	if !strings.Contains(body.Input, "## Logging") {
		t.Fatal("logging payload lacks the logging rules")
	}
	good := `{"model":"m","answers":[{"type":"choice","name":"data_class","choice":"credential"},{"type":"choice","name":"content_exposure","choice":"yes"},{"type":"choice","name":"redaction","choice":"no"},{"type":"choice","name":"log_exposure","choice":"vulnerable"}]}`
	if _, _, _, err := c.decodeQuestions([]byte(good), questionsFor(u)); err != nil {
		t.Fatalf("valid answers rejected: %v", err)
	}
	bad := strings.Replace(good, `"choice":"vulnerable"`, `"choice":"insufficient"`, 1)
	if _, _, _, err := c.decodeQuestions([]byte(bad), questionsFor(u)); err == nil {
		t.Fatal("invalid choice accepted")
	}
}
