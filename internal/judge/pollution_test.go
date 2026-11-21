package judge

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
	"github.com/zazzcode/zazzles/internal/pipeline"
	"github.com/zazzcode/zazzles/internal/report"
)

func TestPollutionPolicy(t *testing.T) {
	fixture := filepath.Join("..", "langjs", "testdata", "pollution")
	uses := map[string]analysis.CandidateUse{}
	for _, dir := range []string{"source-writes", "lodash-old"} {
		r, err := pipeline.Analyze(filepath.Join(fixture, dir), "")
		if err != nil {
			t.Fatal(err)
		}
		for _, u := range r.Uses {
			if u.Kind == analysis.PollutionKind {
				name, _, _ := strings.Cut(u.Sink.Text, "(")
				uses[name] = u
			}
		}
	}
	for _, tt := range []struct {
		name, witness, control, bypass, coverage, status, blocker string
	}{
		{"raw write", "merge", "vulnerable", "not_applicable", "incomplete", "confirmed_vulnerability", ""},
		{"verified library write", "lodash.merge", "vulnerable", "not_applicable", "incomplete", "confirmed_vulnerability", ""},
		{"partial guard has open route", "partial", "vulnerable", "bypass_identified", "incomplete", "confirmed_vulnerability", ""},
		{"partial guard rejects protected answer", "partial", "protected", "no_bypass", "complete", "needs_evidence", "pollution_answers_inconsistent"},
		{"complete guard rejects bypass answer", "guarded", "vulnerable", "bypass_identified", "incomplete", "needs_evidence", "pollution_bypass_unsupported"},
		{"raw path rejects protected answer", "merge", "protected", "no_bypass", "complete", "needs_evidence", "pollution_answers_inconsistent"},
		{"complete key guard", "guarded", "protected", "no_bypass", "complete", "protected_for_claim", ""},
		{"own property guard", "own", "protected", "no_bypass", "complete", "protected_for_claim", ""},
		{"fresh null prototype", "Object.create", "protected", "no_bypass", "complete", "protected_for_claim", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			u, ok := uses[tt.witness]
			if !ok {
				t.Fatalf("missing parsed witness %s", tt.witness)
			}
			transport := pollutionTestTransport(func(r *http.Request) (*http.Response, error) {
				var request struct {
					Input     string `json:"input"`
					Questions []struct {
						Name string `json:"name"`
					} `json:"questions"`
				}
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil || !strings.Contains(request.Input, `"pollution"`) || len(request.Questions) != 3 {
					t.Errorf("unexpected request: %v %+v", err, request.Questions)
				}
				var response bytes.Buffer
				_ = json.NewEncoder(&response).Encode(map[string]any{"model": "fixture-model", "answers": []map[string]string{
					{"type": "choice", "name": "prototype_key_control", "choice": tt.control},
					{"type": "choice", "name": "key_guard_bypass", "choice": tt.bypass},
					{"type": "choice", "name": "protection_coverage", "choice": tt.coverage},
				}})
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(&response)}, nil
			})
			client, err := New("openai", "fixture-model", "fixture-key")
			if err != nil {
				t.Fatal(err)
			}
			client.UseEndpoint("https://test.invalid/decisions", &http.Client{Transport: transport})
			a, trace := client.AssessTrace(context.Background(), u)
			if a.Status != "completed" || a.FindingStatus != tt.status || a.QuestionVersion != analysispacks.PollutionProtocol {
				t.Fatalf("assessment: %+v", a)
			}
			if tt.blocker != "" && !slices.ContainsFunc(a.BlockingGaps, func(g analysis.Gap) bool { return g.Kind == tt.blocker }) {
				t.Fatalf("missing blocker %s: %+v", tt.blocker, a.BlockingGaps)
			}
			replay := client.Replay(u, trace)
			if replay.RequestDigest != a.RequestDigest || replay.FindingStatus != a.FindingStatus || replay.Protection != a.Protection || replay.Status != a.Status {
				t.Fatalf("assessment changed on replay: %+v", replay)
			}
			u.Assessment = a
			r := &analysis.AnalysisReport{Uses: []analysis.CandidateUse{u}}
			report.Enrich(r)
			if len(r.Findings) != 1 || r.Findings[0].Status != tt.status || !slices.Equal(r.Findings[0].TypeIDs, []string{analysis.PollutionFinding}) {
				t.Fatalf("published finding: %+v", r.Findings)
			}
			sarif, err := json.Marshal(report.SARIF(r))
			if err != nil || !strings.Contains(string(sarif), `"ruleId":"scan/prototype-pollution"`) || !strings.Contains(string(sarif), "CWE-1321") {
				t.Fatalf("SARIF missing pollution rule: %v", err)
			}
		})
	}
}

type pollutionTestTransport func(*http.Request) (*http.Response, error)

func (f pollutionTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
