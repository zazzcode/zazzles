package judge

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
	"github.com/zazzcode/zazzles/internal/pipeline"
	"github.com/zazzcode/zazzles/internal/report"
)

func selectedSQLUse(t *testing.T) analysis.CandidateUse {
	t.Helper()
	r := sqlFixture(t, "server.ts", `import express from 'express';import {Sequelize} from 'sequelize';const app=express();const db=new Sequelize('sqlite::memory:');app.get('/sql',(req,res)=>db.query('SELECT '+req.query.id));`)
	for _, u := range r.Uses {
		if u.Kind == "sql_query_candidate" {
			return u
		}
	}
	t.Fatal("no SQL candidate")
	return analysis.CandidateUse{}
}
func sqlFixture(t *testing.T, name, source string) *analysis.AnalysisReport {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, name), []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := pipeline.Analyze(root, name)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestSQLComponentPayload(t *testing.T) {
	u := selectedSQLUse(t)
	for _, provider := range []string{"openai", "jev"} {
		t.Run(provider, func(t *testing.T) {
			c, _ := New(provider, "fixture-model", "never-persist-key")
			trace, err := c.Preview(u)
			if err != nil {
				t.Fatal(err)
			}
			var body map[string]any
			if err := json.Unmarshal(trace.Request, &body); err != nil {
				t.Fatal(err)
			}
			key := "input"
			if provider == "jev" {
				key = "state"
			}
			input := body[key].(string)
			for _, bad := range []string{"Cross-site scripting", "NoSQL", "## Logging", "TestSQL", "never-persist-key", "internal/parse"} {
				if strings.Contains(input, bad) {
					t.Fatalf("unrelated material leaked: %s", bad)
				}
			}
			for _, want := range []string{"analysis_components", "sequelize-raw-query-v1", "control_flow", "TypeScript types are not runtime validation", "An ORM search value"} {
				if !strings.Contains(input, want) {
					t.Fatalf("missing selected context: %s", want)
				}
			}
			if trace.QuestionVersion != analysispacks.SQLProtocol || trace.RequestDigest == "" || trace.Components == nil {
				t.Fatal("SQL provenance missing")
			}

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				var received map[string]any
				if err := json.NewDecoder(req.Body).Decode(&received); err != nil {
					t.Error(err)
					w.WriteHeader(400)
					return
				}
				if !reflect.DeepEqual(received, body) {
					t.Error("transport changed selected payload")
				}
				if provider == "openai" {
					w.Write(sqlResponse(u, "fixture-model", "insufficient", "vulnerable"))
					return
				}
				answers := map[string]any{}
				values := map[string]string{"validation": "uncertain", "protection": "insufficient", "injection_protection": "vulnerable"}
				for name, value := range values {
					answers[name] = map[string]string{"type": "choice", "choice": value}
				}
				json.NewEncoder(w).Encode(map[string]any{"model": "fixture-model", "answers": answers})
			}))
			defer server.Close()
			c.endpoint = server.URL
			c.http = server.Client()
			assessed, saved := c.AssessTrace(context.Background(), u)
			if assessed.Status != "completed" || assessed.FindingStatus != "confirmed_vulnerability" || len(assessed.Answers) != 3 {
				t.Fatalf("%s selected SQL transport/decoder failed: %+v", provider, assessed)
			}
			if replay := c.Replay(u, saved); replay.Status != "completed" || !sameJSON(replay, assessed) {
				t.Fatalf("%s selected SQL replay differs: %+v", provider, replay)
			}

			t.Logf("%s request=%d bytes components=%d", provider, trace.RequestBytes, len(u.Components.Components))
		})
	}
}

func TestSQLSelectionFailurePipeline(t *testing.T) {
	u := selectedSQLUse(t)
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(500) }))
	defer server.Close()
	c, _ := New("openai", "fixture-model", "key")
	c.endpoint = server.URL
	c.http = server.Client()
	for _, change := range []func(*analysis.CandidateUse){
		func(v *analysis.CandidateUse) { v.Components = nil },
		func(v *analysis.CandidateUse) { v.APIModel = nil },
		func(v *analysis.CandidateUse) { v.Sink.Span.File = "sink.go" },
		func(v *analysis.CandidateUse) { s := *v.Components; s.Digest = "wrong"; v.Components = &s },
	} {
		v := u
		change(&v)
		got := c.Assess(context.Background(), v)
		if got.Status != "failed" || got.Reason == "" || got.FindingStatus == "protected_for_claim" {
			t.Fatalf("selection failure hidden: %+v", got)
		}
	}
	if calls != 0 {
		t.Fatalf("selection failure made %d HTTP calls", calls)
	}
}

func TestSQLComponentLimits(t *testing.T) {
	u := selectedSQLUse(t)
	u.Sink.Text = strings.Repeat("x", 100<<10)
	c, _ := New("openai", "fixture-model", "key")
	calls := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++ }))
	defer s.Close()
	c.endpoint = s.URL
	c.http = s.Client()
	got := c.Assess(context.Background(), u)
	if calls != 0 || got.Status != "not_run" || !strings.HasPrefix(got.Reason, evidenceTooLarge+":") {
		t.Fatalf("oversize request not rejected: %+v calls=%d", got, calls)
	}
}

func sqlResponse(u analysis.CandidateUse, model, protection, injection string) []byte {
	answers := []map[string]string{}
	values := map[string]string{"validation": "uncertain", "protection": protection, "injection_protection": injection}
	for _, q := range questionsFor(u) {
		answers = append(answers, map[string]string{"type": "choice", "name": q.name, "choice": values[q.name]})
	}
	b, _ := json.Marshal(map[string]any{"model": model, "answers": answers})
	return b
}

func TestSQLComponentReplay(t *testing.T) {
	u := selectedSQLUse(t)
	c, _ := New("openai", "fixture-model", "key")
	trace, err := c.Preview(u)
	if err != nil {
		t.Fatal(err)
	}
	trace.HTTPStatus = 200
	trace.Response = sqlResponse(u, "fixture-model", "insufficient", "vulnerable")
	if got := c.Replay(u, trace); got.Status != "completed" || got.RequestDigest != trace.RequestDigest {
		t.Fatalf("exact replay failed: %+v", got)
	}
	for _, text := range []string{"analysis_guidelines", "Sequelize query takes", "injection_protection", "Request values", "version", "fixture-model"} {
		changed := trace
		request := string(trace.Request)
		if !strings.Contains(request, text) {
			if text == "Request values" {
				text = "SELECT "
			} else {
				t.Fatalf("mutation absent: %s", text)
			}
		}
		changed.Request = []byte(strings.Replace(request, text, text+" changed", 1))
		if got := c.Replay(u, changed); got.Status != "failed" {
			t.Fatalf("changed %s reused stale answers", text)
		}
	}
	changed := trace
	changed.QuestionVersion = "old"
	if c.Replay(u, changed).Status != "failed" {
		t.Fatal("old protocol replayed")
	}
	v := u
	v.Sink.Text += " changed"
	if c.Replay(v, trace).Status != "failed" {
		t.Fatal("changed evidence replayed")
	}
}

func TestSQLComponentPipelineParity(t *testing.T) {
	for _, language := range []string{"javascript", "typescript"} {
		for _, entry := range []string{"graphql", "grpc"} {
			t.Run(language+"/"+entry, func(t *testing.T) {
				r, err := pipeline.Analyze(fixtureRoot(language+"/"+entry), "")
				if err != nil {
					t.Fatal(err)
				}
				assessed := 0
				s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
					var body struct{ Input string }
					json.NewDecoder(req.Body).Decode(&body)
					injection, practice := "vulnerable", "insufficient"
					if strings.Contains(body.Input, `"field":"bound"`) || strings.Contains(body.Input, `"field":"guarded"`) || strings.Contains(body.Input, `"field":"unknown"`) || strings.Contains(body.Input, `"method":"Bound"`) || strings.Contains(body.Input, `"method":"Guarded"`) || strings.Contains(body.Input, `"method":"Unknown"`) || strings.Contains(body.Input, `"method":"UnknownGuard"`) {
						injection, practice = "protected", "sufficient"
					}
					w.Write(sqlResponse(r.Uses[0], "fixture-model", practice, injection))
				}))
				defer s.Close()
				c, _ := New("openai", "fixture-model", "key")
				c.endpoint = s.URL
				c.http = s.Client()
				for i := range r.Uses {
					u := &r.Uses[i]
					if u.Kind != "sql_query_candidate" {
						continue
					}
					if u.Components == nil || u.Components.Failure != "" {
						t.Fatalf("selection: %+v", u.Components)
					}
					a, tr := c.AssessTrace(context.Background(), *u)
					if a.Status != "completed" {
						t.Fatalf("SQL not assessed: %+v", a)
					}

					field := ""
					if u.EntryFacts.GraphQL != nil {
						field = u.EntryFacts.GraphQL.Field
					} else {
						field = strings.ToLower(u.EntryFacts.GRPC.Method)
					}
					want := map[string]string{"raw": "confirmed_vulnerability", "open": "confirmed_vulnerability", "lookup": "confirmed_vulnerability", "bound": "protected_for_claim", "guarded": "protected_for_claim", "unknown": "needs_evidence", "unknownguard": "needs_evidence"}[field]
					if want == "" || a.FindingStatus != want {
						t.Fatalf("%s: result=%s want=%s", field, a.FindingStatus, want)
					}
					if len(u.Completeness.Blockers) > 0 && a.FindingStatus != "needs_evidence" {
						t.Fatal("optimistic answer bypassed missing evidence")
					}
					if c.Replay(*u, tr).Status != "completed" {
						t.Fatal("pipeline replay failed")
					}
					u.Assessment = a
					assessed++
				}
				if assessed != 6 {
					t.Fatal("no actual SQL pipeline")
				}
				assertComponentReportParity(t, r)
				report.Enrich(r)
				before, _ := json.Marshal(r.Findings)
				var html bytes.Buffer
				if err := report.HTML(&html, r); err != nil {
					t.Fatal(err)
				}
				sarif := report.SARIF(r)
				after, _ := json.Marshal(r.Findings)
				if !bytes.Equal(before, after) || html.Len() == 0 || len(sarif["runs"].([]any)) != 1 {
					t.Fatal("report semantics changed during export")
				}
				raw, _ := json.Marshal(r)
				var saved analysis.AnalysisReport
				if err := json.Unmarshal(raw, &saved); err != nil {
					t.Fatal(err)
				}
				if saved.Uses[0].ID != r.Uses[0].ID {
					t.Fatal("saved association changed")
				}
			})
		}
	}
}

func assertComponentReportParity(t *testing.T, r *analysis.AnalysisReport) {
	t.Helper()
	report.Enrich(r)
	if len(r.Findings) != len(r.Uses) {
		t.Fatal("canonical record count differs from candidates")
	}
	var html bytes.Buffer
	if err := report.HTML(&html, r); err != nil {
		t.Fatal(err)
	}
	run := report.SARIF(r)["runs"].([]any)[0].(map[string]any)
	results := run["results"].([]any)
	// Records grouped into a representative row stay in JSON; the views show
	// one row per group.
	var shown []int
	for i, f := range r.Findings {
		if f.GroupedInto == "" {
			shown = append(shown, i)
		}
	}
	if len(results) != len(shown) || strings.Count(html.String(), `<article class="finding"`) != len(shown) {
		t.Fatal("JSON/HTML/SARIF record counts differ")
	}
	statuses := map[string]int{}
	for k, i := range shown {
		f := r.Findings[i]
		statuses[f.Status]++
		props := results[k].(map[string]any)["properties"].(map[string]any)
		if !reflect.DeepEqual(props["scan.finding"], f) || !reflect.DeepEqual(props["scan.assessment"], r.Uses[i].Assessment) {
			t.Fatal("SARIF changed canonical finding or raw assessment")
		}
	}
	for status, count := range statuses {
		if strings.Count(html.String(), `status-`+status+`"`) != count {
			t.Fatalf("HTML status %s count differs from JSON: want %d", status, count)
		}
	}
	data, _ := json.Marshal(r)
	var saved analysis.AnalysisReport
	if err := json.Unmarshal(data, &saved); err != nil {
		t.Fatal(err)
	}
	for i, u := range r.Uses {
		if !sameJSON(saved.Uses[i].Assessment, u.Assessment) || !reflect.DeepEqual(saved.Uses[i].Components, u.Components) || saved.Uses[i].Sink != u.Sink {
			t.Fatal("JSON lost source, selected components or raw assessment")
		}
	}
}

func TestSQLHTTPComponentAnswers(t *testing.T) {
	for _, answer := range []struct{ injection, want string }{{"vulnerable", "confirmed_vulnerability"}, {"protected", "protected_for_claim"}, {"unknown", "needs_evidence"}, {"not_applicable", "not_applicable"}} {
		t.Run(answer.injection, func(t *testing.T) {
			u := selectedSQLUse(t)
			c, _ := New("openai", "fixture-model", "key")
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write(sqlResponse(u, "fixture-model", "insufficient", answer.injection))
			}))
			defer s.Close()
			c.endpoint = s.URL
			c.http = s.Client()
			a, _ := c.AssessTrace(context.Background(), u)
			if a.Status != "completed" || a.FindingStatus != answer.want || a.Answers["protection"] != "insufficient" || a.Answers["validation"] != "uncertain" {
				t.Fatalf("independent facets lost: %+v", a)
			}
		})
	}
}

func sameJSON(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}
