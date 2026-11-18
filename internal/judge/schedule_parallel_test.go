package judge

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/pipeline"
)

var updateScheduleGolden = flag.Bool("update-schedule-golden", false, "rewrite the serial scheduler goldens in testdata/schedule_serial")

// scheduleAnswers answers every question the scenario families ask.
var scheduleAnswers = map[string]string{
	"validation": "uncertain", "protection": "insufficient", "injection_protection": "vulnerable",
	"output_context": "html_text", "encoding_adequacy": "not_present", "sanitizer_effectiveness": "absent", "xss_all_paths_protected": "no", "xss_exposure": "vulnerable",
	"data_class": "credential", "content_exposure": "yes", "redaction": "no", "log_exposure": "vulnerable",
}

// scheduleStub is a local decision endpoint. Every hook sees the 1-based
// request ordinal and the exact request body; the stub is safe for concurrent use.
type scheduleStub struct {
	mu       sync.Mutex
	requests int
	status   func(n int, body []byte) int // non-200 fails the request
	usage    func(body []byte) int        // reported input tokens; default 11
	before   func(n int, body []byte)     // runs before answering, outside the lock
	broken   func(n int) bool             // answers 200 with an undecodable body
	inFlight int
	maxConc  int
	bodies   [][]byte
}

func (s *scheduleStub) client(t *testing.T) *Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var raw bytes.Buffer
		if _, err := raw.ReadFrom(req.Body); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		body := raw.Bytes()
		s.mu.Lock()
		s.requests++
		n := s.requests
		s.inFlight++
		if s.inFlight > s.maxConc {
			s.maxConc = s.inFlight
		}
		s.bodies = append(s.bodies, body)
		s.mu.Unlock()
		defer func() {
			s.mu.Lock()
			s.inFlight--
			s.mu.Unlock()
		}()
		if s.before != nil {
			s.before(n, body)
		}
		if s.status != nil {
			if code := s.status(n, body); code != http.StatusOK {
				w.WriteHeader(code)
				return
			}
		}
		if s.broken != nil && s.broken(n) {
			_, _ = w.Write([]byte(`{"model":"fixture-model","answers":"not-a-list"}`))
			return
		}
		var parsed struct {
			Questions []struct {
				Name string `json:"name"`
			} `json:"questions"`
		}
		if err := json.Unmarshal(body, &parsed); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		list := []map[string]string{}
		for _, q := range parsed.Questions {
			list = append(list, map[string]string{"name": q.Name, "type": "choice", "choice": scheduleAnswers[q.Name]})
		}
		tokens := 11
		if s.usage != nil {
			tokens = s.usage(body)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"model": "fixture-model", "answers": list, "usage": map[string]int{"input_tokens": tokens, "output_tokens": 3}})
	}))
	t.Cleanup(server.Close)
	c, err := New("openai", "fixture-model", "synthetic-test-key")
	if err != nil {
		t.Fatal(err)
	}
	c.UseEndpoint(server.URL, server.Client())
	return c
}

func (s *scheduleStub) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requests
}

// scheduleSQLReport parses groups distinct SQL handlers, each registered on
// members routes, so every group is one equivalence signature.
func scheduleSQLReport(t *testing.T, groups, members int) *analysis.AnalysisReport {
	t.Helper()
	var src strings.Builder
	src.WriteString(`import express from 'express';import {Sequelize} from 'sequelize';const app=express();const db=new Sequelize('sqlite::memory:');`)
	for g := 0; g < groups; g++ {
		fmt.Fprintf(&src, "function h%d(req,res){db.query('SELECT '+req.query.p%d)}\n", g, g)
	}
	for g := 0; g < groups; g++ {
		for m := 0; m < members; m++ {
			fmt.Fprintf(&src, "app.get('/g%d/m%d',h%d);", g, m, g)
		}
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "server.ts"), []byte(src.String()), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := pipeline.Analyze(root, "server.ts")
	if err != nil {
		t.Fatal(err)
	}
	r.Root = "<fixture>"
	var uses []analysis.CandidateUse
	for _, u := range r.Uses {
		if u.Kind == "sql_query_candidate" {
			uses = append(uses, u)
		}
	}
	if len(uses) != groups*members {
		t.Fatalf("sql uses=%d, want %d", len(uses), groups*members)
	}
	r.Uses = uses
	return r
}

// familyClaims adds an XSS claim, a logging claim and two non-assessable records.
func familyClaims() []analysis.CandidateUse {
	xss := xssClaim("raw")
	xss.ID = "xss-claim"
	logging := logClaim("log_sensitive_field_hint")
	logging.ID = "logging-claim"
	return []analysis.CandidateUse{{ID: "outbound-observation", Kind: "outbound_http_candidate"}, xss, {ID: "api-data", Kind: "xss_data_candidate"}, logging}
}

type scheduleScenario struct {
	name            string
	groups, members int
	claims          bool
	limit           int
	limits          *Limits // nil leaves the client without a limiter
	requestLimit    int     // 0 keeps the production request limit
	skip, only      []string
	status          func(n int, body []byte) int
	malformed       func(n int) bool
}

// serialScenarios are the AC1 scenarios. Their N=1 outputs are pinned in
// testdata/schedule_serial and were captured from the pre-change serial scheduler.
var serialScenarios = []scheduleScenario{
	{name: "success", groups: 1, members: 1, limit: 10, limits: &Limits{}},
	{name: "equivalent_reuse", groups: 1, members: 5, limit: 1, limits: &Limits{}},
	{name: "leader_failure_member_fallback", groups: 2, members: 3, limit: 10, status: failOrdinal(1, http.StatusInternalServerError)},
	{name: "leader_failure_halts", groups: 3, members: 2, limit: 10, limits: &Limits{}, status: failOrdinal(1, http.StatusInternalServerError)},
	{name: "malformed_response_halts", groups: 3, members: 1, limit: 10, limits: &Limits{}, malformed: func(n int) bool { return n == 2 }},
	{name: "limit_exhaustion", groups: 5, members: 2, limit: 3, limits: &Limits{}},
	{name: "halt_with_binding_limit", groups: 6, members: 1, limit: 3, limits: &Limits{}, status: failOrdinal(2, http.StatusTooManyRequests)},
	{name: "skipped_families", groups: 2, members: 2, claims: true, limit: 10, limits: &Limits{}, skip: []string{"sql"}},
	{name: "only_families", groups: 2, members: 2, claims: true, limit: 10, limits: &Limits{}, only: []string{"logging"}},
	{name: "priority_and_observations", groups: 2, members: 1, claims: true, limit: 2, limits: &Limits{}},
	{name: "size_limit_preflight", groups: 3, members: 2, limit: 1, limits: &Limits{}, requestLimit: 1024},
	{name: "tpm_preflight", groups: 3, members: 1, limit: 1, limits: &Limits{TPM: 1}},
}

func failOrdinal(n, code int) func(int, []byte) int {
	return func(got int, _ []byte) int {
		if got == n {
			return code
		}
		return http.StatusOK
	}
}

type scheduleOutcome struct {
	Failed   bool                     `json:"failed"`
	Requests int                      `json:"requests"`
	Report   json.RawMessage          `json:"report"`
	Traces   map[string]DecisionTrace `json:"traces"`
}

func (sc scheduleScenario) options(limit int, save func(string, DecisionTrace) error) ScheduleOptions {
	return ScheduleOptions{Limit: limit, SkippedFamilies: sc.skip, OnlyFamilies: sc.only, SaveTrace: save}
}

func runScheduleScenario(t *testing.T, sc scheduleScenario, stub *scheduleStub) scheduleOutcome {
	t.Helper()
	if sc.requestLimit > 0 {
		withRequestLimit(t, sc.requestLimit)
	}
	r := scheduleSQLReport(t, sc.groups, sc.members)
	if sc.claims {
		r.Uses = append(r.Uses, familyClaims()...)
	}
	if sc.status != nil {
		stub.status = sc.status
	}
	if sc.malformed != nil {
		stub.broken = sc.malformed
	}
	c := stub.client(t)
	if sc.limits != nil {
		if err := c.SetLimits(*sc.limits); err != nil {
			t.Fatal(err)
		}
	}
	var mu sync.Mutex
	traces := map[string]DecisionTrace{}
	save := func(id string, trace DecisionTrace) error {
		mu.Lock()
		defer mu.Unlock()
		if _, dup := traces[id]; dup {
			t.Errorf("trace %s saved twice", id)
		}
		traces[id] = trace
		return nil
	}
	failed := c.AssessScheduled(context.Background(), r, sc.options(sc.limit, save))
	if summary := c.LimitSummary(); summary != "" {
		r.Limitations = append(r.Limitations, summary)
	}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return scheduleOutcome{Failed: failed, Requests: stub.count(), Report: data, Traces: traces}
}

type goldenAssessment struct {
	ID         string              `json:"id"`
	Assessment analysis.Assessment `json:"assessment"`
}

type goldenTrace struct {
	SHA256        string `json:"sha256"`
	RequestDigest string `json:"request_digest"`
	HTTPStatus    int    `json:"http_status"`
	RequestBytes  int    `json:"request_bytes"`
}

// marshalOutcome pins the whole report and every saved trace by SHA-256 of
// their exact JSON, and keeps assessments and limitations readable for diffs.
func marshalOutcome(t *testing.T, o scheduleOutcome) []byte {
	t.Helper()
	// Decode only the scheduler-owned fields; full report validation would
	// reject the synthetic family claims, which have no entry association.
	var r struct {
		Uses []struct {
			ID         string              `json:"id"`
			Assessment analysis.Assessment `json:"assessment"`
		} `json:"uses"`
		Limitations []string `json:"limitations"`
	}
	if err := json.Unmarshal(o.Report, &r); err != nil {
		t.Fatal(err)
	}
	golden := struct {
		Failed       bool                   `json:"failed"`
		Requests     int                    `json:"requests"`
		ReportSHA256 string                 `json:"report_sha256"`
		Assessments  []goldenAssessment     `json:"assessments"`
		Limitations  []string               `json:"limitations"`
		Traces       map[string]goldenTrace `json:"traces"`
	}{Failed: o.Failed, Requests: o.Requests, ReportSHA256: sha256Hex(o.Report), Limitations: r.Limitations, Traces: map[string]goldenTrace{}}
	for _, u := range r.Uses {
		golden.Assessments = append(golden.Assessments, goldenAssessment{u.ID, u.Assessment})
	}
	for id, trace := range o.Traces {
		data, err := json.Marshal(trace)
		if err != nil {
			t.Fatal(err)
		}
		golden.Traces[id] = goldenTrace{sha256Hex(data), trace.RequestDigest, trace.HTTPStatus, trace.RequestBytes}
	}
	data, err := json.MarshalIndent(golden, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(data, '\n')
}

// TestScheduleSerialGolden is AC1: the serial scheduler output for every
// scenario is byte-identical to the captured pre-change output.
func TestScheduleSerialGolden(t *testing.T) {
	for _, sc := range serialScenarios {
		t.Run(sc.name, func(t *testing.T) {
			got := marshalOutcome(t, runScheduleScenario(t, sc, &scheduleStub{}))
			path := filepath.Join("testdata", "schedule_serial", sc.name+".json")
			if *updateScheduleGolden {
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, got, 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("serial output differs from the pre-change golden %s", path)
			}
		})
	}
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
