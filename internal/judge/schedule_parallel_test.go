package judge

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

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

func (s *scheduleStub) client(t testing.TB) *Client {
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

var scheduleReports = struct {
	sync.Mutex
	parsed map[[2]int]*analysis.AnalysisReport
}{parsed: map[[2]int]*analysis.AnalysisReport{}}

// scheduleSQLReport parses groups distinct SQL handlers, each registered on
// members routes, so every group is one equivalence signature. Parses are
// memoized; each caller gets its own Uses and Limitations, which the scheduler
// replaces or appends but never mutates in place.
func scheduleSQLReport(t *testing.T, groups, members int) *analysis.AnalysisReport {
	t.Helper()
	scheduleReports.Lock()
	defer scheduleReports.Unlock()
	key := [2]int{groups, members}
	if scheduleReports.parsed[key] == nil {
		scheduleReports.parsed[key] = parseScheduleSQLReport(t, groups, members)
	}
	r := *scheduleReports.parsed[key]
	r.Uses = append([]analysis.CandidateUse(nil), r.Uses...)
	r.Limitations = append([]string(nil), r.Limitations...)
	return &r
}

func parseScheduleSQLReport(t testing.TB, groups, members int) *analysis.AnalysisReport {
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
// testdata/schedule_serial; they were captured from the pre-change serial
// scheduler and regenerated when only account failures and outages halt.
// A 400 fails one candidate; a 401 stops the scan.
var serialScenarios = []scheduleScenario{
	{name: "success", groups: 1, members: 1, limit: 10, limits: &Limits{}},
	{name: "equivalent_reuse", groups: 1, members: 5, limit: 1, limits: &Limits{}},
	{name: "leader_failure_member_fallback", groups: 2, members: 3, limit: 10, status: failOrdinal(1, http.StatusBadRequest)},
	{name: "leader_failure_halts", groups: 3, members: 2, limit: 10, limits: &Limits{}, status: failOrdinal(1, http.StatusUnauthorized)},
	{name: "malformed_response_continues", groups: 3, members: 1, limit: 10, limits: &Limits{}, malformed: func(n int) bool { return n == 2 }},
	{name: "limit_exhaustion", groups: 5, members: 2, limit: 3, limits: &Limits{}},
	{name: "halt_with_binding_limit", groups: 6, members: 1, limit: 3, limits: &Limits{}, status: failOrdinal(2, http.StatusUnauthorized)},
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

func (sc scheduleScenario) options(limit, concurrency int, save func(string, DecisionTrace) error) ScheduleOptions {
	return ScheduleOptions{Limit: limit, Concurrency: concurrency, SkippedFamilies: sc.skip, OnlyFamilies: sc.only, SaveTrace: save}
}

func runScheduleScenario(t *testing.T, sc scheduleScenario, stub *scheduleStub, concurrency int) scheduleOutcome {
	t.Helper()
	c, r, opts := prepareScheduleScenario(t, sc, stub, concurrency)
	return runPrepared(t, c, r, opts, stub)
}

// prepareScheduleScenario builds the report, stub client and options; traces
// are collected into the returned options' SaveTrace.
func prepareScheduleScenario(t *testing.T, sc scheduleScenario, stub *scheduleStub, concurrency int) (*Client, *analysis.AnalysisReport, ScheduleOptions) {
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
	return c, r, sc.options(sc.limit, concurrency, nil)
}

func runPrepared(t *testing.T, c *Client, r *analysis.AnalysisReport, opts ScheduleOptions, stub *scheduleStub) scheduleOutcome {
	t.Helper()
	var mu sync.Mutex
	traces := map[string]DecisionTrace{}
	var savedOrder []string
	opts.SaveTrace = func(id string, trace DecisionTrace) error {
		mu.Lock()
		defer mu.Unlock()
		if _, dup := traces[id]; dup {
			t.Errorf("trace %s saved twice", id)
		}
		traces[id] = trace
		savedOrder = append(savedOrder, id)
		return nil
	}
	failed := c.AssessScheduled(context.Background(), r, opts)
	assertSavedInPriorityOrder(t, r, savedOrder)
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
			got := marshalOutcome(t, runScheduleScenario(t, sc, &scheduleStub{}, 1))
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

// assertSavedInPriorityOrder checks that SaveTrace ran in priority order.
func assertSavedInPriorityOrder(t *testing.T, r *analysis.AnalysisReport, saved []string) {
	t.Helper()
	rank := map[string]int{}
	order := make([]int, len(r.Uses))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(i, j int) bool {
		return securitySinkPriority(r.Uses[order[i]]) < securitySinkPriority(r.Uses[order[j]])
	})
	for k, i := range order {
		rank[r.Uses[i].ID] = k
	}
	for k := 1; k < len(saved); k++ {
		if rank[saved[k-1]] >= rank[saved[k]] {
			t.Fatalf("SaveTrace out of priority order: %s before %s", saved[k-1], saved[k])
		}
	}
}

// TestScheduleParallelMatchesSerialGolden runs every AC1 scenario whose stub
// does not depend on request arrival order at N=4 against the same golden.
func TestScheduleParallelMatchesSerialGolden(t *testing.T) {
	for _, sc := range serialScenarios {
		if sc.status != nil || sc.malformed != nil {
			continue // ordinal-keyed failures are arrival-order dependent above N=1
		}
		t.Run(sc.name, func(t *testing.T) {
			out := runScheduleScenario(t, sc, &scheduleStub{}, 4)
			// LimitSummary names the concurrency by design; everything else must match.
			out.Report = bytes.ReplaceAll(out.Report, []byte("up to 4 assessment requests in flight"), []byte("requests remain sequential"))
			got := marshalOutcome(t, out)
			want, err := os.ReadFile(filepath.Join("testdata", "schedule_serial", sc.name+".json"))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatal("N=4 output differs from the serial golden")
			}
		})
	}
}

// TestScheduleParallelEquivalence is AC2: with a response fixed per request and
// a random per-request delay, N=4 output equals N=1 output for 20 seeds.
func TestScheduleParallelEquivalence(t *testing.T) {
	sc := scheduleScenario{name: "equivalence", groups: 6, members: 2, claims: true, limit: 5, limits: &Limits{}}
	deterministic := func(seed int64) *scheduleStub {
		rng := rand.New(rand.NewSource(seed))
		var mu sync.Mutex
		return &scheduleStub{
			usage: func(body []byte) int { return 10 + int(sha256.Sum256(body)[0]%7) },
			before: func(int, []byte) {
				mu.Lock()
				d := time.Duration(rng.Intn(3000)) * time.Microsecond
				mu.Unlock()
				time.Sleep(d)
			},
		}
	}
	serial := marshalOutcome(t, runScheduleScenario(t, sc, deterministic(0), 1))
	for seed := int64(1); seed <= 20; seed++ {
		if got := marshalOutcome(t, runScheduleScenario(t, sc, deterministic(seed), 4)); !bytes.Equal(got, serial) {
			t.Fatalf("seed %d: N=4 output differs from N=1", seed)
		}
	}
}

// TestScheduleDispatchesConcurrently is AC3: with N=4, four distinct
// signatures are in flight together, never more than four, and each
// equivalent group sends one request.
func TestScheduleDispatchesConcurrently(t *testing.T) {
	const n, groups = 4, 8
	var mu sync.Mutex
	batches := map[int]chan struct{}{}
	arrived := map[int]int{}
	stub := &scheduleStub{}
	stub.before = func(k int, _ []byte) {
		batch := (k - 1) / n
		mu.Lock()
		if batches[batch] == nil {
			batches[batch] = make(chan struct{})
		}
		ch := batches[batch]
		arrived[batch]++
		if arrived[batch] == n {
			close(ch)
		}
		mu.Unlock()
		select {
		case <-ch:
		case <-time.After(10 * time.Second):
			t.Errorf("request %d: %d requests never reached the stub together", k, n)
		}
	}
	sc := scheduleScenario{name: "concurrency", groups: groups, members: 3, limit: 10, limits: &Limits{}}
	out := runScheduleScenario(t, sc, stub, n)
	if out.Requests != groups {
		t.Fatalf("requests=%d, want one per equivalent group (%d)", out.Requests, groups)
	}
	if stub.maxConc != n {
		t.Fatalf("max in flight=%d, want %d", stub.maxConc, n)
	}
	if out.Failed {
		t.Fatal("concurrent run reported incomplete assessments")
	}
}

// TestScheduleCapUsesPriorityLeaders is AC4: ten distinct signatures and
// Limit=3 send exactly the first three leaders in priority order.
func TestScheduleCapUsesPriorityLeaders(t *testing.T) {
	stub := &scheduleStub{}
	sc := scheduleScenario{name: "cap", groups: 10, members: 1, limit: 3, limits: &Limits{}}
	c, r, opts := prepareScheduleScenario(t, sc, stub, 4)
	want := map[string]bool{}
	for _, u := range r.Uses[:3] { // every use is priority 0, so priority order is report order
		trace, err := c.Preview(u)
		if err != nil {
			t.Fatal(err)
		}
		want[string(trace.Request)] = true
	}
	runPrepared(t, c, r, opts, stub)
	if len(stub.bodies) != 3 {
		t.Fatalf("requests=%d, want 3", len(stub.bodies))
	}
	for _, body := range stub.bodies {
		if !want[string(body)] {
			t.Fatal("a request outside the first three priority leaders reached HTTP")
		}
	}
	for k, u := range r.Uses {
		if k < 3 && u.Assessment.Status != "completed" || k >= 3 && (u.Assessment.Status != "not_run" || u.Assessment.Reason != "judge request limit reached") {
			t.Fatalf("use %d: %+v", k, u.Assessment)
		}
	}
}

// TestScheduleHaltStopsAcquisition is AC5: request #2 fails; no request is
// acquired after the failure is recorded, at most 2+(N-1) requests are sent,
// and every candidate without an answer carries the limiter's stop reason.
func TestScheduleHaltStopsAcquisition(t *testing.T) {
	for _, n := range []int{1, 4} {
		t.Run(fmt.Sprintf("N=%d", n), func(t *testing.T) {
			stub := &scheduleStub{status: failOrdinal(2, http.StatusUnauthorized)}
			sc := scheduleScenario{name: "halt", groups: 10, members: 2, limit: 10, limits: &Limits{}}
			c, r, opts := prepareScheduleScenario(t, sc, stub, n)
			if n > 1 {
				// Hold the other in-flight requests until the failure is recorded,
				// so the bound is checked at its widest.
				stub.before = func(k int, _ []byte) {
					deadline := time.Now().Add(10 * time.Second)
					for k != 2 && c.limiter.haltReason() == "" && time.Now().Before(deadline) {
						time.Sleep(time.Millisecond)
					}
				}
			}
			out := runPrepared(t, c, r, opts, stub)
			if out.Requests > 2+(n-1) || c.limiter.attempts != out.Requests {
				t.Fatalf("requests=%d attempts=%d, want at most %d and equal", out.Requests, c.limiter.attempts, 2+(n-1))
			}
			failures := 0
			for _, u := range r.Uses {
				switch {
				case u.Assessment.Status == "completed":
				case u.Assessment.Reason == "judge HTTP 401":
					failures++
				case u.Assessment.Reason != "judge limit: stopped after decision model account or credentials rejected (judge HTTP 401)":
					t.Fatalf("%s: %+v", u.ID, u.Assessment)
				}
			}
			if failures != 1 || !out.Failed {
				t.Fatalf("failures=%d failed=%v", failures, out.Failed)
			}
		})
	}
}

// TestSchedulePacingUnderConcurrency is AC6: with an injected clock, RPM=2
// and N=4 never admit more than two requests in any rolling minute, and the
// TPM reservation refusal keeps its message.
func TestSchedulePacingUnderConcurrency(t *testing.T) {
	stub := &scheduleStub{}
	sc := scheduleScenario{name: "pacing", groups: 7, members: 2, limit: 10, limits: &Limits{RPM: 2}}
	c, r, opts := prepareScheduleScenario(t, sc, stub, 4)
	var clockMu sync.Mutex
	clock := time.Unix(0, 0)
	admitted := map[uint64]time.Time{}
	observe := func() { // caller holds c.limiter.mu
		for _, e := range c.limiter.window {
			admitted[e.id] = e.at
		}
	}
	c.limiter.now = func() time.Time {
		observe() // every window entry is seen before any later prune
		clockMu.Lock()
		defer clockMu.Unlock()
		return clock
	}
	c.limiter.wait = func(ctx context.Context, d time.Duration) error {
		clockMu.Lock()
		clock = clock.Add(d)
		clockMu.Unlock()
		return ctx.Err()
	}
	out := runPrepared(t, c, r, opts, stub)
	c.limiter.mu.Lock()
	observe()
	c.limiter.mu.Unlock()
	if out.Failed || out.Requests != sc.groups || len(admitted) != sc.groups {
		t.Fatalf("failed=%v requests=%d admitted=%d", out.Failed, out.Requests, len(admitted))
	}
	var times []time.Time
	for _, at := range admitted {
		times = append(times, at)
	}
	sort.Slice(times, func(i, j int) bool { return times[i].Before(times[j]) })
	for i := range times {
		inWindow := 0
		for _, at := range times[i:] {
			if at.Sub(times[i]) < time.Minute {
				inWindow++
			}
		}
		if inWindow > 2 {
			t.Fatalf("%d requests admitted in the minute from %v", inWindow, times[i])
		}
	}

	tpm := scheduleScenario{name: "tpm", groups: 3, members: 1, limit: 10, limits: &Limits{TPM: 1}}
	tpmStub := &scheduleStub{}
	c, r, opts = prepareScheduleScenario(t, tpm, tpmStub, 4)
	runPrepared(t, c, r, opts, tpmStub)
	for _, u := range r.Uses {
		if u.Assessment.Reason != "judge limit: request token reservation exceeds the configured TPM window" {
			t.Fatal(u.Assessment)
		}
	}
	if tpmStub.count() != 0 {
		t.Fatal("a refused reservation reached HTTP")
	}
}

// BenchmarkScheduleLatency produces the AC9 stub timing table: 40 distinct
// signatures at a fixed 200 ms stub latency for N = 1, 2, 4 and 8:
//
//	go test ./internal/judge -run '^$' -bench BenchmarkScheduleLatency -benchtime 1x
func BenchmarkScheduleLatency(b *testing.B) {
	r := parseScheduleSQLReport(b, 40, 1)
	for _, n := range []int{1, 2, 4, 8} {
		b.Run(fmt.Sprintf("N=%d", n), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				stub := &scheduleStub{before: func(int, []byte) { time.Sleep(200 * time.Millisecond) }}
				c := stub.client(b)
				run := *r
				run.Uses = append([]analysis.CandidateUse(nil), r.Uses...)
				run.Limitations = nil
				b.StartTimer()
				c.AssessScheduled(context.Background(), &run, ScheduleOptions{Limit: 40, Concurrency: n})
				b.StopTimer()
				if stub.count() != 40 || stub.maxConc > n {
					b.Fatalf("requests=%d max in flight=%d", stub.count(), stub.maxConc)
				}
			}
		})
	}
}
