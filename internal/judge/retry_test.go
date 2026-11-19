package judge

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zazzcode/zazzles/internal/analysis"
)

// retryStep is how the retry stub answers one request ordinal. The zero step,
// and every ordinal past the table, answers 200 with valid answers.
type retryStep struct {
	status     int           // non-zero, non-200 status with an empty JSON body
	retryAfter string        // Retry-After header for a failure status
	hijack     bool          // close the connection without a response
	broken     bool          // 200 with an undecodable body
	delay      time.Duration // answer 200 only after this delay
}

type retryStub struct {
	mu       sync.Mutex
	steps    []retryStep
	requests int
}

func (s *retryStub) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requests
}

// client returns a stub-backed client. A nil limits leaves pacing off; otherwise
// the limiter's wait is recorded and never sleeps.
func (s *retryStub) client(t *testing.T, limits *Limits) (*Client, *[]time.Duration) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var raw bytes.Buffer
		if _, err := raw.ReadFrom(req.Body); err != nil {
			t.Error(err)
			return
		}
		s.mu.Lock()
		s.requests++
		var step retryStep
		if s.requests <= len(s.steps) {
			step = s.steps[s.requests-1]
		}
		s.mu.Unlock()
		if step.delay > 0 {
			select {
			case <-time.After(step.delay):
			case <-req.Context().Done():
				return
			}
		}
		switch {
		case step.hijack:
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			_ = conn.Close()
			return
		case step.status != 0 && step.status != http.StatusOK:
			if step.retryAfter != "" {
				w.Header().Set("Retry-After", step.retryAfter)
			}
			w.WriteHeader(step.status)
			_, _ = w.Write([]byte(`{"error":"stub"}`))
			return
		case step.broken:
			_, _ = w.Write([]byte(`{"model":"fixture-model","answers":"not-a-list"}`))
			return
		}
		var parsed struct {
			Questions []struct {
				Name string `json:"name"`
			} `json:"questions"`
		}
		if err := json.Unmarshal(raw.Bytes(), &parsed); err != nil {
			t.Error(err)
			return
		}
		list := []map[string]string{}
		for _, q := range parsed.Questions {
			list = append(list, map[string]string{"name": q.Name, "type": "choice", "choice": scheduleAnswers[q.Name]})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"model": "fixture-model", "answers": list, "usage": map[string]int{"input_tokens": 11, "output_tokens": 3}})
	}))
	t.Cleanup(server.Close)
	c, err := New("openai", "fixture-model", "synthetic-test-key")
	if err != nil {
		t.Fatal(err)
	}
	c.UseEndpoint(server.URL, server.Client())
	waits := &[]time.Duration{}
	if limits != nil {
		if err := c.SetLimits(*limits); err != nil {
			t.Fatal(err)
		}
		c.limiter.wait = func(ctx context.Context, d time.Duration) error {
			*waits = append(*waits, d)
			return ctx.Err()
		}
	}
	return c, waits
}

func retryUse(t *testing.T) analysis.CandidateUse {
	t.Helper()
	r := scheduleSQLReport(t, 1, 1)
	if len(r.Uses) == 0 {
		t.Fatal("no scheduler use")
	}
	return r.Uses[0]
}

// TestRetryRecoversOnce is AC1: one 429, 502, 503 or 504 is retried and the
// candidate completes from the second response.
func TestRetryRecoversOnce(t *testing.T) {
	use := retryUse(t)
	for _, code := range []int{http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			stub := &retryStub{steps: []retryStep{{status: code}}}
			c, waits := stub.client(t, &Limits{})
			a, trace := c.AssessTrace(context.Background(), use)
			if a.Status != "completed" || stub.count() != 2 || c.limiter.attempts != 2 {
				t.Fatalf("status=%s reason=%q requests=%d attempts=%d", a.Status, a.Reason, stub.count(), c.limiter.attempts)
			}
			if trace.HTTPStatus != 200 || trace.Retries != 1 || !strings.Contains(string(trace.Response), `"fixture-model"`) || trace.ResponseBytes != len(trace.Response) {
				t.Fatalf("trace status=%d retries=%d response=%s", trace.HTTPStatus, trace.Retries, trace.Response)
			}
			if summary := c.LimitSummary(); !strings.Contains(summary, "retries 1") || !strings.Contains(summary, "Attempts 2") {
				t.Fatalf("summary %q", summary)
			}
			if c.limiter.haltReason() != "" || c.limiter.unknown != 1 || len(*waits) != 1 || (*waits)[0] != 2*time.Second {
				t.Fatalf("halt=%q unknown=%d waits=%v", c.limiter.haltReason(), c.limiter.unknown, *waits)
			}
			data, err := json.Marshal(trace)
			if err != nil || !strings.Contains(string(data), `"retries":1`) {
				t.Fatalf("trace JSON %s %v", data, err)
			}
		})
	}
	t.Run("three failures then success", func(t *testing.T) {
		stub := &retryStub{steps: []retryStep{{status: 503}, {status: 429}, {status: 502}}}
		c, waits := stub.client(t, &Limits{})
		a, trace := c.AssessTrace(context.Background(), use)
		if a.Status != "completed" || stub.count() != 4 || trace.Retries != 3 || c.limiter.attempts != 4 || c.limiter.unknown != 3 {
			t.Fatalf("status=%s requests=%d retries=%d attempts=%d unknown=%d", a.Status, stub.count(), trace.Retries, c.limiter.attempts, c.limiter.unknown)
		}
		if fmt.Sprint(*waits) != "[2s 4s 8s]" || !strings.Contains(c.LimitSummary(), "retries 3") {
			t.Fatalf("waits=%v summary=%q", *waits, c.LimitSummary())
		}
	})
	t.Run("nil limiter", func(t *testing.T) {
		stub := &retryStub{steps: []retryStep{{status: 503, retryAfter: "0"}}}
		c, _ := stub.client(t, nil)
		a, trace := c.AssessTrace(context.Background(), use)
		if a.Status != "completed" || stub.count() != 2 || trace.Retries != 1 {
			t.Fatalf("status=%s requests=%d retries=%d", a.Status, stub.count(), trace.Retries)
		}
	})
}

// TestRetryExhaustedHalts is AC2: a fourth consecutive transient failure
// halts with today's reason after exactly four requests.
func TestRetryExhaustedHalts(t *testing.T) {
	use := retryUse(t)
	stub := &retryStub{steps: []retryStep{{status: 503}, {status: 503}, {status: 503}, {status: 503}}}
	c, _ := stub.client(t, &Limits{})
	first, trace := c.AssessTrace(context.Background(), use)
	second := c.Assess(context.Background(), use)
	if first.Status != "failed" || first.Reason != "judge HTTP 503" || trace.Retries != 3 || trace.HTTPStatus != 503 {
		t.Fatalf("first=%s %q retries=%d", first.Status, first.Reason, trace.Retries)
	}
	if second.Status != "not_run" || second.Reason != "judge limit: stopped after judge HTTP 503" || stub.count() != 4 {
		t.Fatalf("second=%s %q requests=%d", second.Status, second.Reason, stub.count())
	}
}

// TestRetryDroppedConnection is AC3a: a connection closed before any response
// is retried once; a second drop halts.
func TestRetryDroppedConnection(t *testing.T) {
	use := retryUse(t)
	for name, tc := range map[string]struct {
		steps    []retryStep
		requests int
		status   string
	}{
		"drop then success":     {[]retryStep{{hijack: true}}, 2, "completed"},
		"drop twice":            {[]retryStep{{hijack: true}, {hijack: true}}, 2, "failed"},
		"503 then drop twice":   {[]retryStep{{status: 503}, {hijack: true}, {hijack: true}}, 3, "failed"},
		"drop then 503 then ok": {[]retryStep{{hijack: true}, {status: 503}}, 3, "completed"},
	} {
		t.Run(name, func(t *testing.T) {
			stub := &retryStub{steps: tc.steps}
			c, _ := stub.client(t, &Limits{})
			a, _ := c.AssessTrace(context.Background(), use)
			if a.Status != tc.status || stub.count() != tc.requests {
				t.Fatalf("status=%s %q requests=%d", a.Status, a.Reason, stub.count())
			}
			if tc.status == "failed" && a.Reason != "judge transport failed or deadline exceeded" {
				t.Fatalf("reason %q", a.Reason)
			}
		})
	}
}

// TestNoRetryForOtherFailures is AC3: every other failure reaches the stub
// once and halts.
func TestNoRetryForOtherFailures(t *testing.T) {
	use := retryUse(t)
	for name, step := range map[string]retryStep{
		"400": {status: 400}, "401": {status: 401}, "403": {status: 403}, "500": {status: 500, retryAfter: "1"},
		"timeout": {delay: time.Second}, "undecodable 200": {broken: true},
	} {
		t.Run(name, func(t *testing.T) {
			stub := &retryStub{steps: []retryStep{step}}
			c, waits := stub.client(t, &Limits{})
			if step.delay > 0 {
				c.http = &http.Client{Timeout: 50 * time.Millisecond}
			}
			first, trace := c.AssessTrace(context.Background(), use)
			second := c.Assess(context.Background(), use)
			if first.Status != "failed" || trace.Retries != 0 || len(*waits) != 0 {
				t.Fatalf("first=%s %q retries=%d waits=%v", first.Status, first.Reason, trace.Retries, *waits)
			}
			if second.Status != "not_run" || stub.count() != 1 || c.limiter.attempts != 1 {
				t.Fatalf("second=%s requests=%d attempts=%d", second.Status, stub.count(), c.limiter.attempts)
			}
			if step.status != 0 && first.Reason != fmt.Sprintf("judge HTTP %d", step.status) {
				t.Fatalf("reason %q", first.Reason)
			}
			if step.delay > 0 && first.Reason != "judge transport failed or deadline exceeded" {
				t.Fatalf("reason %q", first.Reason)
			}
		})
	}
}

// TestRetryWait is AC4: Retry-After is honored up to 60 s, otherwise the
// backoff applies, and a cancellation during the wait sends nothing more.
func TestRetryWait(t *testing.T) {
	for header, want := range map[string]time.Duration{"3": 3 * time.Second, "60": 60 * time.Second, "61": 2 * time.Second, "": 2 * time.Second, "soon": 2 * time.Second, "-1": 2 * time.Second} {
		t.Run(fmt.Sprintf("Retry-After=%q", header), func(t *testing.T) {
			stub := &retryStub{steps: []retryStep{{status: 503, retryAfter: header}}}
			c, waits := stub.client(t, &Limits{})
			if _, reason := c.exchange(context.Background(), []byte(`{}`), nil); reason != "" || stub.count() != 2 {
				t.Fatalf("reason=%q requests=%d", reason, stub.count())
			}
			if len(*waits) != 1 || (*waits)[0] != want {
				t.Fatalf("waits %v want %v", *waits, want)
			}
		})
	}
	t.Run("canceled", func(t *testing.T) {
		stub := &retryStub{steps: []retryStep{{status: 503}}}
		c, _ := stub.client(t, &Limits{})
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		c.limiter.wait = func(ctx context.Context, d time.Duration) error { cancel(); return ctx.Err() }
		var trace DecisionTrace
		_, reason := c.exchange(ctx, []byte(`{}`), &trace)
		if reason != "judge limit: pacing canceled: context canceled" || stub.count() != 1 || trace.Retries != 0 || c.limiter.attempts != 1 {
			t.Fatalf("reason=%q requests=%d retries=%d attempts=%d", reason, stub.count(), trace.Retries, c.limiter.attempts)
		}
	})
}

// TestRetryAcquiresThroughLimiter is AC5: the retry waits for the RPM window
// and is refused, unsent, when the limiter halts during its wait.
func TestRetryAcquiresThroughLimiter(t *testing.T) {
	stub := &retryStub{steps: []retryStep{{status: 503}}}
	c, _ := stub.client(t, &Limits{RPM: 1})
	now := time.Unix(0, 0)
	var waits []time.Duration
	c.limiter.now = func() time.Time { return now }
	c.limiter.wait = func(ctx context.Context, d time.Duration) error {
		waits = append(waits, d)
		now = now.Add(d)
		return ctx.Err()
	}
	var trace DecisionTrace
	if _, reason := c.exchange(context.Background(), []byte(`{}`), &trace); reason != "" || stub.count() != 2 || trace.Retries != 1 {
		t.Fatalf("reason=%q requests=%d retries=%d", reason, stub.count(), trace.Retries)
	}
	if len(waits) != 2 || waits[0] != 2*time.Second || waits[1] != 58*time.Second || c.limiter.attempts != 2 {
		t.Fatalf("waits=%v attempts=%d", waits, c.limiter.attempts)
	}
	if n := len(c.limiter.window); n != 1 || !c.limiter.window[0].at.Equal(time.Unix(60, 0)) { // the t0 entry expired as the retry was admitted
		t.Fatalf("window %+v", c.limiter.window)
	}

	stub = &retryStub{steps: []retryStep{{status: 503}}}
	c, _ = stub.client(t, &Limits{RPM: 1})
	c.limiter.now = func() time.Time { return time.Unix(0, 0) }
	c.limiter.wait = func(ctx context.Context, d time.Duration) error {
		c.limiter.complete(0, nil, "judge HTTP 500") // another request fails meanwhile
		return ctx.Err()
	}
	trace = DecisionTrace{}
	if _, reason := c.exchange(context.Background(), []byte(`{}`), &trace); reason != "judge limit: stopped after judge HTTP 500" || stub.count() != 1 || trace.Retries != 0 || c.limiter.attempts != 1 {
		t.Fatalf("reason=%q requests=%d retries=%d attempts=%d", reason, stub.count(), trace.Retries, c.limiter.attempts)
	}
}

// TestScheduleRetryKeepsSlots is AC6: at N=4, one 503-then-200 on request #2
// judges the same candidates, under the same --judge-limit slots, as an
// all-200 run. Only the LimitSummary line differs.
func TestScheduleRetryKeepsSlots(t *testing.T) {
	sc := scheduleScenario{name: "retry", groups: 6, members: 2, limit: 4, limits: &Limits{RPM: 1000}}
	run := func(status func(int, []byte) int) (scheduleOutcome, *Client) {
		stub := &scheduleStub{status: status}
		c, r, opts := prepareScheduleScenario(t, sc, stub, 4)
		c.limiter.wait = func(ctx context.Context, _ time.Duration) error { return ctx.Err() }
		return runPrepared(t, c, r, opts, stub), c
	}
	clean, _ := run(nil)
	retried, c := run(failOrdinal(2, http.StatusServiceUnavailable))
	if clean.Failed != retried.Failed || retried.Requests != clean.Requests+1 || clean.Requests != sc.limit {
		t.Fatalf("failed=%v/%v requests=%d/%d", clean.Failed, retried.Failed, clean.Requests, retried.Requests)
	}
	if !strings.Contains(c.LimitSummary(), "retries 1") {
		t.Fatal(c.LimitSummary())
	}
	normalize := func(o scheduleOutcome) []byte {
		var r map[string]any
		if err := json.Unmarshal(o.Report, &r); err != nil {
			t.Fatal(err)
		}
		var keep []any
		for _, l := range r["limitations"].([]any) {
			if !strings.HasPrefix(l.(string), "Decision-model limits") {
				keep = append(keep, l)
			}
		}
		r["limitations"] = keep
		data, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	if !bytes.Equal(normalize(clean), normalize(retried)) {
		t.Fatal("report differs beyond the LimitSummary line")
	}
	retries := 0
	for id, tr := range retried.Traces {
		base, ok := clean.Traces[id]
		if !ok || base.RequestDigest != tr.RequestDigest || tr.HTTPStatus != 200 {
			t.Fatalf("trace %s: digest or status differs", id)
		}
		retries += tr.Retries
	}
	if len(retried.Traces) != len(clean.Traces) || retries != 1 {
		t.Fatalf("traces=%d/%d retries=%d", len(clean.Traces), len(retried.Traces), retries)
	}
}
