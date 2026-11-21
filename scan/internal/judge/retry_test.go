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

	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

// retryStep is how the retry stub answers one request ordinal. The zero step,
// and every ordinal past the table, answers 200 with valid answers.
type retryStep struct {
	status     int           // non-zero, non-200 status with an empty JSON body
	retryAfter string        // Retry-After header for a failure status
	hijack     bool          // close the connection without a response
	broken     bool          // 200 with an undecodable body
	delay      time.Duration // answer 200 only after this delay
	body       string        // failure body; default {"error":"stub"}
}

type retryStub struct {
	mu       sync.Mutex
	steps    []retryStep
	after    retryStep // answers every ordinal past steps
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
		} else {
			step = s.after
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
			body := step.body
			if body == "" {
				body = `{"error":"stub"}`
			}
			_, _ = w.Write([]byte(body))
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

// TestRetryRecoversOnce is AC1: one transient status is retried and the
// candidate completes from the second response.
func TestRetryRecoversOnce(t *testing.T) {
	use := retryUse(t)
	for _, code := range []int{408, 429, 500, 502, 503, 504, 529} {
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

// TestRetryExhaustedFailsOnlyThatCandidate is AC2: a fourth consecutive
// transient failure fails that candidate after four requests; the scan goes on.
func TestRetryExhaustedFailsOnlyThatCandidate(t *testing.T) {
	use := retryUse(t)
	stub := &retryStub{steps: []retryStep{{status: 503}, {status: 503}, {status: 503}, {status: 503}}}
	c, _ := stub.client(t, &Limits{})
	first, trace := c.AssessTrace(context.Background(), use)
	second := c.Assess(context.Background(), use)
	if first.Status != "failed" || first.Reason != "judge HTTP 503" || trace.Retries != 3 || trace.HTTPStatus != 503 {
		t.Fatalf("first=%s %q retries=%d", first.Status, first.Reason, trace.Retries)
	}
	if second.Status != "completed" || stub.count() != 5 || c.StopReason() != "" {
		t.Fatalf("second=%s %q requests=%d stop=%q", second.Status, second.Reason, stub.count(), c.StopReason())
	}
}

// TestRetryTransportFailures is AC3a: timeouts and dropped connections are
// retried within the same budget and never stop the scan on their own.
func TestRetryTransportFailures(t *testing.T) {
	use := retryUse(t)
	for name, tc := range map[string]struct {
		steps    []retryStep
		requests int
		status   string
	}{
		"drop then success":     {[]retryStep{{hijack: true}}, 2, "completed"},
		"timeout then success":  {[]retryStep{{delay: time.Second}}, 2, "completed"},
		"drop then 503 then ok": {[]retryStep{{hijack: true}, {status: 503}}, 3, "completed"},
		"four drops":            {[]retryStep{{hijack: true}, {hijack: true}, {hijack: true}, {hijack: true}}, 4, "failed"},
	} {
		t.Run(name, func(t *testing.T) {
			stub := &retryStub{steps: tc.steps}
			c, _ := stub.client(t, &Limits{})
			c.http = &http.Client{Timeout: 100 * time.Millisecond}
			a, _ := c.AssessTrace(context.Background(), use)
			if a.Status != tc.status || stub.count() != tc.requests || c.StopReason() != "" {
				t.Fatalf("status=%s %q requests=%d stop=%q", a.Status, a.Reason, stub.count(), c.StopReason())
			}
			if tc.status == "failed" && a.Reason != "judge transport failed or deadline exceeded" {
				t.Fatalf("reason %q", a.Reason)
			}
		})
	}
}

// TestNoRetryForOtherFailures is AC3: other failures reach the stub once and
// fail only their own candidate.
func TestNoRetryForOtherFailures(t *testing.T) {
	use := retryUse(t)
	for name, step := range map[string]retryStep{
		"400": {status: 400}, "404": {status: 404}, "422": {status: 422, retryAfter: "1"}, "undecodable 200": {broken: true},
	} {
		t.Run(name, func(t *testing.T) {
			stub := &retryStub{steps: []retryStep{step}}
			c, waits := stub.client(t, &Limits{})
			first, trace := c.AssessTrace(context.Background(), use)
			second := c.Assess(context.Background(), use)
			if first.Status != "failed" || trace.Retries != 0 || len(*waits) != 0 {
				t.Fatalf("first=%s %q retries=%d waits=%v", first.Status, first.Reason, trace.Retries, *waits)
			}
			if second.Status != "completed" || stub.count() != 2 || c.StopReason() != "" {
				t.Fatalf("second=%s requests=%d stop=%q", second.Status, stub.count(), c.StopReason())
			}
			if step.status != 0 && first.Reason != fmt.Sprintf("judge HTTP %d", step.status) {
				t.Fatalf("reason %q", first.Reason)
			}
		})
	}
}

// TestAccountFailureStopsScan is AC3b: rejected credentials or an exhausted
// quota stop the scan at once, unretried, with a clear stop reason.
func TestAccountFailureStopsScan(t *testing.T) {
	use := retryUse(t)
	for name, tc := range map[string]struct {
		step retryStep
		stop string
	}{
		"401":         {retryStep{status: 401}, "decision model account or credentials rejected (judge HTTP 401)"},
		"402":         {retryStep{status: 402}, "decision model account or credentials rejected (judge HTTP 402)"},
		"403":         {retryStep{status: 403}, "decision model account or credentials rejected (judge HTTP 403)"},
		"quota 429":   {retryStep{status: 429, body: `{"error":{"code":"insufficient_quota","message":"You exceeded your current quota"}}`}, "decision model account quota or billing exhausted (judge HTTP 429)"},
		"billing 429": {retryStep{status: 429, body: `{"error":{"message":"Your credit balance is too low"}}`}, "decision model account quota or billing exhausted (judge HTTP 429)"},
	} {
		t.Run(name, func(t *testing.T) {
			stub := &retryStub{steps: []retryStep{tc.step}}
			c, waits := stub.client(t, &Limits{})
			first := c.Assess(context.Background(), use)
			second := c.Assess(context.Background(), use)
			if first.Status != "failed" || stub.count() != 1 || len(*waits) != 0 || c.StopReason() != tc.stop {
				t.Fatalf("first=%s requests=%d waits=%v stop=%q", first.Status, stub.count(), *waits, c.StopReason())
			}
			if second.Status != "not_run" || second.Reason != "judge limit: stopped after "+tc.stop {
				t.Fatalf("second=%s %q", second.Status, second.Reason)
			}
		})
	}
}

// TestOutageStopsScan is AC3c: five candidates in a row failing after their
// retries stop the scan as a decision-model outage; a success resets the count.
func TestOutageStopsScan(t *testing.T) {
	use := retryUse(t)
	stub := &retryStub{after: retryStep{status: 503}}
	c, _ := stub.client(t, &Limits{})
	for k := 0; k < outageThreshold; k++ {
		if a := c.Assess(context.Background(), use); a.Status != "failed" {
			t.Fatalf("candidate %d: %s %q", k, a.Status, a.Reason)
		}
	}
	want := "decision model not responding: 5 consecutive requests failed after retries (last: judge HTTP 503)"
	next := c.Assess(context.Background(), use)
	if c.StopReason() != want || next.Status != "not_run" || stub.count() != outageThreshold*(maxRetries+1) {
		t.Fatalf("stop=%q next=%s %q requests=%d", c.StopReason(), next.Status, next.Reason, stub.count())
	}
	if !strings.Contains(c.LimitSummary(), want) {
		t.Fatalf("summary %q", c.LimitSummary())
	}

	var steps []retryStep
	for k := 0; k < outageThreshold-1; k++ {
		steps = append(steps, retryStep{status: 400})
	}
	steps = append(steps, retryStep{})
	for k := 0; k < outageThreshold-1; k++ {
		steps = append(steps, retryStep{status: 400})
	}
	stub = &retryStub{steps: steps}
	c, _ = stub.client(t, &Limits{})
	for range steps {
		c.Assess(context.Background(), use)
	}
	if c.StopReason() != "" {
		t.Fatalf("a success must reset the outage count: %q", c.StopReason())
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
		c.limiter.complete(0, nil, "judge HTTP 401", "account rejected") // another request stops the scan meanwhile
		return ctx.Err()
	}
	trace = DecisionTrace{}
	if _, reason := c.exchange(context.Background(), []byte(`{}`), &trace); reason != "judge limit: stopped after account rejected" || stub.count() != 1 || trace.Retries != 0 || c.limiter.attempts != 1 {
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
