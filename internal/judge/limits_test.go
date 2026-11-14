package judge

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/zazzcode/zazzles/internal/analysis"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDecisionBudgetReservesBeforeRequest(t *testing.T) {
	c, _ := New("gemini", "", "stub")
	if err := c.SetLimits(Limits{BudgetUSD: .01, InputUSDPerMillion: .1}); err != nil {
		t.Fatal(err)
	}
	if _, reason := c.exchange(context.Background(), []byte(`{}`), nil); !strings.HasPrefix(reason, "judge limit: budget") {
		t.Fatalf("request must be refused before transport: %q", reason)
	}
}

func TestDecisionBudgetReconcilesAndRetainsUnknownUsage(t *testing.T) {
	l, err := newRequestLimiter("gemini", "gemini-decision-1", Limits{BudgetUSD: .04, InputUSDPerMillion: .1})
	if err != nil {
		t.Fatal(err)
	}
	if err := l.acquire(context.Background(), 100); err != nil {
		t.Fatal(err)
	}
	l.complete(json.RawMessage(`{"usage":{"total_input_tokens":1000,"total_output_tokens":0}}`), "")
	if err := l.acquire(context.Background(), 100); err != nil {
		t.Fatal("valid usage should release unused reservation:", err)
	}
	l.complete([]byte(`{"usage":{}}`), "")
	if err := l.acquire(context.Background(), 100); err == nil {
		t.Fatal("missing usage must keep maximum reservation")
	}
}

func TestDecisionRateWindowAndCancellation(t *testing.T) {
	l, _ := newRequestLimiter("gemini", "gemini-decision-1", Limits{RPM: 2, TPM: 9000})
	now := time.Unix(0, 0)
	waits := []time.Duration{}
	l.now = func() time.Time { return now }
	l.wait = func(ctx context.Context, d time.Duration) error {
		waits = append(waits, d)
		now = now.Add(d)
		return ctx.Err()
	}
	for i := 0; i < 3; i++ {
		if err := l.acquire(context.Background(), 100); err != nil {
			t.Fatal(err)
		}
		l.complete(nil, "")
	}
	if len(waits) != 1 || waits[0] < time.Minute {
		t.Fatalf("rolling window waits %v", waits)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := l.acquire(ctx, 100); err == nil {
		t.Fatal("canceled request must not be admitted")
	}
	small, _ := newRequestLimiter("gemini", "gemini-decision-1", Limits{TPM: 10})
	if err := small.acquire(context.Background(), 100); err == nil {
		t.Fatal("oversized reservation must not wait forever")
	}
}

func TestDecisionLimitsValidation(t *testing.T) {
	for _, limits := range []Limits{{BudgetUSD: -1}, {BudgetUSD: 1}, {RPM: -1}, {TPM: -1}} {
		if _, err := newRequestLimiter("gemini", "gemini-decision-1", limits); err == nil {
			t.Fatalf("accepted %+v", limits)
		}
	}
	if _, err := newRequestLimiter("jev", "unknown", Limits{BudgetUSD: 1, InputUSDPerMillion: .1}); err == nil {
		t.Fatal("unknown billing bounds must fail closed")
	}
}

func TestDecisionDiscoveryAndAssessmentShareBudget(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Write([]byte(`{"answers":{"route_binding":{"type":"choice","choice":"unknown"}}}`))
	}))
	defer server.Close()
	c, _ := New("gemini", "", "synthetic-key")
	c.UseEndpoint(server.URL, server.Client())
	if err := c.SetLimits(Limits{BudgetUSD: .04, InputUSDPerMillion: .1}); err != nil {
		t.Fatal(err)
	}
	p := analysis.DiscoveryProposal{ID: "proposal", Registration: analysis.Evidence{SHA256: "registration-hash"}, Handler: analysis.Evidence{SHA256: "handler-hash"}}
	got, tr := c.DiscoverTrace(context.Background(), p)
	if got.ModelStatus != "completed" {
		t.Fatalf("discovery=%+v", got)
	}
	a := c.Assess(context.Background(), analysis.CandidateUse{})
	if a.Status != "not_run" || !strings.HasPrefix(a.Reason, "judge limit: budget") || calls != 1 {
		t.Fatalf("assessment=%+v calls=%d", a, calls)
	}
	if replay := c.ReplayDiscovery(p, tr); replay.ModelStatus != "completed" || calls != 1 {
		t.Fatal("replay must remain free")
	}
}

func TestDecisionFailureStopsFollowingRequests(t *testing.T) {
	for _, code := range []int{http.StatusUnauthorized, http.StatusTooManyRequests, http.StatusInternalServerError} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			calls := 0
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(code) }))
			defer s.Close()
			c, _ := New("gemini", "", "synthetic-key")
			c.UseEndpoint(s.URL, s.Client())
			c.SetLimits(Limits{BudgetUSD: 1, InputUSDPerMillion: .1})
			first := c.Assess(context.Background(), analysis.CandidateUse{})
			second := c.Assess(context.Background(), analysis.CandidateUse{})
			if first.Status != "failed" || second.Status != "not_run" || calls != 1 {
				t.Fatalf("first=%s second=%s calls=%d", first.Status, second.Status, calls)
			}
			if !strings.Contains(c.LimitSummary(), "unknown-usage attempts 1") {
				t.Fatal(c.LimitSummary())
			}
		})
	}
}
