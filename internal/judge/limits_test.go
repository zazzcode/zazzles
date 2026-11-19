package judge

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/zazzcode/zazzles/internal/analysis"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDecisionTPMRefusesBeforeRequest(t *testing.T) {
	c, _ := New("openai", "", "stub")
	if err := c.SetLimits(Limits{TPM: 1}); err != nil {
		t.Fatal(err)
	}
	if _, reason := c.exchange(context.Background(), []byte(`{}`), nil); !strings.HasPrefix(reason, "judge limit: request token reservation") {
		t.Fatalf("request must be refused before transport: %q", reason)
	}
}

func TestDecisionRateWindowAndCancellation(t *testing.T) {
	l, _ := newRequestLimiter(Limits{RPM: 2, TPM: 9000})
	now := time.Unix(0, 0)
	waits := []time.Duration{}
	l.now = func() time.Time { return now }
	l.wait = func(ctx context.Context, d time.Duration) error {
		waits = append(waits, d)
		now = now.Add(d)
		return ctx.Err()
	}
	for i := 0; i < 3; i++ {
		if _, err := l.acquire(context.Background(), 100); err != nil {
			t.Fatal(err)
		}
		l.complete(0, nil, "")
	}
	if len(waits) != 1 || waits[0] < time.Minute {
		t.Fatalf("rolling window waits %v", waits)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := l.acquire(ctx, 100); err == nil {
		t.Fatal("canceled request must not be admitted")
	}
	small, _ := newRequestLimiter(Limits{TPM: 10})
	if _, err := small.acquire(context.Background(), 100); err == nil {
		t.Fatal("oversized reservation must not wait forever")
	}
}

func TestDecisionLimitsValidation(t *testing.T) {
	for _, limits := range []Limits{{RPM: -1}, {TPM: -1}} {
		if _, err := newRequestLimiter(limits); err == nil {
			t.Fatalf("accepted %+v", limits)
		}
	}
}

func TestDecisionDiscoveryAndAssessmentShareRateWindow(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Write([]byte(`{"answers":{"route_binding":{"type":"choice","choice":"unknown"}}}`))
	}))
	defer server.Close()
	c, _ := New("gemini", "", "synthetic-key")
	c.UseEndpoint(server.URL, server.Client())
	if err := c.SetLimits(Limits{RPM: 1}); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(0, 0)
	waits := 0
	c.limiter.now = func() time.Time { return now }
	c.limiter.wait = func(ctx context.Context, d time.Duration) error { waits++; now = now.Add(d); return ctx.Err() }
	p := analysis.DiscoveryProposal{ID: "proposal", Registration: analysis.Evidence{SHA256: "registration-hash"}, Handler: analysis.Evidence{SHA256: "handler-hash"}}
	got, tr := c.DiscoverTrace(context.Background(), p)
	if got.ModelStatus != "completed" {
		t.Fatalf("discovery=%+v", got)
	}
	c.Assess(context.Background(), analysis.CandidateUse{})
	if calls != 2 || waits != 1 || c.limiter.attempts != 2 {
		t.Fatalf("calls=%d waits=%d attempts=%d", calls, waits, c.limiter.attempts)
	}
	if replay := c.ReplayDiscovery(p, tr); replay.ModelStatus != "completed" || calls != 2 {
		t.Fatal("replay must make no calls")
	}
}

func TestDisabledPacingDoesNotRetainRateWindow(t *testing.T) {
	l, _ := newRequestLimiter(Limits{})
	l.now = func() time.Time { t.Fatal("disabled pacing should not read the clock"); return time.Time{} }
	for i := 0; i < 10; i++ {
		if _, err := l.acquire(context.Background(), 100); err != nil {
			t.Fatal(err)
		}
		l.complete(0, []byte(`{"usage":{"input_tokens":100}}`), "")
	}
	if len(l.window) != 0 || l.attempts != 10 || l.input != 1000 {
		t.Fatalf("window=%d attempts=%d input=%d", len(l.window), l.attempts, l.input)
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
			c.SetLimits(Limits{})
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

// TestReservationTokensCoversObservedUsage checks the TPM reservation against
// byte and reported-token pairs from the phase 4 Juice Shop live traces.
func TestReservationTokensCoversObservedUsage(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "tpm_ratio.json"))
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct{ Bytes, Tokens int64 }
	if err := json.Unmarshal(raw, &rows); err != nil || len(rows) == 0 {
		t.Fatalf("rows=%d err=%v", len(rows), err)
	}
	for _, size := range []int{0, 1, 2, 3, 4, 20000} {
		if got, want := reservationTokens(size), int64((size+2)/3)+512; got != want {
			t.Fatalf("reservationTokens(%d)=%d want %d", size, got, want)
		}
	}
	for _, r := range rows {
		got := reservationTokens(int(r.Bytes))
		if got < r.Tokens {
			t.Errorf("bytes %d: reservation %d underestimates reported %d", r.Bytes, got, r.Tokens)
		}
		if float64(got) > 1.6*float64(r.Tokens) {
			t.Errorf("bytes %d: reservation %d exceeds 1.6x reported %d", r.Bytes, got, r.Tokens)
		}
	}
}
