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
	"sort"
	"strings"
	"sync"
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
		l.complete(0, nil, "", "")
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
		l.complete(0, []byte(`{"usage":{"input_tokens":100}}`), "", "")
	}
	if len(l.window) != 0 || l.attempts != 10 || l.input != 1000 {
		t.Fatalf("window=%d attempts=%d input=%d", len(l.window), l.attempts, l.input)
	}
}

func TestDecisionFailureStopsFollowingRequests(t *testing.T) {
	for _, code := range []int{http.StatusUnauthorized, http.StatusPaymentRequired, http.StatusForbidden} { // account failures stop the scan; see retry_test.go
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
		if float64(got) > 1.65*float64(r.Tokens) {
			t.Errorf("bytes %d: reservation %d exceeds 1.65x reported %d", r.Bytes, got, r.Tokens)
		}
	}
}

// TestTokenEstimatePacing is AC8: 20,000-byte requests reserve 7,179 tokens, so
// TPM=100,000 admits 13 at once from four concurrent callers and never reserves
// more than the setting in any rolling minute.
func TestTokenEstimatePacing(t *testing.T) {
	const size, requests, workers = 20000, 40, 4
	l, _ := newRequestLimiter(Limits{TPM: 100000})
	if reserve := reservationTokens(size); reserve != 7179 {
		t.Fatalf("reservation %d", reserve)
	}
	var clockMu sync.Mutex
	clock := time.Unix(0, 0)
	admitted := map[uint64]requestWindowEntry{}
	l.now = func() time.Time { // called with l.mu held: record entries before any prune
		for _, e := range l.window {
			admitted[e.id] = e
		}
		clockMu.Lock()
		defer clockMu.Unlock()
		return clock
	}
	l.wait = func(ctx context.Context, d time.Duration) error {
		clockMu.Lock()
		clock = clock.Add(d)
		clockMu.Unlock()
		return ctx.Err()
	}
	var wg sync.WaitGroup
	next := make(chan struct{}, requests)
	for i := 0; i < requests; i++ {
		next <- struct{}{}
	}
	close(next)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range next {
				id, err := l.acquire(context.Background(), size)
				if err != nil {
					t.Error(err)
					return
				}
				l.complete(id, []byte(`{"usage":{"input_tokens":4900}}`), "", "")
			}
		}()
	}
	wg.Wait()
	l.mu.Lock()
	for _, e := range l.window {
		admitted[e.id] = e
	}
	l.mu.Unlock()
	if len(admitted) != requests || l.attempts != requests {
		t.Fatalf("admitted=%d attempts=%d", len(admitted), l.attempts)
	}
	var entries []requestWindowEntry
	first := 0
	for _, e := range admitted {
		entries = append(entries, e)
		if e.at.Equal(time.Unix(0, 0)) {
			first++
		}
	}
	if first != 13 {
		t.Fatalf("first minute admitted %d, want 13", first)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].at.Before(entries[j].at) })
	for i := range entries {
		var tokens int64
		for _, e := range entries[i:] {
			if e.at.Sub(entries[i].at) < time.Minute {
				tokens += e.tokens
			}
		}
		if tokens > 100000 {
			t.Fatalf("%d tokens reserved in the minute from %v", tokens, entries[i].at)
		}
	}

	c, _ := New("openai", "", "stub")
	if err := c.SetLimits(Limits{TPM: 1}); err != nil {
		t.Fatal(err)
	}
	if _, reason := c.exchange(context.Background(), make([]byte, size), nil); reason != "judge limit: request token reservation exceeds the configured TPM window" {
		t.Fatalf("TPM=1 reason %q", reason)
	}
}
