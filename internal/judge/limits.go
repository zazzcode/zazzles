package judge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"
)

// Limits configures shared per-scan request and token pacing. Zero disables a limit.
type Limits struct {
	RPM int
	TPM int64
}

type requestWindowEntry struct {
	id     uint64
	at     time.Time
	tokens int64
}

// requestLimiter is shared by concurrent requests. Every field after mu is
// guarded by mu; settings is fixed at construction. acquire reserves a window
// entry and complete reconciles that same entry, so no lock is held across HTTP.
type requestLimiter struct {
	mu          sync.Mutex
	settings    Limits
	attempts    int
	input       int64
	unknown     int
	halted      string
	concurrency int
	reserved    uint64
	window      []requestWindowEntry
	now         func() time.Time
	wait        func(context.Context, time.Duration) error
}

func newRequestLimiter(cfg Limits) (*requestLimiter, error) {
	if cfg.RPM < 0 || cfg.TPM < 0 {
		return nil, errors.New("judge rate limits cannot be negative")
	}
	return &requestLimiter{settings: cfg, now: time.Now, wait: waitDecisionWindow}, nil
}

func waitDecisionWindow(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// SetLimits starts shared scan pacing. Call before the client's first request.
// It does not enable requests, load credentials or change the request payload.
func (c *Client) SetLimits(cfg Limits) error {
	l, err := newRequestLimiter(cfg)
	if err == nil {
		c.limiter = l
	}
	return err
}

// reservationTokens is a conservative input-token estimate: observed request
// JSON runs 3.7–4.4 bytes per token, so bytes/3 over-reserves; complete()
// still raises the entry to reported usage when that is larger.
func reservationTokens(size int) int64 { return int64((size+2)/3) + 512 }

// oversized reports a request whose reservation can never fit the TPM window.
// A nil limiter refuses nothing.
func (l *requestLimiter) oversized(size int) bool {
	return l != nil && l.settings.TPM > 0 && reservationTokens(size) > l.settings.TPM
}

// haltReason returns the failure that stopped the scan, or "". A nil limiter never halts.
func (l *requestLimiter) haltReason() string {
	if l == nil {
		return ""
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.halted
}

// useConcurrency records the largest assessment concurrency for LimitSummary.
func (l *requestLimiter) useConcurrency(n int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.concurrency = max(l.concurrency, n)
}

// acquire admits one request and returns its window reservation (0 when pacing
// is off). It re-checks the halt after every pacing wait, and it releases mu
// while waiting so that completions and halts are recorded meanwhile.
func (l *requestLimiter) acquire(ctx context.Context, size int) (uint64, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	reserve := reservationTokens(size)
	for {
		if err := ctx.Err(); err != nil {
			return 0, fmt.Errorf("judge limit: pacing canceled: %w", err)
		}
		if l.halted != "" {
			return 0, fmt.Errorf("judge limit: stopped after %s", l.halted)
		}
		if l.oversized(size) {
			return 0, errors.New("judge limit: request token reservation exceeds the configured TPM window")
		}
		if l.settings.RPM == 0 && l.settings.TPM == 0 {
			l.attempts++
			return 0, nil
		}
		now := l.now()
		var tokens int64
		keep := l.window[:0]
		for _, r := range l.window {
			if now.Sub(r.at) < time.Minute {
				keep = append(keep, r)
				tokens += r.tokens
			}
		}
		l.window = keep
		fullRequests := l.settings.RPM > 0 && len(keep) >= l.settings.RPM
		fullTokens := l.settings.TPM > 0 && tokens > l.settings.TPM-reserve
		if !fullRequests && !fullTokens {
			l.attempts++
			l.reserved++
			l.window = append(l.window, requestWindowEntry{l.reserved, now, reserve})
			return l.reserved, nil
		}
		// The oldest retained request expires first; recheck both windows afterward.
		delay := time.Minute - now.Sub(keep[0].at)
		l.mu.Unlock()
		err := l.wait(ctx, delay)
		l.mu.Lock()
		if err != nil {
			return 0, fmt.Errorf("judge limit: pacing canceled: %w", err)
		}
	}
}

func responseInputUsage(data []byte) (int64, bool) {
	var response struct {
		Usage struct {
			Input      *int64 `json:"input_tokens"`
			TotalInput *int64 `json:"total_input_tokens"`
		} `json:"usage"`
	}
	if json.Unmarshal(data, &response) != nil {
		return 0, false
	}
	n := response.Usage.Input
	if n == nil {
		n = response.Usage.TotalInput
	}
	if n == nil || *n < 0 {
		return 0, false
	}
	return *n, true
}

// complete records one admitted request's outcome. Any failure reason halts new
// acquisitions; reported usage raises that request's own window reservation.
func (l *requestLimiter) complete(id uint64, data []byte, reason string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	tokens, ok := responseInputUsage(data)
	if reason != "" {
		l.halted = reason
	}
	if !ok {
		l.unknown++
		return
	}
	if tokens > math.MaxInt64-l.input {
		l.unknown++
		l.halted = "provider usage accounting overflow"
		return
	}
	l.input += tokens
	for k := range l.window {
		if l.window[k].id == id && id != 0 && tokens > l.window[k].tokens {
			l.window[k].tokens = tokens
		}
	}
}

func (c *Client) stopLimitedScan(reason string) {
	if c.limiter != nil {
		c.limiter.mu.Lock()
		c.limiter.halted = reason
		c.limiter.mu.Unlock()
	}
}

// LimitSummary describes configured scan-local controls and conservative accounting.
// It is report metadata, never model evidence or a provider invoice.
func (c *Client) LimitSummary() string {
	l := c.limiter
	if l == nil {
		return ""
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.settings.RPM == 0 && l.settings.TPM == 0 && l.halted == "" {
		return ""
	}
	mode := "requests remain sequential"
	if l.concurrency > 1 {
		mode = fmt.Sprintf("up to %d assessment requests in flight", l.concurrency)
	}
	return fmt.Sprintf("Decision-model limits (one scan; discovery and assessment share state): RPM %d, estimated input TPM %d; %s. Attempts %d; reported input tokens %d; unknown-usage attempts %d. %s", l.settings.RPM, l.settings.TPM, mode, l.attempts, l.input, l.unknown, strings.TrimSpace(l.halted))
}
