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
	at     time.Time
	tokens int64
}
type requestLimiter struct {
	series   sync.Mutex
	mu       sync.Mutex
	settings Limits
	attempts int
	input    int64
	unknown  int
	halted   string
	window   []requestWindowEntry
	now      func() time.Time
	wait     func(context.Context, time.Duration) error
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

func (l *requestLimiter) acquire(ctx context.Context, size int) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	estimate := int64(size) + 4096 // UTF-8 request bytes plus framing allowance, not an authoritative tokenizer
	for {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("judge limit: pacing canceled: %w", err)
		}
		if l.halted != "" {
			return fmt.Errorf("judge limit: stopped after %s", l.halted)
		}
		if l.settings.TPM > 0 && estimate > l.settings.TPM {
			return errors.New("judge limit: request token reservation exceeds the configured TPM window")
		}
		if l.settings.RPM == 0 && l.settings.TPM == 0 {
			l.attempts++
			return nil
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
		fullTokens := l.settings.TPM > 0 && tokens > l.settings.TPM-estimate
		if !fullRequests && !fullTokens {
			break
		}
		// The oldest retained request expires first; recheck both windows afterward.
		delay := time.Minute - now.Sub(keep[0].at)
		if err := l.wait(ctx, delay); err != nil {
			return fmt.Errorf("judge limit: pacing canceled: %w", err)
		}
	}
	l.attempts++
	l.window = append(l.window, requestWindowEntry{l.now(), estimate})
	return nil
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

func (l *requestLimiter) complete(data []byte, reason string) {
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
	if len(l.window) > 0 && tokens > l.window[len(l.window)-1].tokens {
		l.window[len(l.window)-1].tokens = tokens
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
	return fmt.Sprintf("Decision-model limits (one scan; discovery and assessment share state): RPM %d, estimated input TPM %d; requests remain sequential. Attempts %d; reported input tokens %d; unknown-usage attempts %d. %s", l.settings.RPM, l.settings.TPM, l.attempts, l.input, l.unknown, strings.TrimSpace(l.halted))
}
