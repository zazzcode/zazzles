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

// Limits configures one scan's shared discovery and assessment scheduler. Prices
// must include the highest applicable input premium; zero disables each limit.
type Limits struct {
	BudgetUSD          float64
	InputUSDPerMillion float64
	RPM                int
	TPM                int64
}

type requestSpend struct {
	at     time.Time
	tokens int64
}
type requestLimiter struct {
	series                                sync.Mutex
	mu                                    sync.Mutex
	settings                              Limits
	budget, reserved, maximum, perRequest int64 // currency is integer microdollars
	attempts                              int
	input                                 int64
	unknown                               int
	halted                                string
	window                                []requestSpend
	now                                   func() time.Time
	wait                                  func(context.Context, time.Duration) error
}

func newRequestLimiter(provider, model string, cfg Limits) (*requestLimiter, error) {
	for _, v := range []float64{cfg.BudgetUSD, cfg.InputUSDPerMillion} {
		if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 || v >= float64(math.MaxInt64)/1e6 {
			return nil, errors.New("judge limits require finite, nonnegative bounded numbers")
		}
	}
	if cfg.RPM < 0 || cfg.TPM < 0 {
		return nil, errors.New("judge rate limits cannot be negative")
	}
	l := &requestLimiter{settings: cfg, now: time.Now, wait: waitDecisionWindow}
	if cfg.BudgetUSD > 0 {
		if cfg.InputUSDPerMillion <= 0 {
			return nil, errors.New("judge budget requires --judge-input-usd-per-million (highest applicable input price)")
		}
		// Reserve the full documented context, not a guessed local token count.
		switch {
		case provider == "gemini" && model == "gemini-decision-1":
			l.maximum = 262144
		case provider == "openai" && model == "gpt-6-luna":
			l.maximum = 1050000
		default:
			return nil, errors.New("judge budget has no verified billing bound for the selected provider/model")
		}
		cost := math.Ceil(float64(l.maximum) * cfg.InputUSDPerMillion)
		if cost > float64(math.MaxInt64)/2 {
			return nil, errors.New("judge request-price reservation overflows")
		}
		l.perRequest = int64(cost)
		l.budget = int64(math.Floor(cfg.BudgetUSD * 1e6))
		if l.budget < 1 || l.perRequest < 1 {
			return nil, errors.New("judge budget and price must support at least one microdollar")
		}
	}
	return l, nil
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

// SetLimits starts one shared scan budget. Call before the client's first request.
// It does not enable requests, load credentials or change the request payload.
func (c *Client) SetLimits(cfg Limits) error {
	l, err := newRequestLimiter(c.provider, c.model, cfg)
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
		if l.budget > 0 && l.perRequest > l.budget-l.reserved {
			return errors.New("judge limit: budget cannot reserve the next request's maximum input cost")
		}
		if l.settings.TPM > 0 && estimate > l.settings.TPM {
			return errors.New("judge limit: request token reservation exceeds the configured TPM window")
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
	l.reserved += l.perRequest
	l.attempts++
	l.window = append(l.window, requestSpend{l.now(), estimate})
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
	} // keep the entire currency reservation on unknown usage
	if tokens > math.MaxInt64-l.input {
		l.unknown++
		l.halted = "provider usage accounting overflow"
		return
	}
	l.input += tokens
	if len(l.window) > 0 && tokens > l.window[len(l.window)-1].tokens {
		l.window[len(l.window)-1].tokens = tokens
	}
	if l.budget == 0 {
		return
	}
	if tokens > l.maximum {
		l.halted = "provider usage exceeded the verified billing bound"
		return
	}
	cost := int64(math.Ceil(float64(tokens) * l.settings.InputUSDPerMillion))
	l.reserved -= l.perRequest - cost
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
	if l.settings.BudgetUSD == 0 && l.settings.RPM == 0 && l.settings.TPM == 0 && l.halted == "" {
		return ""
	}
	return fmt.Sprintf("Decision-model limits (one scan; discovery and assessment share state): budget USD %.6f, configured maximum input USD/million %.6f, RPM %d, estimated input TPM %d; requests remain sequential. Attempts %d; reported input tokens %d; conservative accounted/reserved USD %.6f; unknown-usage attempts %d. %s", l.settings.BudgetUSD, l.settings.InputUSDPerMillion, l.settings.RPM, l.settings.TPM, l.attempts, l.input, float64(l.reserved)/1e6, l.unknown, strings.TrimSpace(l.halted))
}
