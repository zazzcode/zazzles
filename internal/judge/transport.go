package judge

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// exchange shares bounded transport across semantic protocols. A 502, 503 or
// 504 is retried once after retryDelay; every other failure, and a second
// consecutive failure, returns at once. It is safe for concurrent use: the
// limiter reserves and reconciles under its own lock and holds no lock across
// the HTTP call or the retry wait.
func (c *Client) exchange(ctx context.Context, payload []byte, trace *DecisionTrace) (data []byte, reason string) {
	for attempt := 0; ; attempt++ {
		data, reason, status, retryAfter := c.send(ctx, payload, trace, attempt)
		if attempt == 1 || !retryable(status) {
			return data, reason
		}
		if err := c.limiter.waitRetry(ctx, retryDelay(retryAfter)); err != nil {
			return nil, "judge limit: pacing canceled: " + err.Error()
		}
	}
}

// retryable reports the transient provider statuses that exchange retries once.
func retryable(status int) bool {
	return status == http.StatusBadGateway || status == http.StatusServiceUnavailable || status == http.StatusGatewayTimeout
}

// retryDelay honors a whole-second Retry-After of at most 10 s, otherwise 2 s.
func retryDelay(header string) time.Duration {
	if n, err := strconv.Atoi(header); err == nil && n >= 0 && n <= 10 {
		return time.Duration(n) * time.Second
	}
	return 2 * time.Second
}

// send makes one limiter-admitted HTTP attempt. A first attempt that fails
// with a retryable status is abandoned rather than completed, so it releases
// its reservation without halting; every other outcome is completed.
func (c *Client) send(ctx context.Context, payload []byte, trace *DecisionTrace, attempt int) (data []byte, reason string, status int, retryAfter string) {
	if c.limiter != nil {
		id, err := c.limiter.acquire(ctx, len(payload))
		if err != nil {
			return nil, err.Error(), 0, ""
		}
		defer func() {
			if attempt == 0 && retryable(status) {
				c.limiter.abandon(id)
			} else {
				c.limiter.complete(id, data, reason)
			}
		}()
	}
	if attempt > 0 {
		c.limiter.noteRetry()
		if trace != nil {
			trace.Retries++
		}
	}
	if trace != nil {
		trace.HTTPStatus, trace.Response, trace.ResponseBytes = 0, nil, 0
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, "request construction failed", 0, ""
	}
	if c.provider == "gemini" {
		req.Header.Set("x-goog-api-key", c.key)
	} else {
		req.Header.Set("Authorization", "Bearer "+c.key)
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := c.http.Do(req)
	if err != nil {
		return nil, "judge transport failed or deadline exceeded", 0, ""
	}
	defer res.Body.Close()
	if trace != nil {
		trace.HTTPStatus = res.StatusCode
	}
	if res.StatusCode != http.StatusOK {
		if trace != nil {
			body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
			trace.ResponseBytes = len(body)
			if json.Valid(body) {
				trace.Response = append(json.RawMessage{}, body...)
			}
		}
		return nil, fmt.Sprintf("judge HTTP %d", res.StatusCode), res.StatusCode, res.Header.Get("Retry-After")
	}
	data, err = io.ReadAll(io.LimitReader(res.Body, (1<<20)+1))
	if err != nil || len(data) > 1<<20 {
		return nil, "response read failed or exceeded 1 MiB limit", res.StatusCode, ""
	}
	if trace != nil {
		trace.ResponseBytes = len(data)
		if json.Valid(data) {
			trace.Response = append(json.RawMessage{}, data...)
		}
	}

	return data, "", res.StatusCode, ""
}
