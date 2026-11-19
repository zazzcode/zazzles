package judge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"
)

// maxRetries bounds the extra sends of one request after transient failures.
const maxRetries = 3

// exchange shares bounded transport across semantic protocols. A 429, 502,
// 503 or 504 is retried up to maxRetries times after retryDelay, and a
// connection dropped before any response is retried once within that bound.
// Every other failure, and the last allowed failure, returns at once. It is
// safe for concurrent use: the limiter reserves and reconciles under its own
// lock and holds no lock across the HTTP call or the retry wait.
func (c *Client) exchange(ctx context.Context, payload []byte, trace *DecisionTrace) (data []byte, reason string) {
	drops := 0
	for attempt := 0; ; attempt++ {
		data, reason, retry, dropped, retryAfter := c.send(ctx, payload, trace, attempt, drops)
		if !retry {
			return data, reason
		}
		if dropped {
			drops++
		}
		if err := c.limiter.waitRetry(ctx, retryDelay(retryAfter, attempt)); err != nil {
			return nil, "judge limit: pacing canceled: " + err.Error()
		}
	}
}

// retryable reports the provider statuses that mean no answer was produced
// and a resend is invited: rate limited or temporarily unavailable.
func retryable(status int) bool {
	switch status {
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	}
	return false
}

// retryDelay honors a whole-second Retry-After of at most 60 s; otherwise it
// waits 2 s, 4 s, then 8 s for the first, second and third retry.
func retryDelay(header string, attempt int) time.Duration {
	if n, err := strconv.Atoi(header); err == nil && n >= 0 && n <= 60 {
		return time.Duration(n) * time.Second
	}
	return (2 * time.Second) << min(attempt, 2)
}

// droppedConnection reports a transport error that is neither a timeout nor
// a cancellation: the connection closed or reset before any response arrived.
func droppedConnection(ctx context.Context, err error) bool {
	var ne net.Error
	return ctx.Err() == nil && !(errors.As(err, &ne) && ne.Timeout())
}

// send makes one limiter-admitted HTTP attempt. A failure that exchange will
// retry is abandoned rather than completed, so it keeps its window entry but
// does not halt; every other outcome is completed and may halt.
func (c *Client) send(ctx context.Context, payload []byte, trace *DecisionTrace, attempt, drops int) (data []byte, reason string, retry, dropped bool, retryAfter string) {
	status := 0
	if c.limiter != nil {
		id, err := c.limiter.acquire(ctx, len(payload))
		if err != nil {
			return nil, err.Error(), false, false, ""
		}
		defer func() {
			if retry {
				c.limiter.abandon(id)
			} else {
				c.limiter.complete(id, data, reason)
			}
		}()
	}
	// retry stays false unless a failure below is one exchange will resend.
	decide := func() bool {
		return attempt < maxRetries && (retryable(status) || dropped && drops == 0)
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
		return nil, "request construction failed", false, false, ""
	}
	if c.provider == "gemini" {
		req.Header.Set("x-goog-api-key", c.key)
	} else {
		req.Header.Set("Authorization", "Bearer "+c.key)
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := c.http.Do(req)
	if err != nil {
		dropped = droppedConnection(ctx, err)
		retry = decide()
		return nil, "judge transport failed or deadline exceeded", retry, dropped, ""
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
		status = res.StatusCode
		retry = decide()
		return nil, fmt.Sprintf("judge HTTP %d", res.StatusCode), retry, false, res.Header.Get("Retry-After")
	}
	data, err = io.ReadAll(io.LimitReader(res.Body, (1<<20)+1))
	if err != nil || len(data) > 1<<20 {
		return nil, "response read failed or exceeded 1 MiB limit", false, false, ""
	}
	if trace != nil {
		trace.ResponseBytes = len(data)
		if json.Valid(data) {
			trace.Response = append(json.RawMessage{}, data...)
		}
	}

	return data, "", false, false, ""
}
