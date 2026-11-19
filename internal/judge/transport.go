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

// maxRetries bounds the extra sends of one request after transient failures.
const maxRetries = 3

// exchange shares bounded transport across semantic protocols. A transient
// failure (see retryableStatus, plus timeouts and dropped connections) is
// retried up to maxRetries times after retryDelay. The final outcome is
// completed on the limiter: an account failure stops the scan at once, and
// other failures only count toward the outage breaker. It is safe for
// concurrent use: the limiter holds no lock across the HTTP call or the wait.
func (c *Client) exchange(ctx context.Context, payload []byte, trace *DecisionTrace) (data []byte, reason string) {
	for attempt := 0; ; attempt++ {
		data, reason, retry, retryAfter := c.send(ctx, payload, trace, attempt)
		if !retry {
			return data, reason
		}
		if err := c.limiter.waitRetry(ctx, retryDelay(retryAfter, attempt)); err != nil {
			return nil, "judge limit: pacing canceled: " + err.Error()
		}
	}
}

// retryableStatus reports provider statuses that mean no answer was produced
// and a resend may succeed: timeout, rate limit, server error or overload.
func retryableStatus(status int) bool {
	switch status {
	case http.StatusRequestTimeout, http.StatusTooManyRequests, http.StatusInternalServerError,
		http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout, 529:
		return true
	}
	return false
}

// accountStop returns the scan-stopping message for a failure no resend can
// fix: rejected credentials or an exhausted quota or billing balance.
func accountStop(status int, body []byte) string {
	switch status {
	case http.StatusUnauthorized, http.StatusPaymentRequired, http.StatusForbidden:
		return fmt.Sprintf("decision model account or credentials rejected (judge HTTP %d)", status)
	case http.StatusTooManyRequests:
		lower := bytes.ToLower(body)
		for _, marker := range [][]byte{[]byte("insufficient_quota"), []byte("billing"), []byte("exceeded your current quota"), []byte("credit balance")} {
			if bytes.Contains(lower, marker) {
				return fmt.Sprintf("decision model account quota or billing exhausted (judge HTTP %d)", status)
			}
		}
	}
	return ""
}

// retryDelay honors a whole-second Retry-After of at most 60 s; otherwise it
// waits 2 s, 4 s, then 8 s for the first, second and third retry.
func retryDelay(header string, attempt int) time.Duration {
	if n, err := strconv.Atoi(header); err == nil && n >= 0 && n <= 60 {
		return time.Duration(n) * time.Second
	}
	return (2 * time.Second) << min(attempt, 2)
}

// send makes one limiter-admitted HTTP attempt. A failure that exchange will
// retry is abandoned rather than completed, so it keeps its window entry but
// neither stops the scan nor counts toward the outage breaker.
func (c *Client) send(ctx context.Context, payload []byte, trace *DecisionTrace, attempt int) (data []byte, reason string, retry bool, retryAfter string) {
	stop := ""
	if c.limiter != nil {
		id, err := c.limiter.acquire(ctx, len(payload))
		if err != nil {
			return nil, err.Error(), false, ""
		}
		defer func() {
			if retry {
				c.limiter.abandon(id)
			} else {
				c.limiter.complete(id, data, reason, stop)
			}
		}()
	}
	canRetry := attempt < maxRetries
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
		return nil, "request construction failed", false, ""
	}
	if c.provider == "gemini" {
		req.Header.Set("x-goog-api-key", c.key)
	} else {
		req.Header.Set("Authorization", "Bearer "+c.key)
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := c.http.Do(req)
	if err != nil {
		// A timeout or dropped connection is retried; a canceled scan is not.
		retry = canRetry && ctx.Err() == nil
		return nil, "judge transport failed or deadline exceeded", retry, ""
	}
	defer res.Body.Close()
	if trace != nil {
		trace.HTTPStatus = res.StatusCode
	}
	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
		if trace != nil {
			trace.ResponseBytes = len(body)
			if json.Valid(body) {
				trace.Response = append(json.RawMessage{}, body...)
			}
		}
		stop = accountStop(res.StatusCode, body)
		retry = canRetry && stop == "" && retryableStatus(res.StatusCode)
		return nil, fmt.Sprintf("judge HTTP %d", res.StatusCode), retry, res.Header.Get("Retry-After")
	}
	data, err = io.ReadAll(io.LimitReader(res.Body, (1<<20)+1))
	if err != nil || len(data) > 1<<20 {
		return nil, "response read failed or exceeded 1 MiB limit", false, ""
	}
	if trace != nil {
		trace.ResponseBytes = len(data)
		if json.Valid(data) {
			trace.Response = append(json.RawMessage{}, data...)
		}
	}

	return data, "", false, ""
}
