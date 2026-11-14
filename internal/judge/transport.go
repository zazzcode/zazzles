package judge

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// exchange shares bounded, no-retry transport across semantic protocols.
func (c *Client) exchange(ctx context.Context, payload []byte, trace *DecisionTrace) (data []byte, reason string) {
	if c.limiter != nil {
		c.limiter.series.Lock()
		defer c.limiter.series.Unlock()
		if err := c.limiter.acquire(ctx, len(payload)); err != nil {
			return nil, err.Error()
		}
		defer func() { c.limiter.complete(data, reason) }()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, "request construction failed"
	}
	if c.provider == "gemini" {
		req.Header.Set("x-goog-api-key", c.key)
	} else {
		req.Header.Set("Authorization", "Bearer "+c.key)
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := c.http.Do(req)
	if err != nil {
		return nil, "judge transport failed or deadline exceeded"
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
		return nil, fmt.Sprintf("judge HTTP %d", res.StatusCode)
	}
	data, err = io.ReadAll(io.LimitReader(res.Body, (1<<20)+1))
	if err != nil || len(data) > 1<<20 {
		return nil, "response read failed or exceeded 1 MiB limit"
	}
	if trace != nil {
		trace.ResponseBytes = len(data)
		if json.Valid(data) {
			trace.Response = append(json.RawMessage{}, data...)
		}
	}

	return data, ""
}
