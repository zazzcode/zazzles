package judge

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
)

// DecisionTrace contains the exact JSON bodies used in one assessment, never
// authentication headers. Callers decide where source-containing traces are saved.
type DecisionTrace struct {
	RequestDigest   string                       `json:"request_digest,omitempty"`
	Components      *analysis.ComponentSelection `json:"analysis_components,omitempty"`
	QuestionVersion string                       `json:"question_version"`
	Request         json.RawMessage              `json:"request,omitempty"`
	Response        json.RawMessage              `json:"response,omitempty"`
	HTTPStatus      int                          `json:"http_status"`
	RequestBytes    int                          `json:"request_bytes"`
	ResponseBytes   int                          `json:"response_bytes"`
	// Retries counts transient-failure retries sent (at most 3); Response and HTTPStatus
	// describe the last attempt.
	Retries int `json:"retries,omitempty"`
	// EvidenceOmissions lists context evidence an over-limit request left out;
	// the budget is deterministic, so a replay rebuilds the same request.
	EvidenceOmissions []analysis.EvidenceOmission `json:"evidence_omissions,omitempty"`
	// Groups are the path-group requests of an over-limit record, in group
	// order; each replays alone against its own group projection.
	Groups []DecisionTrace `json:"groups,omitempty"`
}

// Replay applies the current decoder/policy to a saved decision only when its
// exact request still matches the supplied use. It makes no network request.
func (c *Client) Replay(use analysis.CandidateUse, trace DecisionTrace) analysis.Assessment {
	if len(trace.Groups) > 0 {
		if groups, ok := c.planPathGroups(use); ok {
			a, _ := c.groupAssessment(use, groups, func(i int, sub analysis.CandidateUse) (analysis.Assessment, DecisionTrace) {
				if i >= len(trace.Groups) {
					return analysis.Assessment{Status: "failed", Reason: "Saved decision has no trace for this path group."}, DecisionTrace{}
				}
				return c.Replay(sub, trace.Groups[i]), trace.Groups[i]
			})
			return a
		}
	}
	version := protocolVersion(use)
	a := analysis.Assessment{Status: "failed", Provider: c.provider, Model: c.model, QuestionVersion: version}
	payload, omitted, err := c.budgetedPayload(use)
	if err != nil || !sameRequest(payload, trace.Request) || trace.HTTPStatus != 200 || trace.QuestionVersion != version {
		a.Reason = "Saved decision request does not exactly match the current evidence/protocol, or the response failed."
		return a
	}
	if len(payload) > requestLimit {
		overLimit(&a, use, payload, omitted)
		return a
	}
	a.EvidenceOmissions = omitted
	a.RequestDigest = requestDigest(use, payload)
	if trace.RequestDigest != "" && trace.RequestDigest != a.RequestDigest || trace.Components != nil && !sameComponents(trace.Components, use.Components) {
		a.Status = "failed"
		a.Reason = "Saved component provenance does not match current request"
		return a
	}
	expected := requestQuestions(use, payload)
	answers, model, usage, err := c.decodeQuestions(trace.Response, expected)
	if err != nil {
		a.Reason = err.Error()
		return a
	}
	details, err := c.answerDetails(trace.Response, answers, expected)
	if err != nil {
		a.Reason = err.Error()
		return a
	}
	a.Status, a.Answers, a.Model, a.Usage, a.AnswerDetails = "completed", answers, model, usage, details
	a.Resolutions = resolveAnswers(use, payload, answers, c.provider, model)
	a.FollowUp = neededFollowUp(answers)
	splitResolutionAnswers(&a)
	applyPolicy(use, &a)
	return a
}

// Preview prepares the exact JSON request without making a network call.
func (c *Client) Preview(use analysis.CandidateUse) (DecisionTrace, error) {
	payload, omitted, err := c.budgetedPayload(use)
	if err != nil && analysispacks.ObservationOnly(use.Kind) {
		return DecisionTrace{}, err
	}
	if err == nil && len(payload) > requestLimit {
		if groups, ok := c.planPathGroups(use); ok {
			return c.previewGroups(use, groups), nil
		}
	}
	version := protocolVersion(use)
	return DecisionTrace{QuestionVersion: version, Request: payload, RequestBytes: len(payload), RequestDigest: requestDigest(use, payload), Components: cloneComponents(use.Components), EvidenceOmissions: omitted}, err
}

// AssessTrace evaluates one use and returns its request/response evidence for
// bounded calibration. It has the same limits and transient retries as Assess.
func (c *Client) AssessTrace(ctx context.Context, use analysis.CandidateUse) (analysis.Assessment, DecisionTrace) {
	var trace DecisionTrace
	assessment := c.assess(ctx, use, &trace)
	return assessment, trace
}

func sameRequest(a, b []byte) bool {
	var x, y bytes.Buffer
	if json.Compact(&x, a) != nil || json.Compact(&y, b) != nil {
		return false
	}
	return bytes.Equal(x.Bytes(), y.Bytes())
}

// Compare serialized provenance: omitempty intentionally gives nil and empty
// optional lists the same persisted representation. All identities and digests
// must still match exactly after a trace is saved and loaded.
func sameComponents(a, b *analysis.ComponentSelection) bool {
	x, xe := json.Marshal(a)
	y, ye := json.Marshal(b)
	return xe == nil && ye == nil && bytes.Equal(x, y)
}

// previewGroups prepares a path-group record's requests. RequestBytes is the
// smallest group request within the cap, so a record with any group that fits
// is planned as spending; RequestDigest covers every group digest.
func (c *Client) previewGroups(use analysis.CandidateUse, groups []pathGroup) DecisionTrace {
	out := DecisionTrace{QuestionVersion: protocolVersion(use), Components: cloneComponents(use.Components)}
	var digests []string
	for i, g := range groups {
		if i >= maxPathGroups {
			break
		}
		t, _ := c.Preview(groupUse(use, g, groups))
		out.Groups = append(out.Groups, t)
		digests = append(digests, t.RequestDigest)
		if out.RequestBytes == 0 || t.RequestBytes < out.RequestBytes {
			out.RequestBytes = t.RequestBytes
		}
	}
	out.RequestDigest = groupDigest(digests)
	return out
}

func groupDigest(digests []string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte("path-groups:"+strings.Join(digests, ","))))
}

// groupCost is the number of requests a planned record may send: one per
// path group that fits, otherwise one.
func groupCost(t DecisionTrace) int {
	if len(t.Groups) == 0 {
		return 1
	}
	n := 0
	for _, g := range t.Groups {
		if g.RequestBytes > 0 && g.RequestBytes <= requestLimit {
			n++
		}
	}
	return max(n, 1)
}
