package judge

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

const followUpHelpers = `def helper1(v):
    return v.strip()


def helper2(v):
    return v.lower()


def helper3(v):
    return v


def helper4(v):
    return v.upper()
`

// followUpReport is a snapshot holding helpers.py and one path record per
// named helper, each with a coverage gap naming its helper.
func followUpReport(t *testing.T, helpers ...string) *analysis.AnalysisReport {
	t.Helper()
	base := comprehensionPathUse(t)
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "helpers.py"), []byte(followUpHelpers), 0o644); err != nil {
		t.Fatal(err)
	}
	r := &analysis.AnalysisReport{Root: root, Files: []analysis.Evidence{{Kind: "file", Span: analysis.Span{File: "helpers.py"}, SHA256: fmt.Sprintf("%x", sha256.Sum256([]byte(followUpHelpers)))}}}
	for i, h := range helpers {
		u := base
		c := *base.Completeness
		c.Blockers = nil
		c.Coverage = append(append([]analysis.Gap{}, base.Completeness.Coverage...), analysis.Gap{Kind: "unknown_transfer", Detail: "call may transform or discard its arguments: " + h, At: base.Sink.Span})
		u.Completeness = &c
		u.ID = fmt.Sprintf("%s-%d", base.ID, i)
		r.Uses = append(r.Uses, u)
	}
	return r
}

// followUpStub answers every path question unknown; in a first request it
// asks for the first offered item; a follow-up must offer no second one.
func followUpStub(t *testing.T) (*Client, func() (int, int)) {
	t.Helper()
	var mu sync.Mutex
	requests, followUps := 0, 0
	values := map[string]string{"path_traversal": "unknown", "containment_control": "none", "protection_coverage": "incomplete"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var body struct {
			Input     string `json:"input"`
			Questions []struct {
				Name    string              `json:"name"`
				Choices []map[string]string `json:"choices"`
			} `json:"questions"`
		}
		json.NewDecoder(req.Body).Decode(&body)
		followUp := strings.Contains(body.Input, followUpKind)
		mu.Lock()
		requests++
		if followUp {
			followUps++
		}
		mu.Unlock()
		answers := []map[string]string{}
		for _, q := range body.Questions {
			choice := values[q.Name]
			if q.Name == neededQuestion {
				if followUp {
					t.Error("a follow-up request must not ask for a second follow-up")
				}
				choice = q.Choices[0]["value"]
				for _, ch := range q.Choices {
					if strings.Contains(ch["value"], "helper") || strings.Contains(ch["value"], "missing") {
						choice = ch["value"]
					}
				}
			} else if strings.HasPrefix(q.Name, resolvePrefix) {
				choice = citeNone
			}
			answers = append(answers, map[string]string{"name": q.Name, "type": "choice", "choice": choice})
		}
		json.NewEncoder(w).Encode(map[string]any{"model": "fixture-model", "answers": answers})
	}))
	t.Cleanup(server.Close)
	c, _ := New("openai", "fixture-model", "synthetic-test-key")
	c.UseEndpoint(server.URL, server.Client())
	return c, func() (int, int) { mu.Lock(); defer mu.Unlock(); return requests, followUps }
}

// TestSingleEvidenceFollowUp (AC5): a named item the snapshot resolves yields
// exactly one follow-up carrying it; an unresolvable item yields none; no
// record gets a second follow-up.
func TestSingleEvidenceFollowUp(t *testing.T) {
	// Four assessment requests allow one follow-up under the 25% cap.
	r := followUpReport(t, "helper1", "missing_a", "missing_b", "missing_c")
	c, counts := followUpStub(t)
	c.AssessScheduled(context.Background(), r, ScheduleOptions{Limit: 100, Concurrency: 2})
	requests, followUps := counts()
	if requests != 5 || followUps != 1 {
		t.Fatalf("requests %d follow-ups %d, want 4 assessments and 1 follow-up", requests, followUps)
	}
	got := r.Uses[0].Assessment.FollowUp
	if got == nil || got.Status != "sent" || got.Evidence == nil || !strings.Contains(got.Evidence.Text, "def helper1") || got.Symbol != "helper1" {
		t.Fatalf("follow-up: %+v", got)
	}
	for _, u := range r.Uses[1:] {
		if f := u.Assessment.FollowUp; f == nil || f.Status != "unresolved" {
			t.Fatalf("unresolvable item: %+v", f)
		}
	}
	summary := strings.Join(r.Limitations, "\n")
	if !strings.Contains(summary, "Evidence follow-ups: 1 sent beside 4 assessment requests") {
		t.Fatalf("follow-up counts missing from the run summary:\n%s", summary)
	}
}

// TestFollowUpCap (AC5, D-6): follow-ups never exceed 25% of assessment
// requests, in priority order; the rest record follow_up_cap_reached.
func TestFollowUpCap(t *testing.T) {
	r := followUpReport(t, "helper1", "helper2", "helper3", "helper4")
	c, counts := followUpStub(t)
	c.AssessScheduled(context.Background(), r, ScheduleOptions{Limit: 100, Concurrency: 4})
	requests, followUps := counts()
	if requests != 5 || followUps != 1 {
		t.Fatalf("requests %d follow-ups %d", requests, followUps)
	}
	status := []string{}
	for _, u := range r.Uses {
		status = append(status, u.Assessment.FollowUp.Status)
	}
	if strings.Join(status, ",") != "sent,follow_up_cap_reached,follow_up_cap_reached,follow_up_cap_reached" {
		t.Fatalf("cap order: %v", status)
	}
}
