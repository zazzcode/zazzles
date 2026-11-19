package judge

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"testing"
)

const resumeLinePrefix = "Judge resume:"

// savedFrom indexes a collected trace map the way the CLI loader would.
func savedFrom(traces ...map[string]DecisionTrace) *SavedDecisions {
	merged := map[string]DecisionTrace{}
	for _, m := range traces {
		for id, t := range m {
			merged[id] = t
		}
	}
	var named []NamedTrace
	for id, t := range merged {
		named = append(named, NamedTrace{Name: id, Trace: t})
	}
	return NewSavedDecisions(named, 0)
}

// runResumed runs a scenario with saved decisions supplied through ScheduleOptions.
func runResumed(t *testing.T, sc scheduleScenario, stub *scheduleStub, n int, saved *SavedDecisions) scheduleOutcome {
	t.Helper()
	c, r, opts := prepareScheduleScenario(t, sc, stub, n)
	opts.Resume = saved
	return runPrepared(t, c, r, opts, stub)
}

// withoutResumeLine returns the report JSON with only the D-4 line removed,
// and that line ("" when absent).
func withoutResumeLine(t *testing.T, o scheduleOutcome) ([]byte, string) {
	t.Helper()
	var r map[string]any
	if err := json.Unmarshal(o.Report, &r); err != nil {
		t.Fatal(err)
	}
	var keep []any
	line := ""
	for _, l := range r["limitations"].([]any) {
		if s := l.(string); strings.HasPrefix(s, resumeLinePrefix) {
			if line != "" {
				t.Fatal("resume line written twice")
			}
			line = s
			continue
		}
		keep = append(keep, l)
	}
	r["limitations"] = keep
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return data, line
}

func completedRequests(o scheduleOutcome) int {
	n := 0
	for _, tr := range o.Traces {
		if tr.HTTPStatus == 200 && tr.Retries == 0 {
			n++
		}
	}
	return n
}

func assertSameRun(t *testing.T, got, want scheduleOutcome) {
	t.Helper()
	g, line := withoutResumeLine(t, got)
	w, _ := withoutResumeLine(t, want)
	if !bytes.Equal(g, w) {
		t.Fatalf("resumed report differs beyond the resume line:\n%s\n%s", g, w)
	}
	if line == "" {
		t.Fatal("resumed report has no resume line")
	}
	if got.Failed != want.Failed || len(got.Traces) != len(want.Traces) {
		t.Fatalf("failed=%v/%v traces=%d/%d", got.Failed, want.Failed, len(got.Traces), len(want.Traces))
	}
	for id, tr := range want.Traces {
		a, _ := json.Marshal(got.Traces[id])
		b, _ := json.Marshal(tr)
		if !bytes.Equal(a, b) {
			t.Fatalf("trace %s differs", id)
		}
	}
}

// TestResumeMatchesUninterruptedRun is AC4: a run resumed from a halted run's
// traces equals one uninterrupted run except for the resume line, and sends
// only what the halted run did not complete.
func TestResumeMatchesUninterruptedRun(t *testing.T) {
	sc := scheduleScenario{name: "resume", groups: 7, members: 2, limit: 6, limits: &Limits{}}
	for _, n := range []int{1, 4} {
		t.Run(fmt.Sprintf("N=%d", n), func(t *testing.T) {
			stubA := &scheduleStub{status: failOrdinal(3, http.StatusBadRequest)}
			a := runScheduleScenario(t, sc, stubA, n)
			if !a.Failed {
				t.Fatal("run A must halt")
			}
			stubB := &scheduleStub{}
			b := runResumed(t, sc, stubB, n, savedFrom(a.Traces))
			stubC := &scheduleStub{}
			c := runScheduleScenario(t, sc, stubC, n)
			assertSameRun(t, b, c)
			if done := stubA.count() - 1; stubB.count() != stubC.count()-done {
				t.Fatalf("B sent %d, want %d - %d", stubB.count(), stubC.count(), done)
			}
			sentA := map[string]bool{}
			for k, body := range stubA.bodies {
				if k != 2 { // ordinal 3 failed
					sentA[string(body)] = true
				}
			}
			for _, body := range stubB.bodies {
				if sentA[string(body)] {
					t.Fatal("B resent a request A completed")
				}
			}
		})
	}
	t.Run("chained", func(t *testing.T) {
		a := runScheduleScenario(t, sc, &scheduleStub{status: failOrdinal(2, http.StatusBadRequest)}, 1)
		b := runResumed(t, sc, &scheduleStub{status: failOrdinal(2, http.StatusBadRequest)}, 1, savedFrom(a.Traces))
		if !a.Failed || !b.Failed {
			t.Fatal("A and B must both halt")
		}
		stub := &scheduleStub{}
		resumed := runResumed(t, sc, stub, 1, savedFrom(a.Traces, b.Traces))
		c := runScheduleScenario(t, sc, &scheduleStub{}, 1)
		assertSameRun(t, resumed, c)
		if stub.count() >= c.Requests {
			t.Fatalf("chained resume sent %d of %d", stub.count(), c.Requests)
		}
	})
}

// sortedKeys is a small helper for deterministic failure messages.
func sortedKeys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
