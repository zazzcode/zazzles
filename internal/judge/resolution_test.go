package judge

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
	"github.com/zazzcode/zazzles/internal/pipeline"
)

// bypassCitation is a verified bypass citation of the use's first guarded
// command path, as resolveAnswers records it.
func bypassCitation(u analysis.CandidateUse) []analysis.Resolution {
	if u.Command == nil {
		return nil
	}
	for _, p := range u.Command.Paths {
		if p.Protection == "guarded" {
			d := p.Dependency
			return []analysis.Resolution{{Question: resolvePrefix + "bypass", QuestionVersion: BypassQuestionVersion, Answer: "bypass_identified", Citation: []string{"e0", "e1"}, Verified: true, Dependency: &d}}
		}
	}
	return nil
}

// TestCommandBypassCitation (AC1, D-8): a bypass_identified answer needs a
// verified citation of a guarded path of the unsafe facet.
func TestCommandBypassCitation(t *testing.T) {
	weak := guardedCommandUse(t, map[string]string{"package.json": `{"dependencies":{"express":"4.18.2"}}`, "server.js": weakRegexJS})
	vulnerable := commandAnswers{"shell_syntax_protection": "vulnerable", "executable_control": "not_applicable", "argument_control": "not_applicable", "guard_bypass": "bypass_identified", "protection_coverage": "incomplete"}
	verified := bypassCitation(weak)
	if verified == nil {
		t.Fatal("fixture has no guarded path")
	}
	unverified := []analysis.Resolution{verified[0]}
	unverified[0].Verified, unverified[0].Rejection = false, "hop e0>e1 is neither a scanner edge nor the asked gap"
	other := 99
	offFacet := []analysis.Resolution{verified[0]}
	offFacet[0].Dependency = &other
	for _, tt := range []struct {
		name        string
		resolutions []analysis.Resolution
		status      string
		discharged  bool
	}{
		{"verified citation stands", verified, "confirmed_vulnerability", true},
		{"no citation stays Review", nil, "needs_evidence", false},
		{"unverified citation stays Review", unverified, "needs_evidence", false},
		{"citation of another path stays Review", offFacet, "needs_evidence", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			a := analysis.Assessment{Status: "completed", QuestionVersion: analysispacks.CommandProtocol, Answers: vulnerable, Resolutions: append([]analysis.Resolution{}, tt.resolutions...)}
			applyCommandPolicy(weak, &a)
			if a.FindingStatus != tt.status || a.ModelResolved() != tt.discharged {
				t.Fatalf("status %s model-resolved %v blockers %+v", a.FindingStatus, a.ModelResolved(), a.BlockingGaps)
			}
			if tt.status == "needs_evidence" && !hasGapKind(a.BlockingGaps, "command_guard_semantics_unknown") {
				t.Fatalf("want command_guard_semantics_unknown, got %+v", a.BlockingGaps)
			}
		})
	}
}

// testWire is a compacted request: e0 source, e1 transfer, e2 transfer, e3
// sink, e4 a second source; g0 overlaps e1 (line 3); g1 is another gap.
func testWire() *wireIndex {
	use := map[string]any{
		"sink_evidence": "e3",
		"evidence": []any{
			[]any{"input_source", 0.0, 2.0, 2.0, "req.query.name"},
			[]any{"assignment", 0.0, 3.0, 3.0, "x = [s for s in name]"},
			[]any{"assignment", 0.0, 4.0, 4.0, "y = x[0]"},
			[]any{"sql_query_candidate", 0.0, 5.0, 5.0, "db.query(y)"},
			[]any{"input_source", 0.0, 9.0, 9.0, "req.body.other"},
		},
		"dependencies": []any{
			map[string]any{"source": "e0", "transfers": []any{"e1", "e2"}},
			map[string]any{"source": "e4", "transfers": []any{}},
		},
		"control_edges": []any{},
		"compact_wire": map[string]any{
			"sources": []any{[]any{"app.js"}},
			"gaps":    []any{[]any{"unknown_transfer", 0.0, 0.0, 3.0, 3.0}, []any{"transfer_limit", 0.0, 0.0, 9.0, 9.0}},
		},
	}
	x, err := indexWire(use)
	if err != nil {
		panic(err)
	}
	return x
}

// TestResolutionCitationVerifier (AC1, D-2) is the one verifier's table.
func TestResolutionCitationVerifier(t *testing.T) {
	x := testWire()
	for _, tt := range []struct {
		name, asked, reject string
		cite                []string
		dependency          int
	}{
		{"valid chain through the asked gap", "g0", "", []string{"e0", "e1", "g0", "e2", "e3"}, 0},
		{"valid witness over scanner edges", "", "", []string{"e0", "e1", "e2", "e3"}, 0},
		{"second dependency witness", "", "", []string{"e4", "e3"}, 1},
		{"unknown ID", "g0", "was not in the request", []string{"e0", "e1", "g0", "e9", "e3"}, -1},
		{"extra invented hop", "", "neither a scanner edge", []string{"e0", "e2", "e3"}, -1},
		{"chain skips the asked gap", "g0", "skips the asked gap", []string{"e0", "e1", "e2", "e3"}, -1},
		{"cites another gap", "g0", "not the gap the question asked", []string{"e0", "g1", "e3"}, -1},
		{"gap on a dependency it does not touch", "g0", "does not start at the source of a dependency the asked gap touches", []string{"e4", "g0", "e3"}, -1},
		{"gap away from its span", "g0", "does not bridge", []string{"e0", "e1", "e2", "g0", "e3"}, -1},
		{"does not reach the sink", "", "does not end at the sink", []string{"e0", "e1", "e2"}, -1},
		{"empty citation", "g0", "empty citation", nil, -1},
		{"repeated ID", "", "repeats", []string{"e0", "e1", "e1", "e3"}, -1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c, reason := verifyCitation(x, tt.cite, tt.asked)
			if tt.reject == "" {
				if reason != "" || c.dependency != tt.dependency || len(c.spans) != len(tt.cite) {
					t.Fatalf("want verified dependency %d, got %q dependency %d spans %d", tt.dependency, reason, c.dependency, len(c.spans))
				}
				return
			}
			if !strings.Contains(reason, tt.reject) {
				t.Fatalf("want rejection containing %q, got %q", tt.reject, reason)
			}
		})
	}
}

// resolutionStub answers the family questions from values, every flow-gap
// question with flow, and every citation question with its first offered
// chain (or tamper(chain) when tamper is set).
func resolutionStub(t *testing.T, values map[string]string, flow string, tamper func(string) string) *Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var body struct {
			Questions []struct {
				Name    string              `json:"name"`
				Choices []map[string]string `json:"choices"`
			} `json:"questions"`
		}
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
			t.Error(err)
			return
		}
		answers := []map[string]string{}
		for _, q := range body.Questions {
			choice := values[q.Name]
			switch {
			case strings.HasSuffix(q.Name, citeSuffix):
				choice = q.Choices[0]["value"]
				if tamper != nil {
					choice = tamper(choice)
				}
			case strings.HasPrefix(q.Name, resolvePrefix+"flow_"):
				choice = flow
			}
			answers = append(answers, map[string]string{"name": q.Name, "type": "choice", "choice": choice})
		}
		json.NewEncoder(w).Encode(map[string]any{"model": "fixture-model", "answers": answers})
	}))
	t.Cleanup(server.Close)
	c, _ := New("openai", "fixture-model", "synthetic-test-key")
	c.UseEndpoint(server.URL, server.Client())
	return c
}

// flowGapSQLUse returns a fixture SQL record blocked only by flow gaps that
// have resolution questions.
func flowGapSQLUse(t *testing.T) analysis.CandidateUse {
	t.Helper()
	r, err := pipeline.Analyze(fixtureRoot("javascript/graphql"), "")
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range r.Uses {
		if u.Kind != "sql_query_candidate" || len(flowGapBlockers(u)) == 0 {
			continue
		}
		// Keep only the flow gap: the fixture's helper blocker has no
		// question, and blockers do not enter component selection.
		c := *u.Completeness
		c.Blockers = flowGapBlockers(u)
		u.Completeness = &c
		return u
	}
	t.Fatal("no SQL record blocked only by resolvable flow gaps")
	return analysis.CandidateUse{}
}

// TestResolutionDischargesBlocker (AC1): a verified value_preserved chain
// discharges the flow gap and records provenance; an invented ID, a skipped
// gap or cannot_tell changes nothing and the rejection is recorded.
func TestResolutionDischargesBlocker(t *testing.T) {
	use := flowGapSQLUse(t)
	vulnerable := map[string]string{"validation": "insufficient", "protection": "insufficient", "injection_protection": "vulnerable"}
	for _, tt := range []struct {
		name, flow, status, rejection string
		tamper                        func(string) string
		discharged                    bool
	}{
		{"verified chain discharges", "value_preserved", "confirmed_vulnerability", "", nil, true},
		{"cannot_tell leaves the blocker", "cannot_tell", "needs_evidence", "", nil, false},
		{"value_constrained stays Review", "value_constrained", "needs_evidence", "", nil, false},
		{"invented ID is rejected", "value_preserved", "needs_evidence", "was not in the request", func(v string) string { return strings.Replace(v, ">", ">e999>", 1) }, false},
		{"skipped gap is rejected", "value_preserved", "needs_evidence", "skips the asked gap", func(v string) string {
			ids := []string{}
			for _, id := range strings.Split(v, ">") {
				if !strings.HasPrefix(id, "g") {
					ids = append(ids, id)
				}
			}
			return strings.Join(ids, ">")
		}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := resolutionStub(t, vulnerable, tt.flow, tt.tamper)
			a := c.Assess(context.Background(), use)
			if a.Status != "completed" || a.FindingStatus != tt.status || a.ModelResolved() != tt.discharged {
				t.Fatalf("status %s/%s model-resolved %v blockers %+v resolutions %+v", a.Status, a.FindingStatus, a.ModelResolved(), a.BlockingGaps, a.Resolutions)
			}
			if len(a.Resolutions) == 0 {
				t.Fatal("no resolution recorded")
			}
			r := a.Resolutions[0]
			if r.Provider != "openai" || r.Model != "fixture-model" || r.QuestionVersion != FlowGapQuestionVersion || r.Blocker == nil || len(r.Citation) == 0 {
				t.Fatalf("provenance missing: %+v", r)
			}
			if tt.rejection != "" && (r.Verified || !strings.Contains(r.Rejection, tt.rejection)) {
				t.Fatalf("want rejection %q, got %+v", tt.rejection, r)
			}
			if tt.discharged && (!r.Discharged || len(a.BlockingGaps) != 0 || !strings.Contains(a.Reason, "Model-resolved")) {
				t.Fatalf("discharge not visible: %+v reason %q", r, a.Reason)
			}
			for name := range a.Answers {
				if strings.HasPrefix(name, resolvePrefix) {
					t.Fatalf("resolution answer %s left in the family answers", name)
				}
			}
			// Replay reproduces the same resolution from the saved request.
			_, trace := c.AssessTrace(context.Background(), use)
			replayed := c.Replay(use, trace)
			if replayed.FindingStatus != a.FindingStatus || len(replayed.Resolutions) != len(a.Resolutions) || replayed.ModelResolved() != a.ModelResolved() {
				t.Fatalf("replay differs: %+v", replayed)
			}
		})
	}
}

// TestResolutionGate (D-7): a fixing blocker without a question keeps the
// record from the judge; one with a question is sent.
func TestResolutionGate(t *testing.T) {
	use := flowGapSQLUse(t)
	if _, fixed := resolutionGate(use); fixed {
		t.Fatal("a record whose blockers all have questions must be sent")
	}
	blocked := use
	c := *use.Completeness
	c.Blockers = append(append([]analysis.Gap{}, c.Blockers...), analysis.Gap{Kind: "render_protection_unresolved", Detail: "x", At: use.Sink.Span})
	blocked.Completeness = &c
	a, fixed := resolutionGate(blocked)
	if !fixed || a.Status != "not_run" || !strings.HasPrefix(a.Reason, BlockerUnresolvable+":") || !hasGapKind(a.BlockingGaps, "render_protection_unresolved") || hasGapKind(a.BlockingGaps, "unknown_transfer") {
		t.Fatalf("gate: fixed %v %+v", fixed, a)
	}
}

func TestCitationLabelResolvesTextRef(t *testing.T) {
	// Deduplicated evidence names its text through text_ref; the citation
	// label must show that code, not an empty string.
	excerpts := []any{[]any{0, 10, 12, "  var url = m[1];\n  exec('identify ' + url, cb);\n}"}}
	if got := excerptText(excerpts, "s0", 11, 11, 3, 30); got != "exec('identify ' + url, cb)" {
		t.Fatalf("one line: %q", got)
	}
	if got := excerptText(excerpts, "s0", 10, 11, 7, 19); got != "url = m[1];\n  exec('identify '" {
		t.Fatalf("two lines: %q", got)
	}
	if excerptText(excerpts, "s9", 10, 10, 1, 2) != "" || excerptText(excerpts, "s0", 20, 20, 1, 2) != "" {
		t.Fatal("an unknown reference or line must give no text")
	}
}
