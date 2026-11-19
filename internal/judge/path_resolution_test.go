package judge

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
	"github.com/zazzcode/zazzles/internal/pipeline"
)

const comprehensionApp = `from flask import Flask, request

app = Flask(__name__)


@app.route("/read")
def read():
    parts = [s for s in request.args.get("name", "").split("/") if s != ""]
    name = parts[0]
    with open(name) as f:
        return f.read()
`

func comprehensionPathUse(t *testing.T) analysis.CandidateUse {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte(comprehensionApp), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("flask==2.0.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r, err := pipeline.Analyze(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range r.Uses {
		if u.Kind == "path_traversal_candidate" {
			return u
		}
	}
	t.Fatal("no path record")
	return analysis.CandidateUse{}
}

// TestFlowGapQuestionPath (AC2): the request names the comprehension span and
// the four answers; value_preserved with a verified chain yields a finding
// marked model-resolved; cannot_tell leaves the blocker.
func TestFlowGapQuestionPath(t *testing.T) {
	use := comprehensionPathUse(t)
	gaps := flowGapBlockers(use)
	if len(gaps) != 1 || gaps[0].Kind != "python_comprehension_unresolved" {
		t.Fatalf("want the comprehension flow gap, got %+v", use.Completeness.Blockers)
	}
	c, _ := New("openai", "fixture-model", "k")
	payload, err := c.payload(use)
	if err != nil {
		t.Fatal(err)
	}
	asked := payloadResolutionQuestions(payload)
	if len(asked) < 2 || !strings.HasPrefix(asked[0].name, resolvePrefix+"flow_g") || asked[1].name != asked[0].name+citeSuffix {
		t.Fatalf("flow-gap question pair missing: %+v", asked)
	}
	if !strings.Contains(asked[0].instructions, "python_comprehension_unresolved") {
		t.Fatalf("question does not name the span: %s", asked[0].instructions)
	}
	values := []string{}
	for _, ch := range asked[0].choices {
		values = append(values, ch["value"])
	}
	if strings.Join(values, ",") != "value_preserved,value_constrained,value_replaced,cannot_tell" {
		t.Fatalf("answers: %v", values)
	}
	if !strings.Contains(asked[1].choices[0]["value"], strings.TrimPrefix(asked[0].name, resolvePrefix+"flow_")) {
		t.Fatalf("offered chain skips the gap: %+v", asked[1].choices)
	}
	vulnerable := map[string]string{"path_traversal": "vulnerable", "containment_control": "none", "protection_coverage": "incomplete"}
	for _, tt := range []struct{ flow, status string }{
		{"value_preserved", "confirmed_vulnerability"},
		{"cannot_tell", "needs_evidence"},
		{"value_constrained", "needs_evidence"},
	} {
		t.Run(tt.flow, func(t *testing.T) {
			a := resolutionStub(t, vulnerable, tt.flow, nil).Assess(context.Background(), use)
			if a.Status != "completed" || a.FindingStatus != tt.status {
				t.Fatalf("status %s/%s blockers %+v reason %q", a.Status, a.FindingStatus, a.BlockingGaps, a.Reason)
			}
			if tt.status == "confirmed_vulnerability" && (!a.ModelResolved() || !strings.Contains(a.Reason, "Model-resolved")) {
				t.Fatalf("finding not marked model-resolved: %+v", a)
			}
			if tt.status == "needs_evidence" && (a.ModelResolved() || !hasGapKind(a.BlockingGaps, "python_comprehension_unresolved")) {
				t.Fatalf("blocker lost: %+v", a.BlockingGaps)
			}
		})
	}
}

// TestDisagreementNeedsWitness (AC4, D-5): a vulnerable verdict that
// contradicts the facts stands as a model-resolved finding only with a
// verified cited chain along an uncontained flow.
func TestDisagreementNeedsWitness(t *testing.T) {
	use := comprehensionPathUse(t)
	c := *use.Completeness
	c.Blockers = nil // isolate the witness question from the flow gap
	use.Completeness = &c
	facts := *use.Path
	facts.Paths = append([]analysis.PathFlow{}, use.Path.Paths...)
	for i := range facts.Paths {
		facts.Paths[i].Protection = "unknown" // the scanner holds no witness
	}
	use.Path = &facts
	analysispacks.Attach(&use)
	if pathHasWitness(use) {
		t.Fatal("fixture must lack a scanner witness")
	}
	vulnerable := map[string]string{"path_traversal": "vulnerable", "containment_control": "none", "protection_coverage": "incomplete"}
	t.Run("verified chain stands", func(t *testing.T) {
		a := resolutionStub(t, vulnerable, "", nil).Assess(context.Background(), use)
		if a.FindingStatus != "confirmed_vulnerability" || !a.ModelResolved() || verifiedResolution(&a, resolvePrefix+"witness", "") == nil {
			t.Fatalf("status %s blockers %+v resolutions %+v", a.FindingStatus, a.BlockingGaps, a.Resolutions)
		}
	})
	t.Run("no chain is inconsistent", func(t *testing.T) {
		a := resolutionStub(t, vulnerable, "", func(string) string { return citeNone }).Assess(context.Background(), use)
		if a.FindingStatus != "needs_evidence" || a.ModelResolved() || !hasGapKind(a.BlockingGaps, "path_answers_inconsistent") {
			t.Fatalf("status %s blockers %+v", a.FindingStatus, a.BlockingGaps)
		}
	})
	t.Run("invented hop is inconsistent", func(t *testing.T) {
		a := resolutionStub(t, vulnerable, "", func(v string) string { return v[strings.LastIndex(v, ">")+1:] }).Assess(context.Background(), use)
		if a.FindingStatus != "needs_evidence" || !hasGapKind(a.BlockingGaps, "path_answers_inconsistent") {
			t.Fatalf("status %s blockers %+v", a.FindingStatus, a.BlockingGaps)
		}
	})
	t.Run("an enforcing control is never overridden", func(t *testing.T) {
		guarded := use
		g := facts
		g.Paths = append([]analysis.PathFlow{}, facts.Paths...)
		g.Guards = append(append([]analysis.PathGuard{}, facts.Guards...), analysis.PathGuard{Kind: analysis.PathGuardAllowlist, Context: 0})
		for i := range g.Paths {
			g.Paths[i].Controls = []int{len(g.Guards) - 1}
		}
		guarded.Path = &g
		if citedWitness(guarded, &g, nil, g.Paths[0].Dependency) {
			t.Fatal("an allow-listed flow cannot carry a cited witness")
		}
	})
}
