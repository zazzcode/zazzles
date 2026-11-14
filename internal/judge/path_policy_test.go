package judge

import (
	"context"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
	"github.com/zazzcode/zazzles/internal/parse"
)

// pathAnswers is a deliberately stubbed model answer set.
type pathAnswers map[string]string

var (
	// honestRaw is the truthful answer for request text reaching a path operand unguarded.
	honestRaw = pathAnswers{"path_traversal": "vulnerable", "containment_control": "none", "protection_coverage": "incomplete"}
	// optimisticBoundary claims a lexical boundary protects everything, whatever the source shows.
	optimisticBoundary  = pathAnswers{"path_traversal": "protected", "containment_control": "lexical_boundary", "protection_coverage": "complete"}
	optimisticAllowlist = pathAnswers{"path_traversal": "protected", "containment_control": "finite_allowlist", "protection_coverage": "complete"}
	protectedResolved   = pathAnswers{"path_traversal": "protected", "containment_control": "resolved_boundary", "protection_coverage": "complete"}
	unknownAnswers      = pathAnswers{"path_traversal": "unknown", "containment_control": "unknown", "protection_coverage": "unknown"}
)

func pathStub(t *testing.T, provider string, answers pathAnswers) (*Client, *int) {
	return commandStub(t, provider, commandAnswers(answers))
}

func pathUsesByRoute(t *testing.T, fixture string) (map[string]analysis.CandidateUse, *analysis.AnalysisReport) {
	t.Helper()
	r, err := parse.Analyze("../parse/testdata/"+fixture, "")
	if err != nil {
		t.Fatal(err)
	}
	routes := map[string]string{}
	for _, e := range r.Entries {
		routes[e.ID] = e.HTTPRoute().PathPattern
	}
	out := map[string]analysis.CandidateUse{}
	for _, u := range r.Uses {
		if u.Kind == "path_traversal_candidate" {
			out[routes[u.EntryID]] = u
		}
	}
	return out, r
}

func pathUsesOf(r *analysis.AnalysisReport) []analysis.CandidateUse {
	var out []analysis.CandidateUse
	for _, u := range r.Uses {
		if u.Kind == "path_traversal_candidate" {
			out = append(out, u)
		}
	}
	return out
}

// TestPathPolicyMatrix drives the same independent source shapes through the
// model-answer policy in TypeScript and Python: a truthful vulnerable answer
// confirms only a supported witness, an over-claimed protection never closes a
// blocker, and an unmodeled or bare control stays unresolved.
func TestPathPolicyMatrix(t *testing.T) {
	const confirmed, protected, needs, poor = "confirmed_vulnerability", "protected_for_claim", "needs_evidence", "poor_practice"
	// A row names the same source shape by its route in each language fixture.
	type row struct {
		ts, py  string
		answers pathAnswers
		want    string
		blocker string // expected blocking gap kind, when relevant
	}
	rows := []row{
		{"/v/join-read", "/v/join", honestRaw, confirmed, ""},
		{"/v/resolve-sync", "/v/open", honestRaw, confirmed, ""},
		{"/v/write", "/v/write", honestRaw, confirmed, ""},
		{"/v/promises", "/v/io-open", honestRaw, confirmed, ""},
		{"/v/normalize-only", "/v/normpath-only", honestRaw, confirmed, ""},
		{"/v/direct", "/v/open", honestRaw, confirmed, ""},
		{"/v/try-catch", "/v/try-except", honestRaw, confirmed, ""},
		{"/v/blacklist", "/v/blacklist", honestRaw, confirmed, ""},
		{"/v/reassigned", "/v/reassigned", honestRaw, confirmed, ""},
		{"/v/sibling-branch", "/v/sibling-branch", honestRaw, confirmed, ""},
		{"/v/helper", "/v/helper", honestRaw, confirmed, ""},
		// over-claimed protection on raw paths is inconsistent, never green
		{"/v/join-read", "/v/join", optimisticBoundary, needs, "path_answers_inconsistent"},
		{"/v/reassigned", "/v/reassigned", optimisticAllowlist, needs, "path_answers_inconsistent"},
		{"/v/sibling-branch", "/v/sibling-branch", optimisticAllowlist, needs, "path_answers_inconsistent"},
		{"/v/blacklist", "/v/blacklist", optimisticBoundary, needs, "path_answers_inconsistent"},
		// enforced containment on the same value
		{"/p/allowlist", "/p/allowlist", optimisticAllowlist, protected, ""},
		{"/p/allowlist-array", "/p/allowlist-tuple", optimisticAllowlist, protected, ""},
		{"/p/prefix-boundary", "/p/prefix-boundary", optimisticBoundary, protected, ""},
		{"/p/relative", "/p/commonpath", optimisticBoundary, protected, ""},
		{"/p/realpath", "/p/realpath", protectedResolved, protected, ""},
		// a protected path cannot be reported vulnerable
		{"/p/allowlist", "/p/allowlist", honestRaw, needs, "path_answers_inconsistent"},
		{"/p/prefix-boundary", "/p/prefix-boundary", honestRaw, needs, "path_answers_inconsistent"},
		// resolved containment needs a realpath result in the source
		{"/p/prefix-boundary", "/p/prefix-boundary", protectedResolved, needs, "path_answers_inconsistent"},
		{"/p/allowlist", "/p/allowlist", optimisticBoundary, needs, "path_answers_inconsistent"},
		// unknown controls
		{"/u/prefix-bare", "/u/prefix-bare", optimisticBoundary, needs, "path_answers_inconsistent"},
		{"/u/prefix-bare", "/u/prefix-bare", honestRaw, poor, ""},
		{"/u/missing-helper", "/u/missing-helper", honestRaw, needs, ""},
		{"/u/missing-helper", "/u/missing-helper", optimisticBoundary, needs, ""},
		{"/u/basename", "/u/basename", honestRaw, needs, "path_answers_inconsistent"},
		{"/u/basename", "/u/basename", unknownAnswers, needs, ""},
		{"/v/join-read", "/v/join", unknownAnswers, needs, ""},
	}
	for _, fixture := range []struct {
		dir   string
		route func(row) string
	}{
		{"typescript/path-traversal", func(r row) string { return r.ts }},
		{"python/path-traversal", func(r row) string { return r.py }},
	} {
		uses, _ := pathUsesByRoute(t, fixture.dir)
		for _, tt := range rows {
			route := fixture.route(tt)
			u, ok := uses[route]
			if !ok {
				t.Fatalf("%s: no candidate for %s", fixture.dir, route)
			}
			t.Run(fixture.dir+route+"/"+tt.want+"/"+tt.answers["path_traversal"]+"-"+tt.answers["containment_control"], func(t *testing.T) {
				c, _ := pathStub(t, "openai", tt.answers)
				a := c.Assess(context.Background(), u)
				if a.Status != "completed" || a.FindingStatus != tt.want || a.QuestionVersion != analysispacks.PathProtocol {
					t.Fatalf("assessment %+v, want %s", a, tt.want)
				}
				if tt.blocker != "" {
					found := false
					for _, g := range a.BlockingGaps {
						found = found || g.Kind == tt.blocker
					}
					if !found {
						t.Fatalf("blocking gaps %+v lack %s", a.BlockingGaps, tt.blocker)
					}
				}
				if tt.want == confirmed && (len(a.BlockingGaps) != 0 || a.Protection != "insufficient") {
					t.Fatalf("confirmed with blockers or wrong protection: %+v", a)
				}
				if tt.want == protected && a.Protection != "sufficient" {
					t.Fatalf("protected label: %+v", a)
				}
				if tt.want == poor && (len(a.BlockingGaps) != 0 || a.Protection != "insufficient") {
					t.Fatalf("poor practice with blockers or wrong label: %+v", a)
				}
				if tt.want == needs && (a.FindingStatus == confirmed || a.FindingStatus == protected || a.FindingStatus == poor) {
					t.Fatal("unresolved record became final")
				}
			})
		}
	}
}

func TestPathPolicyFacts(t *testing.T) {
	uses, _ := pathUsesByRoute(t, "typescript/path-traversal")
	base := uses["/p/allowlist"]
	assess := func(mutate func(*analysis.CandidateUse), answers pathAnswers) analysis.Assessment {
		u := base
		f := *base.Path
		f.Paths = append([]analysis.PathFlow{}, base.Path.Paths...)
		u.Path = &f
		mutate(&u)
		c, _ := pathStub(t, "openai", answers)
		return c.Assess(context.Background(), u)
	}
	t.Run("allow-list then decode is not covered", func(t *testing.T) {
		a := assess(func(u *analysis.CandidateUse) { u.Path.Paths[0].DecodedAfterGuard = true }, optimisticAllowlist)
		if a.FindingStatus != "needs_evidence" || !strings.Contains(a.Reason, "contradict") {
			t.Fatalf("%+v", a)
		}
		// nor does the void control turn it into a confirmed finding
		if a := assess(func(u *analysis.CandidateUse) { u.Path.Paths[0].DecodedAfterGuard = true }, honestRaw); a.FindingStatus == "confirmed_vulnerability" {
			t.Fatalf("%+v", a)
		}
	})
	t.Run("unresolved flow cannot be complete", func(t *testing.T) {
		a := assess(func(u *analysis.CandidateUse) { u.Path.Paths[0].Protection = "unknown" }, optimisticAllowlist)
		if a.FindingStatus != "needs_evidence" {
			t.Fatalf("%+v", a)
		}
	})
	t.Run("missing path operand evidence", func(t *testing.T) {
		a := assess(func(u *analysis.CandidateUse) {
			c := *u.Completeness
			c.Evidence = map[string][]analysis.Evidence{}
			for k, v := range u.Completeness.Evidence {
				if k != "path_operands" {
					c.Evidence[k] = v
				}
			}
			u.Completeness = &c
		}, optimisticAllowlist)
		if a.FindingStatus != "needs_evidence" || len(a.BlockingGaps) == 0 || a.BlockingGaps[0].Kind != "path_evidence_missing" {
			t.Fatalf("%+v", a)
		}
	})
	t.Run("invalid facts", func(t *testing.T) {
		a := assess(func(u *analysis.CandidateUse) { u.Path.Platform = "windows" }, optimisticAllowlist)
		if a.FindingStatus != "needs_evidence" {
			t.Fatalf("%+v", a)
		}
	})
	t.Run("wrong protocol", func(t *testing.T) {
		u := base
		a := &analysis.Assessment{Answers: map[string]string(optimisticAllowlist), QuestionVersion: "path-components-v0"}
		applyPathPolicy(u, a)
		if a.FindingStatus == "protected_for_claim" {
			t.Fatalf("%+v", a)
		}
	})
	t.Run("global blocker voids a witness, scoped blocker does not", func(t *testing.T) {
		raw := uses["/v/join-read"]
		c := *raw.Completeness
		c.Blockers = []analysis.Gap{{Kind: "unrelated_helper", Detail: "elsewhere", At: raw.Sink.Span}}
		raw.Completeness = &c
		if a := func() analysis.Assessment {
			cl, _ := pathStub(t, "openai", honestRaw)
			return cl.Assess(context.Background(), raw)
		}(); a.FindingStatus == "confirmed_vulnerability" {
			t.Fatalf("global blocker ignored: %+v", a)
		}
	})
}
