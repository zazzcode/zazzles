package judge

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/pipeline"
	"github.com/zazzcode/zazzles/scan/internal/report"
)

// Entry access and state changes are context. They do not change the request
// bytes of a use this family does not own.
func TestExistingFamilyRequestsUnchanged(t *testing.T) {
	for _, fixture := range []string{"authorization", "coverage", "doctrine-sql", "doctrine-storage", "exposure", "logging", "mass-assignment", "operations", "services-ops", "twig"} {
		t.Run(fixture, func(t *testing.T) {
			checkExistingFamilyRequests(t, fixture)
		})
	}
}

func checkExistingFamilyRequests(t *testing.T, fixture string) {
	t.Helper()
	r, err := pipeline.Analyze(filepath.Join("..", "langphp", "testdata", "symfony", fixture), "")
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, u := range r.Uses {
		if u.Kind == analysis.AuthorizationKind || u.EntryFacts == nil || u.EntryFacts.Access == nil && len(u.EntryFacts.StateChanges) == 0 {
			continue
		}
		seen++
		full, err := json.Marshal(wireBundle(u))
		if err != nil {
			t.Fatal(err)
		}
		facts := *u.EntryFacts
		facts.Access, facts.StateChanges = nil, nil
		cleared := u
		cleared.EntryFacts = &facts
		bare, err := json.Marshal(wireBundle(cleared))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(full, bare) {
			t.Fatalf("%s request changed when access was removed", u.Kind)
		}
	}
	if seen == 0 {
		t.Fatal("fixture has no pre-existing use")
	}
}

// The SSRF request stays byte-identical when authorization is skipped and
// when the report links it to authorization findings.
func TestSSRFRequestUnchanged(t *testing.T) {
	r, err := pipeline.Analyze(filepath.Join("..", "langphp", "testdata", "symfony", "authorization"), "")
	if err != nil {
		t.Fatal(err)
	}
	ssrf := -1
	for i, u := range r.Uses {
		if u.Kind == "ssrf_candidate" {
			ssrf = i
			break
		}
	}
	if ssrf == -1 {
		t.Fatal("fixture has no SSRF use")
	}
	c, err := New("openai", "fixture-model", "offline")
	if err != nil {
		t.Fatal(err)
	}
	order := make([]int, len(r.Uses))
	for i := range order {
		order[i] = i
	}
	requestFor := func(opts ScheduleOptions) []byte {
		t.Helper()
		groups, excluded := c.plan(context.Background(), r, order, opts)
		if len(opts.SkippedFamilies) > 0 {
			skipped := 0
			for i, u := range r.Uses {
				if u.Kind == analysis.AuthorizationKind {
					if !strings.Contains(excluded[i].Reason, "--skip-family authorization") {
						t.Fatal("authorization use was not excluded by the skip-family option")
					}
					skipped++
				}
			}
			if skipped == 0 {
				t.Fatal("fixture has no authorization uses to exclude")
			}
		}
		for _, group := range groups {
			for _, candidate := range group {
				if candidate.index == ssrf {
					if candidate.previewErr != nil || len(candidate.preview.Request) == 0 {
						t.Fatalf("SSRF request preview is missing: %v", candidate.previewErr)
					}
					return candidate.preview.Request
				}
			}
		}
		t.Fatal("SSRF request not planned")
		return nil
	}
	if full, skipped := requestFor(ScheduleOptions{}), requestFor(ScheduleOptions{SkippedFamilies: []string{"authorization"}}); !bytes.Equal(full, skipped) {
		t.Fatal("skipping authorization changed the SSRF request")
	}
	r.Uses[ssrf].Assessment.Status = "completed"
	before, err := json.Marshal(wireBundle(r.Uses[ssrf]))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(before, []byte(`"authorization"`)) {
		t.Fatal("ssrf request contains authorization")
	}
	report.Enrich(r)
	if len(r.Findings[ssrf].RelatedFindings) == 0 {
		t.Fatal("fixture did not link the SSRF finding to an authorization finding")
	}
	after, err := json.Marshal(wireBundle(r.Uses[ssrf]))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("report enrichment changed the SSRF request")
	}
}
