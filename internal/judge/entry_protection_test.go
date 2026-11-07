package judge

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/parse"
	"github.com/zazzcode/zazzles/internal/report"
)

func TestEntryProtectionCoverage(t *testing.T) {
	for _, tc := range []struct {
		fixture                       string
		confirmed, protected, unknown int
	}{
		{"javascript/browser-events", 2, 1, 1}, {"typescript/dynamic-dispatch", 1, 1, 0},
		{"javascript/graphql", 3, 2, 1}, {"javascript/grpc", 2, 2, 2},
		{"python/dynamic-vulnpy/independent-controls", 2, 2, 1},
	} {
		fixture := tc.fixture
		t.Run(fixture, func(t *testing.T) {
			r, err := parse.Analyze("../parse/testdata/"+fixture, "")
			if err != nil {
				t.Fatal(err)
			}
			counts := assessEntryControls(t, r, !strings.HasPrefix(fixture, "python/"))
			if counts["confirmed_vulnerability"] != tc.confirmed || counts["protected_for_claim"] != tc.protected || counts["needs_evidence"] != tc.unknown {
				t.Fatalf("source-reviewed outcome counts changed: %v", counts)
			}
			if base := os.Getenv("ZAZZ_TEST_ACCEPTANCE_REPORTS"); base != "" {
				r.Limitations = append(r.Limitations, "SYNTHETIC LOCAL STUB: policy controls only; no model accuracy or runtime claim.")
				if _, err := report.WriteBundle(filepath.Join(base, "stub", fixture), r); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
	t.Run("mixed", func(t *testing.T) {
		base := t.TempDir()
		if artifacts := os.Getenv("ZAZZ_TEST_ACCEPTANCE_REPORTS"); artifacts != "" {
			base = artifacts
			if err := os.MkdirAll(base, 0700); err != nil {
				t.Fatal(err)
			}
		}
		root, err := os.MkdirTemp(base, "mixed-source-")
		if err != nil {
			t.Fatal(err)
		}
		for _, fixture := range []struct{ source, dest string }{
			{"javascript/grpc", ""}, {"python/dynamic-vulnpy/apps", "apps"}, {"python/dynamic-vulnpy/src", "src"}, {"python/dynamic-vulnpy/independent-controls", "independent-controls"}, {"javascript/graphql", "graphql"}, {"javascript/browser-events", "events"}, {"typescript/dynamic-dispatch", "http"},
		} {
			if err := os.CopyFS(filepath.Join(root, fixture.dest), os.DirFS("../parse/testdata/"+fixture.source)); err != nil {
				t.Fatal(err)
			}
		}
		r, err := parse.Analyze(root, "")
		if err != nil {
			t.Fatal(err)
		}
		predecessorUses := 0
		for _, u := range r.Uses {
			if u.Kind != "command_execution_candidate" {
				predecessorUses++
			}
		}
		if len(r.Entries) != 68 || predecessorUses != 53 {
			t.Fatal("mixed source inventory changed")
		}
		counts := assessEntryControls(t, r, true)
		if counts["confirmed_vulnerability"] != 22 || counts["protected_for_claim"] != 8 || counts["needs_evidence"] != 6 {
			t.Fatalf("mixed source-reviewed outcomes changed: %v", counts)
		}
		if artifacts := os.Getenv("ZAZZ_TEST_ACCEPTANCE_REPORTS"); artifacts != "" {
			r.Limitations = append(r.Limitations, "SYNTHETIC LOCAL STUB: policy controls only; no model accuracy or runtime claim.")
			bundle, err := report.WriteBundle(filepath.Join(artifacts, "stub", "mixed"), r)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("mixed source %s; assessed bundle %s", root, bundle)
		}
	})

}

func assessEntryControls(t *testing.T, r *analysis.AnalysisReport, wantZero bool) map[string]int {
	t.Helper()
	current := analysis.CandidateUse{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var body struct {
			Questions []struct {
				Name string `json:"name"`
			} `json:"questions"`
		}
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		choices := map[string]string{"validation": "uncertain", "protection": "insufficient", "injection_protection": "vulnerable", "output_context": "html_text", "encoding_adequacy": "not_present", "sanitizer_effectiveness": "absent", "xss_all_paths_protected": "no", "xss_exposure": "vulnerable"}
		// Deliberately overclaim unknown transforms/guards: structural policy must reject them.
		if controlProtected(current) {
			choices["protection"] = "sufficient"
			choices["injection_protection"] = "protected"
			choices["encoding_adequacy"] = "adequate"
			choices["xss_all_paths_protected"] = "yes"
			choices["xss_exposure"] = "protected"
		}
		answers := []map[string]string{}
		for _, q := range body.Questions {
			answers = append(answers, map[string]string{"name": q.Name, "type": "choice", "choice": choices[q.Name]})
		}
		json.NewEncoder(w).Encode(map[string]any{"model": "fixture-model", "answers": answers})
	}))
	defer server.Close()
	c, err := New("openai", "fixture-model", "synthetic-test-key")
	if err != nil {
		t.Fatal(err)
	}
	c.endpoint = server.URL
	c.http = server.Client()
	counts := map[string]int{}
	byEntry := map[string]int{}
	checked := 0
	for _, u := range r.Uses {
		byEntry[u.EntryID]++
	}
	for i := range r.Uses {
		u := &r.Uses[i]
		if u.Kind != "sql_query_candidate" && u.XSS == nil {
			continue
		}
		current = *u
		want := "confirmed_vulnerability"
		if controlProtected(*u) {
			want = "protected_for_claim"
		}
		if u.XSS != nil && u.XSS.Protection == "unknown" || strings.Contains(strings.ToLower(report.EntryLabel(*u.EntryFacts)), "unknown") {
			want = "needs_evidence"
		}
		got, trace := c.AssessTrace(context.Background(), *u)
		if got.Status != "completed" || got.FindingStatus != want {
			t.Errorf("%s %s: want %s got %+v", report.EntryLabel(*u.EntryFacts), u.Kind, want, got)
		}
		if c.Replay(*u, trace).Status != "completed" {
			t.Fatal("exact replay rejected")
		}
		changed := *u
		changed.InvocationContextID += "-different"
		if c.Replay(changed, trace).Status != "failed" {
			t.Fatal("cross-context replay accepted")
		}
		u.Assessment = got
		counts[got.FindingStatus]++
		checked++
	}
	if checked == 0 || counts["protected_for_claim"] == 0 || counts["confirmed_vulnerability"] == 0 {
		t.Fatalf("missing positive/negative/unknown controls: %v", counts)
	}
	zero := 0
	for _, e := range r.Entries {
		if byEntry[e.ID] == 0 {
			zero++
		}
	}
	// Independent Python controls have five used entries; other sets include zero-use entries.
	if zero == 0 && wantZero {
		t.Fatal("zero-use inventory missing")
	}
	report.Enrich(r)
	byUse := map[string]analysis.Finding{}
	review := 0
	for _, f := range r.Findings {
		byUse[f.UseID] = f
		if f.Status == "needs_evidence" || f.Status == "needs_review" {
			review++
		}
	}
	if review == 0 {
		t.Fatal("unknown coverage disappeared from final report")
	}
	for _, u := range r.Uses {
		if u.Assessment.FindingStatus == "needs_evidence" && byUse[u.ID].Status == "protected_for_claim" {
			t.Fatal("unknown acquired protection")
		}
		if u.EntryFacts != nil && (u.EntryFacts.GraphQL != nil && u.EntryFacts.GraphQL.Field == "guarded" || u.EntryFacts.GRPC != nil && u.EntryFacts.GRPC.Method == "Guarded") && byUse[u.ID].Status == "protected_for_claim" {
			t.Fatal("scoped injection protection hid construction defect")
		}
	}
	if err := r.ValidateUses(); err != nil {
		t.Fatal(err)
	}
	t.Logf("assessed %d controls: %v; zero-use entries %d", checked, counts, zero)
	return counts
}

func controlProtected(u analysis.CandidateUse) bool {
	if u.XSS != nil {
		return u.XSS.Protection != "raw"
	}
	name := strings.ToLower(report.EntryLabel(*u.EntryFacts))
	return strings.Contains(name, "bound") || strings.Contains(name, "guarded") || strings.Contains(name, "unknown")
}
