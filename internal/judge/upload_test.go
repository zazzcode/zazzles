package judge

import (
	"path/filepath"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
	"github.com/zazzcode/zazzles/internal/pipeline"
)

// TestUploadPolicy (close-findings-gaps AC6, D-21) runs the policy over the
// PHP upload fixtures with stub answers: each changed case sits beside the
// neighbour that must not change.
func TestUploadPolicy(t *testing.T) {
	r, err := pipeline.Analyze(filepath.Join("..", "langphp", "testdata", "upload"), "")
	if err != nil {
		t.Fatal(err)
	}
	byFile := map[string]analysis.CandidateUse{}
	for _, u := range r.Uses {
		if u.Kind == "file_upload_candidate" {
			byFile[filepath.Base(u.Sink.Span.File)] = u
		}
	}
	answers := func(restriction, exposure, coverage string) map[string]string {
		return map[string]string{"type_restriction": restriction, "execution_exposure": exposure, "protection_coverage": coverage}
	}
	for _, tt := range []struct {
		name, file string
		answers    map[string]string
		status     string
	}{
		{"client extension with no control is Confirmed", "raw.php", answers("none", "served_executable", "incomplete"), "confirmed_vulnerability"},
		{"the same record answered unknown stays Review", "raw.php", answers("unknown", "unknown", "unknown"), "needs_evidence"},
		{"a client-declared type alone is Confirmed", "declared.php", answers("client_declared_only", "served_executable", "incomplete"), "confirmed_vulnerability"},
		{"claiming no control beside a recorded check is inconsistent", "declared.php", answers("none", "served_executable", "incomplete"), "needs_evidence"},
		{"an extension allow-list stays Review", "allowlist.php", answers("extension_allow_list", "served_static", "complete"), "needs_evidence"},
		{"an allow-list cannot be served_executable", "allowlist.php", answers("extension_allow_list", "served_executable", "complete"), "needs_evidence"},
		{"a generated name with a fixed extension is Protected", "generated.php", answers("none", "served_static", "complete"), "protected_for_claim"},
		{"a destination outside the served tree is Protected", "outside.php", answers("none", "not_served", "complete"), "protected_for_claim"},
		{"outside the served tree cannot be served_executable", "outside.php", answers("none", "served_executable", "complete"), "needs_evidence"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			u, ok := byFile[tt.file]
			if !ok {
				t.Fatalf("no upload record in %s", tt.file)
			}
			a := analysis.Assessment{Status: "completed", QuestionVersion: analysispacks.UploadProtocol, Answers: tt.answers}
			applyPolicy(u, &a)
			if a.FindingStatus != tt.status {
				t.Fatalf("status %s blockers %+v reason %q", a.FindingStatus, a.BlockingGaps, a.Reason)
			}
		})
	}
	// The request carries the upload protocol's three questions.
	q := requestQuestionNames(t, byFile["raw.php"])
	for _, name := range []string{"type_restriction", "execution_exposure", "protection_coverage"} {
		if !q[name] {
			t.Fatalf("question %s missing from %v", name, q)
		}
	}
}
