package langpy

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
	"github.com/zazzcode/zazzles/internal/langjs"
	"github.com/zazzcode/zazzles/internal/parse"
	"github.com/zazzcode/zazzles/internal/walk"
)

// Analyze and AnalyzeWithChecks keep the package's tests on one unqualified
// call. Like internal/pipeline they select runners from the inventory, build the
// JS/TS base report (D-6), run Python and share production's parse.Assemble, one
// after another in merge order. Tests that need PHP output live in internal/pipeline.
func Analyze(root, entry string) (*analysis.AnalysisReport, error) {
	return AnalyzeWithChecks(root, entry, nil)
}

func AnalyzeWithChecks(root, entry string, checks []analysis.Check) (*analysis.AnalysisReport, error) {
	if err := analysispacks.Validate(); err != nil {
		return nil, err
	}
	entry = parse.NormalizeEntry(entry)
	inv, err := testInventory(root)
	if err != nil {
		return nil, err
	}
	run := inv.Runners(entry)
	var js, py *analysis.AnalysisReport
	if run.JavaScript {
		js, err = langjs.Run(inv, entry, checks, parse.Options{})
	}
	if err == nil && run.Python {
		py, err = Run(inv, entry, checks)
	}
	if err != nil {
		return nil, err
	}
	out, err := parse.Assemble(entry, js, py, nil)
	if err != nil {
		return nil, err
	}
	out.RecordCheckMatches(checks)
	for i := range out.Uses {
		analysispacks.Attach(&out.Uses[i])
	}
	return out, nil
}

func testInventory(root string) (parse.Inventory, error) {
	files, err := walk.Walk(root, walk.Options{})
	if err != nil {
		return parse.Inventory{}, err
	}
	return parse.Inventory{Root: root, Files: files.Files}, nil
}

// newPythonSet opens a set over a fresh walk for set-level tests.
func newPythonSet(root string) (*pythonSet, error) {
	inv, err := testInventory(root)
	if err != nil {
		return nil, err
	}
	return openPythonSet(inv)
}

var update = flag.Bool("update", false, "rewrite golden files")

func kindUse(t *testing.T, report *analysis.AnalysisReport, kind string) analysis.CandidateUse {
	t.Helper()
	for _, use := range report.Uses {
		if use.Kind == kind {
			return use
		}
	}
	t.Fatalf("missing %s in %+v", kind, report.Uses)
	return analysis.CandidateUse{}
}

func gapKind(gaps []analysis.Gap, kind string) bool {
	for _, g := range gaps {
		if g.Kind == kind {
			return true
		}
	}
	return false
}

// The Python half of internal/parse's TestRunnersWithoutSourcesOpenNoGrammar:
// a Python-only inventory still produces the Python report.
func TestRunnersWithoutSourcesOpenNoGrammar(t *testing.T) {
	inv, err := testInventory("testdata/routes")
	if err != nil {
		t.Fatal(err)
	}
	if py, err := Run(inv, "", nil); err != nil || py == nil || len(py.Entries) == 0 {
		t.Fatalf("Run = %v, %v; want entries", py, err)
	}
}

func blockers(u analysis.CandidateUse) []analysis.Gap {
	if u.Completeness == nil {
		return nil
	}
	return u.Completeness.Blockers
}

func usesOf(r *analysis.AnalysisReport, kind, file string) []analysis.CandidateUse {
	var out []analysis.CandidateUse
	for _, u := range r.Uses {
		if u.Kind == kind && (file == "" || u.Sink.Span.File == file) {
			out = append(out, u)
		}
	}
	return out
}

func writeSource(t *testing.T, root, name, text string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(filepath.Join(root, name)), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, name), []byte(strings.TrimSpace(text)), 0644); err != nil {
		t.Fatal(err)
	}
}

func xssUses(r *analysis.AnalysisReport) []analysis.CandidateUse {
	var uses []analysis.CandidateUse
	for _, use := range r.Uses {
		if use.Kind == "xss_candidate" {
			uses = append(uses, use)
		}
	}
	return uses
}
