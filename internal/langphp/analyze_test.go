package langphp

import (
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
	"github.com/zazzcode/zazzles/internal/parse"
	"github.com/zazzcode/zazzles/internal/walk"
)

// Analyze, AnalyzeWithChecks and AnalyzeWithOptions keep the package's tests on
// one unqualified call. They run the JS base report and the PHP runner with the
// pipeline's selection, then share production's Assemble; internal/pipeline
// owns production orchestration. PHP fixtures hold no Python files.
func Analyze(root, entry string) (*analysis.AnalysisReport, error) {
	return AnalyzeWithChecks(root, entry, nil)
}

func AnalyzeWithChecks(root, entry string, checks []analysis.Check) (*analysis.AnalysisReport, error) {
	return AnalyzeWithOptions(root, entry, checks, parse.Options{})
}

func AnalyzeWithOptions(root, entry string, checks []analysis.Check, options parse.Options) (*analysis.AnalysisReport, error) {
	if err := analysispacks.Validate(); err != nil {
		return nil, err
	}
	entry = parse.NormalizeEntry(entry)
	inv, err := testInventory(root)
	if err != nil {
		return nil, err
	}
	run := inv.Runners(entry)
	var js, php *analysis.AnalysisReport
	if run.JavaScript {
		js, err = parse.RunJavaScript(inv, entry, checks, options)
	}
	if err == nil && run.PHP {
		php, err = Run(inv, entry, checks)
	}
	if err != nil {
		return nil, err
	}
	out, err := parse.Assemble(entry, js, nil, php)
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

// newPHPSet opens a set over a fresh walk for set-level tests.
func newPHPSet(root string) (*phpSet, error) {
	inv, err := testInventory(root)
	if err != nil {
		return nil, err
	}
	return openPHPSet(inv)
}

// The PHP half of internal/parse's TestRunnersWithoutSourcesOpenNoGrammar: an
// inventory with no PHP files runs no PHP set, and a PHP entry keeps its
// selection error.
func TestRunnersWithoutSourcesOpenNoGrammar(t *testing.T) {
	inv, err := testInventory("../parse/testdata/python/routes")
	if err != nil {
		t.Fatal(err)
	}
	if php, err := Run(inv, "", nil); php != nil || err != nil {
		t.Fatalf("Run = %v, %v; want nil, nil", php, err)
	}
	if _, err := Run(inv, "missing.php", nil); err == nil {
		t.Fatal("a PHP entry without PHP files must keep its selection error")
	}
}
