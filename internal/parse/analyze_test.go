package parse

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
	"github.com/zazzcode/zazzles/internal/walk"
)

// Analyze, AnalyzeWithChecks and AnalyzeWithOptions keep the package's
// internal tests on one unqualified call. They run the language runners in the
// fixed order and share production's Assemble; internal/pipeline owns the
// production orchestration and its concurrency.
func Analyze(root, entry string) (*analysis.AnalysisReport, error) {
	return AnalyzeWithChecks(root, entry, nil)
}

func AnalyzeWithChecks(root, entry string, checks []analysis.Check) (*analysis.AnalysisReport, error) {
	return AnalyzeWithOptions(root, entry, checks, Options{})
}

func AnalyzeWithOptions(root, entry string, checks []analysis.Check, options Options) (*analysis.AnalysisReport, error) {
	if err := analysispacks.Validate(); err != nil {
		return nil, err
	}
	entry = filepath.ToSlash(filepath.Clean(entry))
	if entry == "." {
		entry = ""
	}
	inv, err := testInventory(root)
	if err != nil {
		return nil, err
	}
	var js, py, php *analysis.AnalysisReport
	switch ext := strings.ToLower(filepath.Ext(entry)); {
	case ext == ".py":
		py, err = RunPython(inv, entry, checks)
	case ext == ".php" || ext == ".phtml":
		php, err = RunPHP(inv, entry, checks)
	default:
		js, err = RunJavaScript(inv, entry, checks, options)
		if err == nil && entry == "" {
			py, err = RunPython(inv, entry, checks)
		}
		if err == nil && entry == "" {
			php, err = RunPHP(inv, entry, checks)
		}
	}
	if err != nil {
		return nil, err
	}
	out, err := Assemble(entry, js, py, php)
	if err != nil {
		return nil, err
	}
	out.RecordCheckMatches(checks)
	for i := range out.Uses {
		analysispacks.Attach(&out.Uses[i])
	}
	return out, nil
}

func testInventory(root string) (Inventory, error) {
	files, err := walk.Walk(root, walk.Options{})
	if err != nil {
		return Inventory{}, err
	}
	return Inventory{Root: root, Files: files.Files}, nil
}

// newPythonSet and newPHPSet open a set over a fresh walk for set-level tests.
func newPythonSet(root string) (*pythonSet, error) {
	inv, err := testInventory(root)
	if err != nil {
		return nil, err
	}
	return openPythonSet(inv)
}

func newPHPSet(root string) (*phpSet, error) {
	inv, err := testInventory(root)
	if err != nil {
		return nil, err
	}
	return openPHPSet(inv)
}

// AC2: a Python-only inventory opens no JS grammar, loads no JS module and runs
// no PHP set; the JS base report and the Python report are still produced.
func TestRunnersWithoutSourcesOpenNoGrammar(t *testing.T) {
	inv, err := testInventory("testdata/python/routes")
	if err != nil {
		t.Fatal(err)
	}
	set, selected, err := openJavaScriptSet(inv)
	if err != nil {
		t.Fatal(err)
	}
	defer set.close()
	if set.parsers != nil || len(selected) != 0 {
		t.Fatalf("JS set opened grammars (%v) or selected %v", set.parsers != nil, selected)
	}
	base, err := set.javascriptReport(selected, "", nil, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(set.modules) != 0 || len(base.Entries) != 0 || len(base.Limitations) == 0 {
		t.Fatalf("JS base report loaded %d modules, %d entries", len(set.modules), len(base.Entries))
	}
	if php, err := RunPHP(inv, "", nil); php != nil || err != nil {
		t.Fatalf("RunPHP = %v, %v; want nil, nil", php, err)
	}
	if py, err := RunPython(inv, "", nil); err != nil || py == nil || len(py.Entries) == 0 {
		t.Fatalf("RunPython = %v, %v; want entries", py, err)
	}
	if _, err := RunPHP(inv, "missing.php", nil); err == nil {
		t.Fatal("a PHP entry without PHP files must keep its selection error")
	}
}
