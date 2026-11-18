package parse

import (
	"os"
	"path/filepath"
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
	entry = NormalizeEntry(entry)
	inv, err := testInventory(root)
	if err != nil {
		return nil, err
	}
	// Same selection as internal/pipeline, run one after another in merge order.
	run := inv.Runners(entry)
	var js, py, php *analysis.AnalysisReport
	if run.JavaScript {
		js, err = RunJavaScript(inv, entry, checks, options)
	}
	if err == nil && run.Python {
		py, err = RunPython(inv, entry, checks)
	}
	if err == nil && run.PHP {
		php, err = RunPHP(inv, entry, checks)
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

// A set that opened no grammar still loads a module it is later allowed to
// load: the first load opens the grammars.
func TestModuleSetOpensGrammarsOnFirstLoad(t *testing.T) {
	inv, err := testInventory("testdata/python/routes")
	if err != nil {
		t.Fatal(err)
	}
	set, _, err := openJavaScriptSet(inv)
	if err != nil {
		t.Fatal(err)
	}
	defer set.close()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "late.js"), []byte("const x = 1;\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	set.root = root
	set.allowed["late.js"] = true
	m, err := set.load("late.js")
	if err != nil || set.parsers == nil || m.tree.RootNode().HasError() {
		t.Fatalf("load = %v, %v; parsers open = %v", m, err, set.parsers != nil)
	}
}

func TestRunnersFollowEntryModes(t *testing.T) {
	inv, err := testInventory("testdata/mixed/three-language")
	if err != nil {
		t.Fatal(err)
	}
	pyOnly, err := testInventory("testdata/python/routes")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		inv   Inventory
		entry string
		want  Languages
	}{
		{inv, NormalizeEntry("."), Languages{JavaScript: true, Python: true, PHP: true}},
		{pyOnly, "", Languages{JavaScript: true, Python: true}},
		{inv, NormalizeEntry("./app.py"), Languages{Python: true}},
		{inv, "index.php", Languages{PHP: true}},
		{inv, "view.PHTML", Languages{PHP: true}},
		{inv, "server.js", Languages{JavaScript: true}},
	} {
		if got := tc.inv.Runners(tc.entry); got != tc.want {
			t.Errorf("Runners(%q) = %+v, want %+v", tc.entry, got, tc.want)
		}
	}
}
