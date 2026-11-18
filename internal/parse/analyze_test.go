package parse

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
	"github.com/zazzcode/zazzles/internal/walk"
)

// Analyze, AnalyzeWithChecks and AnalyzeWithOptions keep the package's
// internal tests on one unqualified call. They run the JS/TS and Python runners
// in the fixed order and share production's Assemble; internal/pipeline owns the
// production orchestration, its concurrency and the PHP runner (internal/langphp).
// Tests that need PHP output live in internal/pipeline or internal/langphp.
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
	var js, py *analysis.AnalysisReport
	if run.JavaScript {
		js, err = RunJavaScript(inv, entry, checks, options)
	}
	if err == nil && run.Python {
		py, err = RunPython(inv, entry, checks)
	}
	if err != nil {
		return nil, err
	}
	out, err := Assemble(entry, js, py, nil)
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

// Routes mirrors internal/pipeline.Routes for the JS/TS and Python fixtures of
// this package: its own walk, both route parts in order, then the same sort.
func Routes(root string) (*analysis.RouteInventory, error) {
	inv, err := testInventory(root)
	if err != nil {
		return nil, err
	}
	out := &analysis.RouteInventory{SchemaVersion: analysis.RouteSchemaVersion, Root: root, Routes: []analysis.Route{}, Gaps: []analysis.Gap{}}
	for _, part := range []func(Inventory) ([]analysis.Route, []analysis.Gap, error){JavaScriptRoutes, PythonRoutes} {
		routes, gaps, err := part(inv)
		if err != nil {
			return nil, err
		}
		out.Routes = append(out.Routes, routes...)
		out.Gaps = append(out.Gaps, gaps...)
	}
	sort.Slice(out.Routes, func(i, j int) bool {
		if out.Routes[i].Registration.File != out.Routes[j].Registration.File {
			return out.Routes[i].Registration.File < out.Routes[j].Registration.File
		}
		if out.Routes[i].Registration.StartByte != out.Routes[j].Registration.StartByte {
			return out.Routes[i].Registration.StartByte < out.Routes[j].Registration.StartByte
		}
		return out.Routes[i].PathPattern < out.Routes[j].PathPattern
	})
	sort.Slice(out.Gaps, func(i, j int) bool {
		if out.Gaps[i].At.File != out.Gaps[j].At.File {
			return out.Gaps[i].At.File < out.Gaps[j].At.File
		}
		if out.Gaps[i].At.StartByte != out.Gaps[j].At.StartByte {
			return out.Gaps[i].At.StartByte < out.Gaps[j].At.StartByte
		}
		return out.Gaps[i].Kind < out.Gaps[j].Kind
	})
	return out, nil
}

// newPythonSet opens a set over a fresh walk for set-level tests.
func newPythonSet(root string) (*pythonSet, error) {
	inv, err := testInventory(root)
	if err != nil {
		return nil, err
	}
	return openPythonSet(inv)
}

// AC2: a Python-only inventory opens no JS grammar and loads no JS module; the
// JS base report and the Python report are still produced. The PHP half of
// this check lives in internal/langphp.
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
	if py, err := RunPython(inv, "", nil); err != nil || py == nil || len(py.Entries) == 0 {
		t.Fatalf("RunPython = %v, %v; want entries", py, err)
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
