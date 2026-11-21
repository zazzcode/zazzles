package langjs

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
	"github.com/zazzcode/zazzles/scan/internal/parse"
	"github.com/zazzcode/zazzles/scan/internal/walk"
)

// Analyze, AnalyzeWithChecks and AnalyzeWithOptions keep the package's
// internal tests on one unqualified call. They run the JS/TS runner and share
// production's parse.Assemble; internal/pipeline owns the production
// orchestration, its concurrency and the Python (internal/langpy) and PHP
// (internal/langphp) runners. Tests that need Python or PHP output live in
// those packages or in internal/pipeline.
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
	// Same selection as internal/pipeline, run one after another in merge order.
	run := inv.Runners(entry)
	var js *analysis.AnalysisReport
	if run.JavaScript {
		js, err = Run(inv, entry, checks, options)
	}
	if err != nil {
		return nil, err
	}
	out, err := parse.Assemble(entry, js, nil, nil)
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

// routeInventory wraps this package's route part for the JS/TS route tests. It
// does not sort: internal/pipeline.Routes owns the inventory order, and its
// tests pin the sorted golden bytes.
func routeInventory(root string) (*analysis.RouteInventory, error) {
	inv, err := testInventory(root)
	if err != nil {
		return nil, err
	}
	routes, gaps, err := Routes(inv)
	if err != nil {
		return nil, err
	}
	return &analysis.RouteInventory{SchemaVersion: analysis.RouteSchemaVersion, Root: root, Routes: routes, Gaps: gaps}, nil
}

// AC2: a Python-only inventory opens no JS grammar and loads no JS module; the
// JS base report is still produced. The Python and PHP halves of this check
// live in internal/langpy and internal/langphp.
func TestRunnersWithoutSourcesOpenNoGrammar(t *testing.T) {
	inv, err := testInventory("../langpy/testdata/routes")
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
	base, err := set.javascriptReport(selected, "", nil, parse.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(set.modules) != 0 || len(base.Entries) != 0 || len(base.Limitations) == 0 {
		t.Fatalf("JS base report loaded %d modules, %d entries", len(set.modules), len(base.Entries))
	}
}

// A set that opened no grammar still loads a module it is later allowed to
// load: the first load opens the grammars.
func TestModuleSetOpensGrammarsOnFirstLoad(t *testing.T) {
	inv, err := testInventory("../langpy/testdata/routes")
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
