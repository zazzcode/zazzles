package parse

import (
	"path/filepath"
	"strings"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
	"github.com/zazzcode/zazzles/internal/walk"
)

// Transitional: external callers move to internal/pipeline in the next commit,
// after which these become the package's internal test helper.

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
	files, err := walk.Walk(root, walk.Options{})
	if err != nil {
		return nil, err
	}
	inv := Inventory{Root: root, Files: files.Files}
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
