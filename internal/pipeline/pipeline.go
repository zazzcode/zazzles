// Package pipeline orchestrates one repository analysis: it walks the target
// once, selects the language runners the inventory and entry need, runs them
// concurrently, merges their reports in the fixed JS/TS, Python, PHP order and
// attaches declared checks and analysis packs. internal/parse produces the
// per-language reports; it does not orchestrate.
package pipeline

import (
	"sync"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
	"github.com/zazzcode/zazzles/internal/parse"
	"github.com/zazzcode/zazzles/internal/walk"
)

// Options controls optional acquisition discovery and runner concurrency.
type Options struct {
	DiscoverRoutes bool
	// Workers caps concurrently running language runners. 0 runs every
	// selected runner at once; 1 runs them one after another in the fixed order.
	Workers int
}

// Analyze resolves route and browser entries and extracts bounded security evidence.
// Entry limits registration files; dependency modules remain inside the target manifest.
func Analyze(root, entry string) (*analysis.AnalysisReport, error) {
	return AnalyzeWithChecks(root, entry, nil)
}

// AnalyzeWithChecks assembles security evidence with optional declared requirements.
func AnalyzeWithChecks(root, entry string, checks []analysis.Check) (*analysis.AnalysisReport, error) {
	return AnalyzeWithOptions(root, entry, checks, Options{})
}

// AnalyzeWithOptions runs the full pipeline with optional discovery and a runner cap.
func AnalyzeWithOptions(root, entry string, checks []analysis.Check, opts Options) (*analysis.AnalysisReport, error) {
	return productionStages().analyze(root, entry, checks, opts)
}

// Runner slots in the fixed merge order.
const (
	javascriptRunner = iota
	pythonRunner
	phpRunner
	runnerCount
)

type runFunc func(inv parse.Inventory, entry string, checks []analysis.Check, opts parse.Options) (*analysis.AnalysisReport, error)

// stages are the pipeline's seams. Production walks with walk.Walk and runs the
// parse runners; tests substitute counting or failing stages.
type stages struct {
	walk    func(root string) (parse.Inventory, error)
	runners [runnerCount]runFunc
}

func productionStages() stages {
	return stages{
		walk: func(root string) (parse.Inventory, error) {
			files, err := walk.Walk(root, walk.Options{})
			if err != nil {
				return parse.Inventory{}, err
			}
			return parse.Inventory{Root: root, Files: files.Files}, nil
		},
		runners: [runnerCount]runFunc{
			javascriptRunner: parse.RunJavaScript,
			pythonRunner: func(inv parse.Inventory, entry string, checks []analysis.Check, _ parse.Options) (*analysis.AnalysisReport, error) {
				return parse.RunPython(inv, entry, checks)
			},
			phpRunner: func(inv parse.Inventory, entry string, checks []analysis.Check, _ parse.Options) (*analysis.AnalysisReport, error) {
				return parse.RunPHP(inv, entry, checks)
			},
		},
	}
}

func (st stages) analyze(root, entry string, checks []analysis.Check, opts Options) (*analysis.AnalysisReport, error) {
	if err := analysispacks.Validate(); err != nil {
		return nil, err
	}
	entry = parse.NormalizeEntry(entry)
	inv, err := st.walk(root)
	if err != nil {
		return nil, err
	}
	reports, err := st.run(inv, entry, checks, opts, selectRunners(inv, entry))
	if err != nil {
		return nil, err
	}
	out, err := parse.Assemble(entry, reports[javascriptRunner], reports[pythonRunner], reports[phpRunner])
	if err != nil {
		return nil, err
	}
	out.RecordCheckMatches(checks)
	for i := range out.Uses {
		analysispacks.Attach(&out.Uses[i])
	}
	return out, nil
}

func selectRunners(inv parse.Inventory, entry string) [runnerCount]bool {
	l := inv.Runners(entry)
	return [runnerCount]bool{javascriptRunner: l.JavaScript, pythonRunner: l.Python, phpRunner: l.PHP}
}

// run executes the selected runners into fixed slots. The returned error is the
// earliest failing runner's in merge order, whatever order the runners finish in.
func (st stages) run(inv parse.Inventory, entry string, checks []analysis.Check, opts Options, selected [runnerCount]bool) ([runnerCount]*analysis.AnalysisReport, error) {
	var reports [runnerCount]*analysis.AnalysisReport
	var errs [runnerCount]error
	parseOpts := parse.Options{DiscoverRoutes: opts.DiscoverRoutes}
	if opts.Workers == 1 {
		for i := range selected {
			if selected[i] {
				if reports[i], errs[i] = st.runners[i](inv, entry, checks, parseOpts); errs[i] != nil {
					return reports, errs[i]
				}
			}
		}
		return reports, nil
	}
	var slots chan struct{}
	if opts.Workers > 1 {
		slots = make(chan struct{}, opts.Workers)
	}
	var wg sync.WaitGroup
	for i := range selected {
		if !selected[i] {
			continue
		}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if slots != nil {
				slots <- struct{}{}
				defer func() { <-slots }()
			}
			reports[i], errs[i] = st.runners[i](inv, entry, checks, parseOpts)
		}(i)
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			return reports, err
		}
	}
	return reports, nil
}
