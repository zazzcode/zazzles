package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
	"github.com/zazzcode/zazzles/internal/judge"
	"github.com/zazzcode/zazzles/internal/parse"
	reportpkg "github.com/zazzcode/zazzles/internal/report"
)

func runAnalysis(root, entry, checksFile, provider, model string, limit int, asJSON, asSARIF bool, outputDir, traceDir string, skipped []string, stdout, stderr io.Writer, scope analysis.EntrySelection) int {
	return runAnalysisConfigured(root, entry, checksFile, provider, model, limit, asJSON, asSARIF, outputDir, traceDir, skipped, nil, stdout, stderr, scope, discoveryOptions{})
}

func runAnalysisConfigured(root, entry, checksFile, provider, model string, limit int, asJSON, asSARIF bool, outputDir, traceDir string, skipped, only []string, stdout, stderr io.Writer, scope analysis.EntrySelection, discovery discoveryOptions, runtimeLimits ...judge.Limits) int {
	var client *judge.Client
	if provider != "" {
		var err error
		model, key, err := judgeConfiguration(provider, model, os.Getenv)
		if err != nil {
			fmt.Fprintf(stderr, "scan: %v\n", err)
			return exitError
		}
		client, err = newJudgeClient(provider, model, key)
		if err != nil {
			fmt.Fprintf(stderr, "scan: %v\n", err)
			return exitError
		}
		if len(runtimeLimits) > 0 {
			if err := client.SetLimits(runtimeLimits[0]); err != nil {
				fmt.Fprintf(stderr, "scan: %v\n", err)
				return exitUsage
			}
		}
	}
	checks, err := loadChecks(checksFile)
	if err != nil {
		fmt.Fprintf(stderr, "scan: %v\n", err)
		return exitError
	}
	report, err := parse.AnalyzeWithOptions(root, entry, checks, parse.Options{DiscoverRoutes: discovery.Enabled})
	if err != nil {
		fmt.Fprintf(stderr, "scan: %v\n", err)
		return exitError
	}
	if scope.Route != "" || scope.Kind != "" || scope.ID != "" {
		if err := report.FilterEntries(scope); err != nil {
			fmt.Fprintf(stderr, "scan: %v\n", err)
			return exitError
		}
	} else {
		report.SelectedScope = &scope
	}
	report.RecordCheckMatches(checks)
	failed := false
	if discovery.Enabled {
		failed = runNodeDiscovery(root, entry, report, client, discovery.Limit, traceDir, stderr)
	}
	if client != nil {
		opts := judge.ScheduleOptions{Limit: limit, SkippedFamilies: skipped, OnlyFamilies: only}
		if traceDir != "" {
			opts.SaveTrace = func(id string, trace judge.DecisionTrace) error { return writeTrace(traceDir, id, trace) }
		}
		if client.AssessScheduled(context.Background(), report, opts) {
			failed = true
		}
	}

	if client != nil {
		if summary := client.LimitSummary(); summary != "" {
			report.Limitations = append(report.Limitations, summary)
		}
	}
	reportpkg.Enrich(report)
	bundleDir := ""
	if outputDir != "" {
		bundleDir, err = reportpkg.WriteBundle(outputDir, report)
		if err != nil {
			fmt.Fprintf(stderr, "scan: output bundle incomplete at %s: %v\n", bundleDir, err)
			return exitError
		}
		if asJSON || asSARIF {
			fmt.Fprintf(stderr, "scan: findings saved to %s\n", bundleDir)
		}
	}
	if asJSON || asSARIF {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		var output any = report
		if asSARIF {
			output = reportpkg.SARIF(report)
		}
		if err := enc.Encode(output); err != nil {
			fmt.Fprintf(stderr, "scan: %v\n", err)
			return exitError
		}
	} else if bundleDir != "" {
		fmt.Fprintf(stdout, "Findings saved to %s\nJSON: findings.json\nHTML: findings.html\nSARIF: findings.sarif\n", bundleDir)
	} else {
		reportpkg.Text(stdout, report)
	}
	if failed {
		return exitError
	}
	return exitOK
}

func queryUse(use analysis.CandidateUse) bool {
	return judge.AssessableUse(use) && use.Kind != "input_validation_candidate"
}

func parseSkipFamilies(value string) ([]string, error) {
	if value == "" {
		return nil, nil
	}
	var out []string
	seen := map[string]bool{}
	for _, name := range strings.Split(value, ",") {
		name = strings.TrimSpace(name)
		if !analysispacks.ValidCLIFamily(name) {
			return nil, fmt.Errorf("unsupported family %q", name)
		}
		if !seen[name] {
			out = append(out, name)
			seen[name] = true
		}
	}

	return out, nil
}

// newJudgeClient builds the selected provider client; tests replace it with a stub.
var newJudgeClient = judge.New

// writeTrace saves one exact request/response trace. Traces contain the
// transmitted source and no credentials; the directory is private.
func writeTrace(dir, id string, trace judge.DecisionTrace) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	safe := strings.NewReplacer(":", "_", "/", "_", "\\", "_").Replace(id)
	data, err := json.Marshal(trace)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, safe+".json"), data, 0o600)
}
