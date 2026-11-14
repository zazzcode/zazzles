package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/judge"
	"github.com/zazzcode/zazzles/internal/parse"
	reportpkg "github.com/zazzcode/zazzles/internal/report"
)

func runAnalysis(root, entry, checksFile, provider, model string, limit int, asJSON, asSARIF bool, outputDir, traceDir string, skipped []string, stdout, stderr io.Writer, scope analysis.EntrySelection) int {
	return runAnalysisConfigured(root, entry, checksFile, provider, model, limit, asJSON, asSARIF, outputDir, traceDir, skipped, stdout, stderr, scope, discoveryOptions{})
}

func runAnalysisConfigured(root, entry, checksFile, provider, model string, limit int, asJSON, asSARIF bool, outputDir, traceDir string, skipped []string, stdout, stderr io.Writer, scope analysis.EntrySelection, discovery discoveryOptions) int {
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
		order := make([]int, len(report.Uses))
		for i := range order {
			order[i] = i
		}
		sort.SliceStable(order, func(a, b int) bool { return queryUse(report.Uses[order[a]]) && !queryUse(report.Uses[order[b]]) })
		requestIndex := 0
		for _, i := range order {
			if familySkipped(report.Uses[i], skipped) {
				// A deliberate scope choice: no request, no limit use, no failure.
				report.Uses[i].Assessment = analysis.Assessment{Status: "not_run", Reason: skipReason}
				continue
			}
			requestIndex++
			if requestIndex > limit {
				report.Uses[i].Assessment.Status = "not_run"
				report.Uses[i].Assessment.Reason = "judge request limit reached"
				failed = true
				continue
			}
			if traceDir != "" {
				var trace judge.DecisionTrace
				report.Uses[i].Assessment, trace = client.AssessTrace(context.Background(), report.Uses[i])
				if err := writeTrace(traceDir, report.Uses[i].ID, trace); err != nil {
					fmt.Fprintf(stderr, "scan: trace not saved: %v\n", err)
					failed = true
				}
			} else {
				report.Uses[i].Assessment = client.Assess(context.Background(), report.Uses[i])
			}
			if report.Uses[i].Assessment.Status != "completed" {
				failed = true
			}
		}
	}
	if len(skipped) > 0 {
		report.SkippedFamilies = skipped
		count := 0
		for _, u := range report.Uses {
			if familySkipped(u, skipped) {
				count++
			}
		}
		report.Limitations = append(report.Limitations, fmt.Sprintf("The input-validation analyzer was not used for this run (--skip-family input-validation): %d input-validation records were not judged and remain Review. This is a scope choice, not an assessment; absence of an input-validation finding here does not mean validation is adequate.", count))
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
	return use.Kind == "sql_query_candidate" || use.Kind == "nosql_query_candidate" || use.Kind == "command_execution_candidate" || use.Kind == "path_traversal_candidate"
}

const skipReason = "input-validation analyzer not used for this run (--skip-family input-validation)"

func parseSkipFamilies(value string) ([]string, error) {
	if value == "" {
		return nil, nil
	}
	var out []string
	for _, name := range strings.Split(value, ",") {
		switch strings.TrimSpace(name) {
		case "input-validation":
			out = append(out, "input-validation")
		default:
			return nil, fmt.Errorf("unsupported family %q", name)
		}
	}
	return out, nil
}

func familySkipped(use analysis.CandidateUse, skipped []string) bool {
	for _, name := range skipped {
		if name == "input-validation" && use.Kind == "input_validation_candidate" {
			return true
		}
	}
	return false
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
