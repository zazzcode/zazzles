package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/judge"
	"github.com/zazzcode/zazzles/internal/parse"
	reportpkg "github.com/zazzcode/zazzles/internal/report"
)

func runAnalysis(root, entry, checksFile, provider, model string, limit int, asJSON, asSARIF bool, outputDir string, stdout, stderr io.Writer, scope analysis.EntrySelection) int {
	var client *judge.Client
	if provider != "" {
		key := ""
		switch provider {
		case "openai":
			key = os.Getenv("OPENAI_API_KEY")
		case "jev":
			key = os.Getenv("TYPESAFE_API_KEY")
		}
		var err error
		client, err = judge.New(provider, model, key)
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
	report, err := parse.AnalyzeWithChecks(root, entry, checks)
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
	if client != nil {
		order := make([]int, len(report.Uses))
		for i := range order {
			order[i] = i
		}
		sort.SliceStable(order, func(a, b int) bool { return queryUse(report.Uses[order[a]]) && !queryUse(report.Uses[order[b]]) })
		for requestIndex, i := range order {
			if requestIndex >= limit {
				report.Uses[i].Assessment.Status = "not_run"
				report.Uses[i].Assessment.Reason = "judge request limit reached"
				failed = true
				continue
			}
			report.Uses[i].Assessment = client.Assess(context.Background(), report.Uses[i])
			if report.Uses[i].Assessment.Status != "completed" {
				failed = true
			}
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
	return use.Kind == "sql_query_candidate" || use.Kind == "nosql_query_candidate" || use.Kind == "command_execution_candidate"
}
