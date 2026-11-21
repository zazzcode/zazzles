// Package cli implements the scan CLI.
//
// It owns flag parsing, wiring, and exit codes. Analysis lives in scan/internal/;
// this package stays thin so the CLI surface is easy to test and easy to
// change.
package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/lang"
	"github.com/zazzcode/zazzles/scan/internal/pipeline"
	"github.com/zazzcode/zazzles/scan/internal/walk"
)

// Exit codes. CI depends on these, so they are part of the CLI contract.
const (
	exitOK    = 0
	exitError = 1
	exitUsage = 2
)

// Run executes the scan CLI with the provided arguments and streams and
// returns the process exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	return run(args, stdout, stderr)
}

// run is the testable entry point: it takes its arguments and streams and
// returns an exit code instead of calling os.Exit.
func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("scan", flag.ContinueOnError)
	flags.SetOutput(stderr)

	var (
		outputDir      = flags.String("output-dir", os.Getenv("SCAN_FINDINGS_DIR"), "write JSON, HTML and SARIF in a fresh run folder; defaults to SCAN_FINDINGS_DIR")
		exportHTML     = flags.String("export-html", "", "render saved evidence JSON as a standalone HTML report without API calls")
		exportFile     = flags.String("export-sarif", "", "convert a saved canonical JSON report to SARIF without API calls")
		list           = flags.Bool("list", false, "list the source files under the target path and exit")
		routes         = flags.Bool("routes", false, "emit supported route inventories and exit")
		analyzeMode    = flags.Bool("analyze", false, "analyze bounded route/browser security evidence; add --judge for model assessment")
		entryKind      = flags.String("entry-kind", "", "select http, browser, graphql or grpc entries for --analyze")
		entryID        = flags.String("entry-id", "", "select an exact snapshot entry ID for --analyze")
		routeFilter    = flags.String("route", "", "optional exact route path pattern for --analyze")
		checksFile     = flags.String("checks", "", "JSON file declaring route/method/field security requirements for --analyze")
		entry          = flags.String("entry", "", "relative JS/TS/Python/PHP registration file for --analyze")
		judgeProvider  = flags.String("judge", "", "optional semantic judge: openai, gemini or jev (transmits bounded source evidence)")
		judgeModel     = flags.String("judge-model", "", "judge model; defaults to JUDGE_DECISION_MODEL, gpt-6-luna for openai or gemini-decision-1 for gemini; required for jev")
		discoverRoutes = flags.Bool("discover-routes", false, "opt-in model-assisted Node route proposals; unverified bindings remain provisional")
		discoveryLimit = flags.Int("discovery-limit", 3, "maximum additional model discovery requests with --discover-routes; transient failures are retried up to 3 times")
		judgeLimit     = flags.Int("judge-limit", 0, "optional cap on candidates sent to the judge per run (default: no cap, every candidate is judged); transient failures are retried up to 3 times")
		asSARIF        = flags.Bool("sarif", false, "emit SARIF 2.1.0 findings for --analyze")
		skipFamily     = flags.String("skip-family", "", "comma-separated analyzer families to exclude: sql,nosql,xss,command,path,ssrf,code,redirect,upload,logging,input-validation,outbound")
		onlyFamily     = flags.String("only-family", "", "comma-separated analyzer families to judge exclusively")
		traceDir       = flags.String("trace-dir", "", "with --judge, save each exact request/response trace (contains transmitted source) as JSON under this directory for offline replay")
		asJSON         = flags.Bool("json", false, "emit machine-readable JSON instead of text")
	)
	limitFlags := addJudgeLimitFlags(flags)
	flags.BoolVar(analyzeMode, "strings", false, "compatibility alias for --analyze")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "usage: scan --list [--json] <path>")
		fmt.Fprintln(stderr, "       scan --routes [--json] <path>")
		fmt.Fprintln(stderr, "       scan --analyze [--json] [--entry file] [--judge openai|gemini|jev] <path>")
		fmt.Fprintln(stderr, "       scan --export-html <saved-report.json>")
		fmt.Fprintln(stderr, "       scan --export-sarif <saved-report.json>")
		flags.PrintDefaults()
	}

	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	explicitOutputDir := false
	explicitDiscoveryLimit, explicitJudgeLimit := false, false
	explicitSkipFamily, explicitOnlyFamily := false, false
	flags.Visit(func(f *flag.Flag) {
		if f.Name == "skip-family" {
			explicitSkipFamily = true
		}
		if f.Name == "only-family" {
			explicitOnlyFamily = true
		}
		if f.Name == "discovery-limit" {
			explicitDiscoveryLimit = true
		}
		if f.Name == "judge-limit" {
			explicitJudgeLimit = true
		}
		if f.Name == "output-dir" {
			explicitOutputDir = true
		}
	})
	if explicitOutputDir && !*analyzeMode {
		flags.Usage()
		return exitUsage
	}
	if *exportFile != "" || *exportHTML != "" {
		if *discoverRoutes || explicitDiscoveryLimit || (*exportFile != "" && *exportHTML != "") || flags.NArg() != 0 || *list || *routes || *analyzeMode || *asJSON || *asSARIF || *entry != "" || *routeFilter != "" || *entryKind != "" || *entryID != "" || *checksFile != "" || *judgeProvider != "" || *judgeModel != "" {
			flags.Usage()
			return exitUsage
		}
		if *exportHTML != "" {
			return runExport(*exportHTML, true, stdout, stderr)
		}
		return runExportSARIF(*exportFile, stdout, stderr)
	}
	modes := 0
	for _, enabled := range []bool{*list, *routes, *analyzeMode} {
		if enabled {
			modes++
		}
	}
	if (*asSARIF && (*asJSON || !*analyzeMode)) || modes != 1 || flags.NArg() != 1 || explicitJudgeLimit && *judgeLimit < 1 || (!*analyzeMode && (*checksFile != "" || *entry != "" || *routeFilter != "" || *entryKind != "" || *entryID != "" || *judgeProvider != "" || *judgeModel != "")) || (*judgeProvider == "" && *judgeModel != "") {
		flags.Usage()
		return exitUsage
	}

	if explicitDiscoveryLimit && !*discoverRoutes {
		fmt.Fprintln(stderr, "scan: --discovery-limit requires --discover-routes")
		return exitUsage
	}
	if *discoverRoutes && (!*analyzeMode || *judgeProvider == "" || *discoveryLimit < 1 || *discoveryLimit > 1000 || *routeFilter != "" || *entryKind != "" || *entryID != "" || *checksFile != "") {
		fmt.Fprintln(stderr, "scan: --discover-routes requires unfiltered --analyze with --judge and --discovery-limit 1..1000")
		return exitUsage
	}
	if *traceDir != "" && (!*analyzeMode || *judgeProvider == "") {
		fmt.Fprintln(stderr, "scan: --trace-dir requires --analyze with --judge")
		return exitUsage
	}
	if *analyzeMode && *judgeProvider != "" {
		if !explicitSkipFamily {
			*skipFamily = os.Getenv("JUDGE_SKIP_FAMILY")
		}
		if !explicitOnlyFamily {
			*onlyFamily = os.Getenv("JUDGE_ONLY_FAMILY")
		}
	}
	skipped, err := parseSkipFamilies(*skipFamily)
	only, onlyErr := parseSkipFamilies(*onlyFamily)
	if err != nil || onlyErr != nil || len(skipped) > 0 && len(only) > 0 || (len(skipped) > 0 || len(only) > 0) && (!*analyzeMode || *judgeProvider == "") {
		fmt.Fprintln(stderr, "scan: family filters require --analyze with --judge; --only-family and --skip-family are mutually exclusive and accept sql,nosql,xss,command,path,ssrf,code,pollution,redirect,logging,input-validation,outbound")
		return exitUsage
	}

	if *entryKind != "" && !analysis.KnownEntryKind(*entryKind) {
		fmt.Fprintln(stderr, "scan: invalid entry kind")
		return exitUsage
	}
	if *analyzeMode {
		var runtime judgeRuntime
		if *judgeProvider != "" {
			var err error
			runtime, *judgeLimit, err = limitFlags.resolve(flags, os.Getenv)
			if err != nil {
				fmt.Fprintf(stderr, "scan: %v\n", err)
				return exitUsage
			}
		}
		return runAnalysisConfigured(flags.Arg(0), *entry, *checksFile, *judgeProvider, *judgeModel, *judgeLimit, *asJSON, *asSARIF, *outputDir, *traceDir, skipped, only, stdout, stderr, analysis.EntrySelection{RegistrationFile: *entry, Route: *routeFilter, Kind: *entryKind, ID: *entryID}, discoveryOptions{Enabled: *discoverRoutes, Limit: *discoveryLimit}, runtime)
	}
	if *routes {
		return runRoutes(flags.Arg(0), *asJSON, stdout, stderr)
	}

	result, err := walk.Walk(flags.Arg(0), walk.Options{})
	if err != nil {
		fmt.Fprintf(stderr, "scan: %v\n", err)
		return exitError
	}

	if *asJSON {
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(newManifest(result)); err != nil {
			fmt.Fprintf(stderr, "scan: %v\n", err)
			return exitError
		}
		return exitOK
	}

	printManifest(stdout, result)
	return exitOK
}

func runRoutes(root string, asJSON bool, stdout, stderr io.Writer) int {
	scanned, err := pipeline.Routes(root)
	if err != nil {
		fmt.Fprintf(stderr, "scan: %v\n", err)
		return exitError
	}
	if asJSON {
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(scanned); err != nil {
			fmt.Fprintf(stderr, "scan: %v\n", err)
			return exitError
		}
		return exitOK
	}
	for _, route := range scanned.Routes {
		fmt.Fprintf(stdout, "%s %s %s:%d\n", route.Method, route.PathPattern, route.Registration.File, route.Registration.StartLine)
	}
	for _, gap := range scanned.Gaps {
		fmt.Fprintf(stdout, "gap %s %s:%d %s\n", gap.Kind, gap.At.File, gap.At.StartLine, gap.Detail)
	}
	return exitOK
}

// manifest is the machine-readable form of a walk result. Field names are part
// of the output contract.
type manifest struct {
	Root        string         `json:"root"`
	Examined    int            `json:"examined"`
	Unsupported int            `json:"unsupported"`
	Supported   int            `json:"supported"`
	ByLanguage  map[string]int `json:"by_language"`
	Files       []manifestFile `json:"files"`
}

type manifestFile struct {
	Path     string `json:"path"`
	Language string `json:"language"`
	Size     int64  `json:"size"`
}

func newManifest(result *walk.Result) manifest {
	byLanguage := make(map[string]int, len(result.ByLanguage))
	for language, count := range result.ByLanguage {
		byLanguage[string(language)] = count
	}

	files := make([]manifestFile, 0, len(result.Files))
	for _, file := range result.Files {
		files = append(files, manifestFile{
			Path:     file.Path,
			Language: string(file.Language),
			Size:     file.Size,
		})
	}

	return manifest{
		Root:        result.Root,
		Examined:    result.Examined,
		Unsupported: result.Unsupported,
		Supported:   len(result.Files),
		ByLanguage:  byLanguage,
		Files:       files,
	}
}

func printManifest(w io.Writer, result *walk.Result) {
	fmt.Fprintf(w, "root:        %s\n", result.Root)
	fmt.Fprintf(w, "examined:    %d\n", result.Examined)
	fmt.Fprintf(w, "supported:   %d\n", len(result.Files))
	fmt.Fprintf(w, "unsupported: %d\n", result.Unsupported)
	fmt.Fprintln(w)

	for _, language := range sortedLanguages(result.ByLanguage) {
		fmt.Fprintf(w, "%-12s %d\n", language, result.ByLanguage[language])
	}

	fmt.Fprintln(w)
	for _, file := range result.Files {
		fmt.Fprintln(w, file.Path)
	}
}

// sortedLanguages returns the languages present in counts in a stable order.
// Map iteration order is deliberately never used for output.
func sortedLanguages(counts map[lang.Language]int) []lang.Language {
	languages := make([]lang.Language, 0, len(counts))
	for language := range counts {
		languages = append(languages, language)
	}
	sort.Slice(languages, func(i, j int) bool { return languages[i] < languages[j] })
	return languages
}
