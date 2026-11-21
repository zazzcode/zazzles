package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/report"
)

// Full multi-framework reports can exceed the former 64 MiB input ceiling.
const maxSavedReportBytes = 512 << 20

func runExportSARIF(path string, stdout, stderr io.Writer) int {
	return runExport(path, false, stdout, stderr)
}

func runExport(path string, asHTML bool, stdout, stderr io.Writer) int {
	f, err := os.Open(path)
	if err != nil {
		fmt.Fprintf(stderr, "scan: %v\n", err)
		return exitError
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxSavedReportBytes+1))
	if err != nil || len(data) > maxSavedReportBytes {
		fmt.Fprintln(stderr, "scan: saved report read failed or exceeds 512 MiB")
		return exitError
	}
	var saved analysis.AnalysisReport
	if err := json.Unmarshal(data, &saved); err != nil || saved.SchemaVersion != analysis.ReportSchemaVersion || saved.Uses == nil {
		fmt.Fprintln(stderr, "scan: expected a schema-v1, schema-v2 or schema-v3 canonical analysis report")
		return exitError
	}
	if asHTML {
		if err := report.HTML(stdout, &saved); err != nil {
			fmt.Fprintf(stderr, "scan: %v\n", err)
			return exitError
		}
		return exitOK
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report.SARIF(&saved)); err != nil {
		fmt.Fprintf(stderr, "scan: %v\n", err)
		return exitError
	}
	return exitOK
}
