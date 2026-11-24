package langjs

import (
	"path/filepath"
	"sort"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

type exposureWant struct {
	file      string
	line      int
	operation string
	subject   string
	entry     string // entry name; empty for any
	guardLine int    // line of the recorded environment guard; 0 for none
}

// TestExpressExposure covers D-8: one row per operation of the table, each with
// a sibling under an environment condition (recorded with the guard) and a
// sibling that sends a constant (no record). The transfer project uses other
// names, aliases, a CommonJS shape and another condition operator.
func TestExpressExposure(t *testing.T) {
	for _, tt := range []struct {
		name string
		dir  string
		want []exposureWant
	}{
		{"primary", "exposure-express/primary", []exposureWant{
			{"server.ts", 9, "errorhandler", analysis.ExposureStack, "USE /", 0},
			{"server.ts", 11, "errorhandler", analysis.ExposureStack, "USE /", 10},
			{"server.ts", 13, "swagger-ui-express.setup", analysis.ExposureConfiguration, "USE /docs", 0},
			{"server.ts", 15, "prom-client.metrics", analysis.ExposureRuntimeState, "GET /metrics", 0},
			{"server.ts", 19, "prom-client.metrics", analysis.ExposureRuntimeState, "GET /metrics-dev", 18},
			{"server.ts", 22, "process.env", analysis.ExposureEnvironment, "GET /env", 0},
			{"server.ts", 23, "process.memoryUsage", analysis.ExposureRuntimeState, "GET /mem", 0},
			{"server.ts", 25, "error.stack", analysis.ExposureStack, "GET /stack", 0},
		}},
		{"transfer", "exposure-express/transfer", []exposureWant{
			{"index.js", 11, "errorhandler", analysis.ExposureStack, "USE /", 10},
			{"index.js", 13, "errorhandler", analysis.ExposureStack, "USE /", 0},
			{"index.js", 14, "swagger-ui-express.setup", analysis.ExposureConfiguration, "USE /api-spec", 0},
			{"index.js", 16, "prom-client.metrics", analysis.ExposureRuntimeState, "GET /stats", 0},
			{"index.js", 19, "process.memoryUsage", analysis.ExposureRuntimeState, "GET /runtime", 0},
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			report, err := Analyze(filepath.Join("testdata", tt.dir), "")
			if err != nil {
				t.Fatal(err)
			}
			var got []exposureWant
			for _, u := range report.Uses {
				if u.Kind != analysis.ExposureKind {
					continue
				}
				if u.Exposure == nil {
					t.Fatalf("exposure use at %s:%d has no facts", u.Sink.Span.File, u.Sink.Span.StartLine)
				}
				if err := u.Exposure.Validate(); err != nil {
					t.Fatal(err)
				}
				entry := ""
				for _, e := range report.Entries {
					if e.ID == u.EntryID {
						entry = e.Name
					}
				}
				guard := 0
				if len(u.Exposure.Guards) > 0 {
					guard = u.Exposure.Guards[0].Span.StartLine
				}
				got = append(got, exposureWant{u.Sink.Span.File, u.Sink.Span.StartLine, u.Exposure.Operation, u.Exposure.Subject, entry, guard})
				if u.Components == nil || u.Components.Failure != "" {
					t.Fatalf("exposure use at line %d has no component selection: %+v", u.Sink.Span.StartLine, u.Components)
				}
				if u.APIModel == nil || u.Completeness == nil || u.Completeness.ClaimKind != "exposure" {
					t.Fatalf("exposure use at line %d lacks its contract or completeness", u.Sink.Span.StartLine)
				}
				for _, role := range []string{"diagnostic_operation", "entry", "control_flow", "sink_binding"} {
					if len(u.Completeness.Evidence[role]) == 0 {
						t.Fatalf("exposure use at line %d lacks evidence role %s", u.Sink.Span.StartLine, role)
					}
				}
			}
			sort.Slice(got, func(i, j int) bool { return got[i].line < got[j].line })
			if len(got) != len(tt.want) {
				t.Fatalf("recorded %d exposure candidates, want %d: %+v", len(got), len(tt.want), got)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("candidate %d = %+v, want %+v", i, got[i], tt.want[i])
				}
			}
		})
	}
}
