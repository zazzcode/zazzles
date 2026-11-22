package langphp

import (
	"slices"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

func TestPHPLogging(t *testing.T) {
	report := symfonyCaseReport(t, "logging")
	checkSymfonyOperationComponents(t, report)
	for _, tc := range []struct {
		id, entry, gap, origin, field string
		line                          int
	}{
		{"LG-01", "ANY /log-password", "log_sensitive_field_hint", "http.path_query_or_form", "password", 14},
		{"LG-02", "ANY /log-status", "", "", "", 0},
		{"LG-03", "ANY /log-authorization", "log_protocol_credential", "http.headers", "Authorization", 26},
		{"LG-04", "ANY /log-untyped", "", "", "", 0},
		{"Monolog-log-context", "ANY /log-monolog", "log_sensitive_field_hint", "http.path_query_or_form", "email", 36},
		{"error_log-body", "ANY /log-builtin", "log_request_container", "", "", 41},
	} {
		t.Run(tc.id, func(t *testing.T) {
			uses := symfonyOperationsForEntry(t, report, tc.entry, "log_sink_candidate")
			if tc.line == 0 {
				if len(uses) != 0 {
					t.Fatalf("unexpected log candidate at %+v", uses[0].Sink.Span)
				}
				return
			}
			if len(uses) != 1 {
				t.Fatalf("got %d log candidates under %s; want one", len(uses), tc.entry)
			}
			u := uses[0]
			if !phpHasComponent(u.Components, "language.logging.php") {
				t.Fatalf("missing PHP logging guidance: %+v", u.Components)
			}
			if at := u.Sink.Span; at.File != "src/Controller/LogCases.php" || at.StartLine != tc.line {
				t.Fatalf("sink %+v; want src/Controller/LogCases.php:%d", at, tc.line)
			}
			for _, gap := range []string{tc.gap, "log_destination_unresolved"} {
				if !slices.ContainsFunc(u.Gaps, func(g analysis.Gap) bool { return g.Kind == gap }) {
					t.Fatalf("missing %s: %+v", gap, u.Gaps)
				}
			}
			if !slices.ContainsFunc(u.Context, func(e analysis.Evidence) bool { return e.Kind == "logger_binding" && e.Span.StartLine == tc.line }) {
				t.Fatal("logger binding evidence missing")
			}
			if tc.field != "" {
				checkSymfonyOperationSource(t, u, tc.origin, tc.field)
			}
			if tc.id == "Monolog-log-context" && len(u.Dependencies) != 1 {
				t.Fatalf("log level leaked into operands: %+v", u.Dependencies)
			}
		})
	}
}
