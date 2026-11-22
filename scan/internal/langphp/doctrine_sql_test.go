package langphp

import (
	"path/filepath"
	"slices"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
)

func TestDoctrineSQL(t *testing.T) {
	report, err := Analyze(filepath.Join("testdata", "symfony", "doctrine-sql"), "")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		id, path, contract, field, slot string
		sinkLine, constructionLine      int
		unresolved                      bool
	}{
		{"SQL-01", "/sql-01", "php-doctrine-dbal-v1", "id", "sql_text", 14, 14, false},
		{"SQL-02", "/sql-02", "php-doctrine-dbal-v1", "id", "sql_text", 21, 19, false},
		{"SQL-03", "/sql-03", "php-doctrine-dbal-v1", "id", "sql_parameters", 26, 0, false},
		{"SQL-04", "/sql-04", "php-doctrine-dbal-v1", "id", "sql_parameters", 33, 0, false},
		{"SQL-05", "/sql-05", "php-doctrine-orm-v1", "name", "sql_text", 38, 38, false},
		{"SQL-06", "/sql-06", "php-doctrine-orm-v1", "name", "sql_parameters", 43, 0, false},
		{"SQL-07", "/sql-07", "php-doctrine-orm-v1", "name", "sql_text", 48, 48, false},
		{"SQL-08", "/sql-08", "php-doctrine-orm-v1", "sort", "sql_text", 55, 54, false},
		{"SQL-09", "/sql-09", "", "", "", 0, 0, false},
		{"SQL-10", "/sql-10", "", "", "", 0, 0, false},
		{"SQL-11", "/sql-11", "php-doctrine-dbal-v1", "id", "sql_text", 67, 65, false},
		{"SQL-12", "/sql-12", "", "", "", 73, 0, true},
	} {
		t.Run(tc.id, func(t *testing.T) {
			idx := slices.IndexFunc(report.Entries, func(e analysis.EntryPoint) bool {
				return e.HTTP != nil && e.HTTP.Path == tc.path
			})
			if idx < 0 {
				t.Fatalf("missing fixture entry %s", tc.path)
			}
			entry := report.Entries[idx]
			var uses []analysis.CandidateUse
			for _, use := range report.Uses {
				if use.EntryID == entry.ID && use.Kind == "sql_query_candidate" {
					uses = append(uses, use)
				}
			}
			const repository = "src/Repository/Stock.php"
			if tc.unresolved && !slices.ContainsFunc(entry.Gaps, func(g analysis.Gap) bool {
				return g.Kind == "php_call_unresolved" && g.At.File == repository && g.At.StartLine == tc.sinkLine
			}) {
				t.Fatalf("missing unresolved receiver gap: %+v", entry.Gaps)
			}
			if tc.contract == "" {
				if len(uses) != 0 {
					t.Fatalf("unexpected SQL candidates: %v", uses)
				}
				return
			}
			if len(uses) != 1 {
				t.Fatalf("want one SQL candidate at line %d, got %d", tc.sinkLine, len(uses))
			}
			use := uses[0]
			if use.Sink.Span.File != repository || use.Sink.Span.StartLine != tc.sinkLine ||
				use.APIModel == nil || use.APIModel.ID != tc.contract {
				t.Fatalf("sink = %+v, contract = %+v", use.Sink, use.APIModel)
			}
			if _, err := analysispacks.Select(use); err != nil {
				t.Fatalf("selecting Doctrine contract: %v", err)
			}
			if len(use.Dependencies) != 1 || use.Dependencies[0].SinkSlot != tc.slot ||
				use.Dependencies[0].Source.Kind != "input_source" ||
				use.Dependencies[0].Source.Span.File != "src/Controller/Inventory.php" ||
				use.Check == nil || !slices.Equal(use.Check.Fields, []string{tc.field}) {
				t.Fatalf("wrong request dependency or field: %+v %+v", use.Dependencies, use.Check)
			}
			if hasSymfonyGap(use.Gaps, "query_text_interpolated") != (tc.slot == "sql_text") {
				t.Fatalf("wrong interpolation evidence: %+v", use.Gaps)
			}
			if tc.slot == "sql_parameters" && !slices.ContainsFunc(use.Context, func(e analysis.Evidence) bool {
				return e.Kind == "parameter_binding"
			}) {
				t.Fatal("missing parameter binding evidence")
			}
			if tc.constructionLine > 0 && (use.Completeness == nil ||
				!slices.ContainsFunc(use.Completeness.Evidence["query_text"], func(e analysis.Evidence) bool {
					return e.Span.File == repository && e.Span.StartLine == tc.constructionLine
				})) {
				t.Fatalf("missing query-text construction evidence at line %d", tc.constructionLine)
			}
		})
	}
}
