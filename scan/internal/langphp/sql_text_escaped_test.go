package langphp

import (
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
	"github.com/zazzcode/zazzles/scan/internal/parse"
)

// Specification 21 follow-up: a request value escaped by the database's escape
// function and then placed outside quotes (inj) or inside a quoted literal (safe),
// in testdata/sql-text/escaped. oci, pgsql and sqlsrv give sql-text-v1 records;
// sqlite3 is recorded by its own contract, which carries no statement_shape.
func TestPHPSQLTextEscapedFixtures(t *testing.T) {
	for dir, want := range map[string]string{
		"inj":  "{1}: outside quotes",
		"safe": "{1}: inside a single-quoted literal",
	} {
		t.Run(dir, func(t *testing.T) {
			uses := phpUsesOfKind(phpAnalyze(t, "testdata/sql-text/escaped/"+dir, ""), "sql_query_candidate")
			if len(uses) != 4 {
				t.Fatalf("records %d, want 4", len(uses))
			}
			text := map[string]bool{}
			for _, u := range uses {
				file := u.Sink.Span.File
				if u.APIModel != nil && u.APIModel.ID == "php-sqlite3-v1" {
					if file != "sqlite3.php" {
						t.Errorf("php-sqlite3-v1 record in %s", file)
					}
					continue
				}
				if u.APIModel == nil || u.APIModel.ID != analysispacks.SQLTextContract {
					t.Errorf("%s: contract %v", file, u.APIModel)
					continue
				}
				text[file] = true
				p := u.Completeness.Evidence[parse.SQLTextPlacementKind]
				if len(p) != 1 || p[0].ModelText != want {
					t.Errorf("%s: placement %+v, want %q", file, p, want)
				}
			}
			if len(text) != 3 || !text["oci.php"] || !text["pgsql.php"] || !text["sqlsrv.php"] {
				t.Errorf("sql-text-v1 records in %v, want oci, pgsql, sqlsrv", text)
			}
		})
	}
}
