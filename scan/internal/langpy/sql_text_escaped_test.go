package langpy

import (
	"path/filepath"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
	"github.com/zazzcode/zazzles/scan/internal/parse"
)

// Specification 21 follow-up: a request value escaped by quote doubling and then
// placed outside quotes (inj) or inside a quoted literal (safe), in testdata/sql-text/escaped.
func TestPythonSQLTextEscapedFixtures(t *testing.T) {
	for dir, want := range map[string]string{
		"inj":  "{1}: outside quotes",
		"safe": "{1}: inside a single-quoted literal",
	} {
		t.Run(dir, func(t *testing.T) {
			got := sqlTextAnalyze(t, filepath.Join("testdata", "sql-text", "escaped", dir))
			n := 0
			for line, uses := range got {
				for _, u := range uses {
					n++
					if sqlTextModelID(u) != analysispacks.SQLTextContract {
						t.Errorf("line %d: contract %q", line, sqlTextModelID(u))
					}
					p := u.Completeness.Evidence[parse.SQLTextPlacementKind]
					if len(p) != 1 || p[0].ModelText != want {
						t.Errorf("line %d: placement %+v, want %q", line, p, want)
					}
				}
			}
			if n != 2 {
				t.Fatalf("records %d, want 2 (pyodbc, oracledb)", n)
			}
		})
	}
}
