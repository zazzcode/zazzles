package langphp

import (
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

func phpGapKinds(gaps []analysis.Gap) map[string]int {
	out := map[string]int{}
	for _, g := range gaps {
		out[g.Kind]++
	}
	return out
}

// TestPHPSQLFlowWideLimits: a loop elsewhere in the entry flow is a judged
// limit of a SQL record, not a blocker. A request value assigned or changed in
// a loop body does not carry the loop's gap: the gap is on the flow only, so
// such a record also holds the loop as a judged limit, not as a blocker.
func TestPHPSQLFlowWideLimits(t *testing.T) {
	const head = "<?php\n$db = new PDO('sqlite:x');\n"
	const injectable = `$db->query("SELECT a FROM t WHERE b = '" . $id . "'");`
	for _, c := range []struct{ name, body string }{
		{"unrelated loop, injectable query", `$id = $_GET['id']; foreach ([1, 2] as $n) { echo $n; } ` + injectable},
		{"value changed in the loop", `$id = $_GET['id']; foreach ([1, 2] as $n) { $id = $id . 'x'; } ` + injectable},
		{"value assigned in the loop", `while ($x) { $id = $_GET['id']; } ` + injectable},
		{"query inside the loop", `foreach ([1, 2] as $n) { $id = $_GET['id']; ` + injectable + ` }`},
		{"bound query, unrelated loop", `$q = $_GET['q']; foreach ([1, 2] as $n) { echo $n; } $s = $db->prepare('SELECT a FROM t WHERE b = :b'); $s->bindValue(':b', $q, PDO::PARAM_STR); $s->execute();`},
	} {
		t.Run(c.name, func(t *testing.T) {
			uses := phpUsesOfKind(phpAnalyze(t, phpFixture(t, map[string]string{"index.php": head + c.body + "\n"}), "index.php"), "sql_query_candidate")
			if len(uses) != 1 {
				t.Fatalf("records %d, want 1", len(uses))
			}
			comp := uses[0].Completeness
			if n := phpGapKinds(comp.Blockers)["php_loop_unresolved"]; n != 0 {
				t.Errorf("loop is a blocker: %v", phpGapKinds(comp.Blockers))
			}
			if len(comp.Blockers) != 0 {
				t.Errorf("blockers: %v", phpGapKinds(comp.Blockers))
			}
			if phpGapKinds(comp.Judged)["php_loop_unresolved"] != 1 {
				t.Errorf("judged limits: %v", phpGapKinds(comp.Judged))
			}
			if phpGapKinds(comp.Coverage)["php_loop_unresolved"] != 1 {
				t.Errorf("the judged limit is not in the coverage the model reads: %v", phpGapKinds(comp.Coverage))
			}
		})
	}
	t.Run("no loop, no judged limit", func(t *testing.T) {
		uses := phpUsesOfKind(phpAnalyze(t, phpFixture(t, map[string]string{"index.php": head + `$id = $_GET['id']; $db->query("SELECT a FROM t WHERE b = '" . $id . "'");` + "\n"}), "index.php"), "sql_query_candidate")
		if len(uses) != 1 || len(uses[0].Completeness.Judged) != 0 || len(uses[0].Completeness.Blockers) != 0 {
			t.Fatalf("%+v", uses)
		}
	})
	t.Run("value limit stays a blocker", func(t *testing.T) {
		uses := phpUsesOfKind(phpAnalyze(t, phpFixture(t, map[string]string{"index.php": head + `$db->query("SELECT a FROM t WHERE b = '" . $_GET['id'] . $undefined . "'");` + "\n"}), "index.php"), "sql_query_candidate")
		if len(uses) != 1 || phpGapKinds(uses[0].Completeness.Blockers)["php_value_unresolved"] == 0 {
			t.Fatalf("blockers %v", phpGapKinds(uses[0].Completeness.Blockers))
		}
	})
}
