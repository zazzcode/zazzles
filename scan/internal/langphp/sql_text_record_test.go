package langphp

import (
	"path/filepath"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
	"github.com/zazzcode/zazzles/scan/internal/parse"
)

// sqlTextUses returns the SQL records of an inline one-file fixture.
func sqlTextUses(t *testing.T, body string) []analysis.CandidateUse {
	t.Helper()
	root := phpFixture(t, map[string]string{"index.php": "<?php\n" + body + "\n"})
	return phpUsesOfKind(phpAnalyze(t, root, "index.php"), "sql_query_candidate")
}

func sqlTextSlots(u analysis.CandidateUse) map[string]int {
	out := map[string]int{}
	for _, d := range u.Dependencies {
		out[d.SinkSlot]++
	}
	return out
}

// TestPHPSQLTextDriverForms: every driver form gives exactly one SQL record; a
// form a contract records keeps its contract, the others get sql-text-v1. The
// text case has the request value in slot sql_text, the bound twin in
// sql_parameters.
func TestPHPSQLTextDriverForms(t *testing.T) {
	contract := map[string]string{"mysqli.php": "php-mysqli-v1", "pdo.php": "php-pdo-v1", "sqlite3.php": "php-sqlite3-v1"}
	for _, dir := range []struct{ name, slot string }{{"text", parse.SQLTextSlot}, {"bound", parse.SQLTextParametersSlot}} {
		files, err := filepath.Glob(filepath.Join("testdata/sql-text", dir.name, "*.php"))
		if err != nil || len(files) != 8 {
			t.Fatalf("%s fixtures: %v %v", dir.name, files, err)
		}
		for _, file := range files {
			base := filepath.Base(file)
			t.Run(dir.name+"/"+base, func(t *testing.T) {
				uses := phpUsesOfKind(phpAnalyze(t, filepath.Join("testdata/sql-text", dir.name), base), "sql_query_candidate")
				if len(uses) != 1 {
					t.Fatalf("records %d, want 1: %+v", len(uses), uses)
				}
				u := uses[0]
				want := contract[base]
				if dir.name == "bound" && (base == "mysqli.php" || base == "pdo.php") {
					// A bound value with no contract record at the call that runs it.
					want = ""
				}
				if want == "" {
					want = analysispacks.SQLTextContract
				}
				if u.APIModel == nil || u.APIModel.ID != want {
					t.Fatalf("contract %+v, want %s", u.APIModel, want)
				}
				if slots := sqlTextSlots(u); len(slots) != 1 || slots[dir.slot] != 1 {
					t.Fatalf("slots %v, want only %s", slots, dir.slot)
				}
			})
		}
	}
}

// TestPHPSQLTextRecordShape: the sink binding is the callee only, the text
// argument is the query text, and the excerpt evidence holds the sink span.
func TestPHPSQLTextRecordShape(t *testing.T) {
	uses := phpUsesOfKind(phpAnalyze(t, "testdata/sql-text/text", "pgsql.php"), "sql_query_candidate")
	if len(uses) != 1 {
		t.Fatalf("records %d", len(uses))
	}
	u := uses[0]
	if u.Completeness == nil || len(u.Completeness.Blockers) != 0 {
		t.Fatalf("completeness %+v", u.Completeness)
	}
	binding := u.Completeness.Evidence["sink_binding"]
	if len(binding) != 1 || binding[0].Text != "pg_query" {
		t.Fatalf("sink_binding %+v", binding)
	}
	query := u.Completeness.Evidence["query_text"]
	if len(query) != 1 || query[0].Kind != "query_text" {
		t.Fatalf("query_text %+v", query)
	}
	found := false
	for _, e := range u.Context {
		if e.Kind == parse.SQLTextSourceExcerptKind && e.Span.File == u.Sink.Span.File && e.Span.StartByte <= u.Sink.Span.StartByte && e.Span.EndByte >= u.Sink.Span.EndByte {
			found = true
		}
	}
	if !found {
		t.Fatalf("no source_excerpt holds the sink span %+v: %+v", u.Sink.Span, u.Context)
	}
}

func TestPHPSQLTextNoRecord(t *testing.T) {
	for _, c := range []struct{ name, body string }{
		{"SQL text and no dependency", `$c = pg_connect("host=db"); pg_query($c, "SELECT * FROM users WHERE name = 'x'"); $r = oci_parse($c, "SELECT * FROM t"); oci_execute($r);`},
		{"prose in an argument", `$n = $_GET['n']; trim("Select a file from the list " . $n); strtolower("Update your settings, " . $n); sprintf("Delete from the list %s", $n);`},
		{"a request value and no SQL text", `$c = pg_connect("host=db"); pg_query($c, $_GET['q']); foo($_GET['q'], "name");`},
		{"statement with no bound request value", `$s = $db->prepare("SELECT * FROM t WHERE a = :a"); $s->bindValue(':a', 5); $s->execute();`},
	} {
		t.Run(c.name, func(t *testing.T) {
			if uses := sqlTextUses(t, c.body); len(uses) != 0 {
				t.Fatalf("records: %+v", uses)
			}
		})
	}
}

// A log call that takes SQL text with request data IS recorded: the hook reads
// the text, not the callee, and the decision model sorts a log from a query.
func TestPHPSQLTextLogCallIsRecorded(t *testing.T) {
	uses := sqlTextUses(t, `error_log("SELECT * FROM users WHERE name = '" . $_GET['name'] . "'");`)
	if len(uses) != 1 || uses[0].APIModel.ID != analysispacks.SQLTextContract {
		t.Fatalf("records: %+v", uses)
	}
}

// No second record where a contract records the call or the statement.
func TestPHPSQLTextNoDuplicateOfContract(t *testing.T) {
	const head = "$c = new PDO('mysql:host=db', 'u', 'p');\n"
	for _, c := range []struct{ name, body string }{
		{"query", `$c->query("SELECT * FROM users WHERE name = '" . $_GET['name'] . "'");`},
		{"prepared text built from a request value", `$s = $c->prepare("SELECT * FROM users WHERE name = '" . $_GET['name'] . "'"); $s->execute();`},
		{"bound then executed", `$s = $c->prepare("SELECT * FROM users WHERE name = :n"); $s->bindParam(':n', $_GET['name']); $s->execute();`},
		{"two binds then executed", `$s = $c->prepare("SELECT * FROM users WHERE name = :n AND pw = :p"); $s->bindValue(':n', $_GET['name']); $s->bindValue(':p', $_GET['pw']); $s->execute();`},
	} {
		t.Run(c.name, func(t *testing.T) {
			uses := sqlTextUses(t, head+c.body)
			if len(uses) == 0 {
				t.Fatal("the contract recorded nothing")
			}
			for _, u := range uses {
				if u.APIModel.ID == analysispacks.SQLTextContract {
					t.Fatalf("sql-text-v1 record beside a contract record: %+v", u.Sink.Span)
				}
			}
		})
	}
}

// One record per statement: a statement the scanner does not track as a
// connection's gets one record at its first call that carries a request value;
// later bind calls add their values to it; a second statement gets its own.
func TestPHPSQLTextOneRecordPerStatement(t *testing.T) {
	uses := sqlTextUses(t, `
function run($db) {
$s = $db->prepare("SELECT * FROM users WHERE name = :n AND pw = :p");
$s->bindParam(':n', $_GET['name']);
$s->bindParam(':p', $_POST['pw']);
$s->execute();
$t = $db->prepare("SELECT * FROM posts WHERE id = :i");
$t->bindValue(':i', $_GET['id']);
$t->execute();
$s = $db->prepare("SELECT * FROM log WHERE who = ?");
$s->execute([$_COOKIE['who']]);
}
run($db);`)
	if len(uses) != 3 {
		t.Fatalf("records %d, want 3: %+v", len(uses), uses)
	}
	want := []int{2, 1, 1}
	for i, u := range uses {
		if u.APIModel.ID != analysispacks.SQLTextContract || sqlTextSlots(u)[parse.SQLTextParametersSlot] != want[i] || len(sqlTextSlots(u)) != 1 {
			t.Errorf("record %d: slots %v", i, sqlTextSlots(u))
		}
	}
	if uses[0].Sink.Span.StartByte >= uses[1].Sink.Span.StartByte {
		t.Errorf("the first statement's record is not at its first bind call")
	}
}

// A prepared statement text built from a request value is recorded once, at the
// prepare call, and a later bind adds to that record.
func TestPHPSQLTextPreparedTextAndBind(t *testing.T) {
	uses := sqlTextUses(t, `function run($db) {
$s = $db->prepare("SELECT * FROM " . $_GET['t'] . " WHERE a = :a");
$s->bindValue(':a', $_GET['a']);
$s->execute();
}
run($db);`)
	if len(uses) != 1 {
		t.Fatalf("records %d", len(uses))
	}
	if s := sqlTextSlots(uses[0]); s[parse.SQLTextSlot] != 1 || s[parse.SQLTextParametersSlot] != 1 {
		t.Fatalf("slots %v", s)
	}
}

// Blockers are limits on the text and on the values reaching the call; a limit
// elsewhere in the flow is a judged limit.
func TestPHPSQLTextBlockersAndJudgedLimits(t *testing.T) {
	loop := sqlTextUses(t, `$id = $_GET['id']; foreach ([1, 2] as $n) { echo $n; } $c = pg_connect("h"); pg_query($c, "SELECT a FROM t WHERE b = '" . $id . "'");`)
	if len(loop) != 1 {
		t.Fatalf("records %d", len(loop))
	}
	comp := loop[0].Completeness
	if len(comp.Blockers) != 0 || phpGapKinds(comp.Judged)["php_loop_unresolved"] != 1 {
		t.Fatalf("blockers %v judged %v", phpGapKinds(comp.Blockers), phpGapKinds(comp.Judged))
	}
	value := sqlTextUses(t, `$c = pg_connect("h"); pg_query($c, "SELECT a FROM t WHERE b = '" . $_GET['id'] . $undefined . "'");`)
	if len(value) != 1 || phpGapKinds(value[0].Completeness.Blockers)["php_value_unresolved"] == 0 {
		t.Fatalf("an unresolved value in the text is not a blocker: %+v", value)
	}
}

// A dependency whose source is in another file gets an excerpt of that file.
func TestPHPSQLTextExcerptOfOtherFile(t *testing.T) {
	root := phpFixture(t, map[string]string{
		"index.php": "<?php\nrequire 'lib.php';\n$c = pg_connect('h');\npg_query($c, \"SELECT a FROM t WHERE b = '\" . $name . \"'\");\n",
		"lib.php":   "<?php\n$name = $_GET['name'];\n",
	})
	uses := phpUsesOfKind(phpAnalyze(t, root, "index.php"), "sql_query_candidate")
	if len(uses) != 1 {
		t.Fatalf("records %d", len(uses))
	}
	u := uses[0]
	files := map[string]bool{}
	for _, e := range u.Context {
		if e.Kind == parse.SQLTextSourceExcerptKind {
			files[e.Span.File] = true
		}
	}
	if !files["index.php"] {
		t.Fatalf("no excerpt of the sink's file: %v", files)
	}
	for _, d := range u.Dependencies {
		covered := files[d.Source.Span.File]
		for _, e := range u.Context {
			if e.Span.File == d.Source.Span.File && sqlTextJudgeKind(e.Kind) {
				covered = true
			}
		}
		if !covered {
			t.Fatalf("source file %s of a dependency is not covered: %+v", d.Source.Span.File, u.Context)
		}
	}
}
