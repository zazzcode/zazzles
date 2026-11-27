package langphp

import (
	"fmt"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
	"github.com/zazzcode/zazzles/scan/internal/parse"
)

// sqlTextFollowForm builds the text of a statement around a value val (a PHP
// expression): the setup statements and the text expression.
type sqlTextFollowForm struct {
	name  string
	build func(val string) (setup, expr string)
}

var sqlTextFollowForms = []sqlTextFollowForm{
	{"implode", func(v string) (string, string) {
		return "", `implode(" ", ["SELECT a FROM t WHERE b =", ` + v + `])`
	}},
	{"join", func(v string) (string, string) {
		return "", `join(" ", ["SELECT a FROM t", "WHERE b =", ` + v + `])`
	}},
	{"implode of a list built by appends", func(v string) (string, string) {
		return `$p = ["SELECT a FROM t WHERE"]; $p[] = "b ="; $p[] = ` + v + `;`, `implode(" ", $p)`
	}},
	{"sprintf", func(v string) (string, string) {
		return "", `sprintf("SELECT a FROM t WHERE b = %s", ` + v + `)`
	}},
	{"vsprintf", func(v string) (string, string) {
		return "", `vsprintf("SELECT a FROM t WHERE b = %s AND c = %d", [` + v + `, 1])`
	}},
	{"heredoc", func(v string) (string, string) {
		return "$v = " + v + ";\n$q = <<<SQL\nSELECT a FROM t WHERE b = {$v}\nSQL;\n", `$q`
	}},
	{"function", func(v string) (string, string) {
		return `function build($id) { return "SELECT a FROM t WHERE b = " . $id; }`, `build(` + v + `)`
	}},
	{"function with two returns", func(v string) (string, string) {
		return `function build($id) { if ($id === 1) { return "nothing to see"; } return "SELECT a FROM t WHERE b = " . $id; }`, `build(` + v + `)`
	}},
	{"method", func(v string) (string, string) {
		return `class Qs { function build($i) { return "SELECT a FROM t WHERE b = " . $i; } } $o = new Qs;`, `$o->build(` + v + `)`
	}},
	{"this method", func(v string) (string, string) {
		return `class Qs { function sql($i) { return "SELECT a FROM t WHERE b = " . $i; } function run($c, $i) { return pg_query($c, $this->sql($i)); } }`, `$ZZ`
	}},
	{"static method", func(v string) (string, string) {
		return `class Qs { static function build($i) { return "SELECT a FROM t WHERE b = " . $i; } }`, `Qs::build(` + v + `)`
	}},
	{"const", func(v string) (string, string) {
		return `const Q = "SELECT a FROM t WHERE b = ";`, `Q . ` + v
	}},
	{"define", func(v string) (string, string) {
		return `define('Q', "SELECT a FROM t WHERE b = ");`, `Q . ` + v
	}},
	{"class constant", func(v string) (string, string) {
		return `class Qs { const Q = "SELECT a FROM t WHERE b = "; }`, `Qs::Q . ` + v
	}},
}

func sqlTextFollowBody(form sqlTextFollowForm, val, call string) string {
	setup, expr := form.build(val)
	if expr == "$ZZ" {
		return ""
	}
	return setup + "\n$c = pg_connect('h');\n" + fmt.Sprintf(call, expr)
}

func sqlTextOnlySQL(uses []analysis.CandidateUse) []analysis.CandidateUse {
	var out []analysis.CandidateUse
	for _, u := range uses {
		if u.APIModel != nil && u.APIModel.ID == analysispacks.SQLTextContract {
			out = append(out, u)
		}
	}
	return out
}

// Text built by a join, a format, a heredoc, a helper or a constant: the
// injectable form gives one sql-text-v1 record with slot sql_text, the bound
// twin one with slot sql_parameters, the form with no request value none.
func TestPHPSQLTextFollowForms(t *testing.T) {
	for _, form := range sqlTextFollowForms {
		if form.name == "this method" {
			continue
		}
		t.Run(form.name, func(t *testing.T) {
			inject := sqlTextOnlySQL(sqlTextUses(t, sqlTextFollowBody(form, `$_GET['x']`, "pg_query($c, %s);")))
			if len(inject) != 1 {
				t.Fatalf("injectable: records %d", len(inject))
			}
			if s := sqlTextSlots(inject[0]); len(s) != 1 || s[parse.SQLTextSlot] != 1 {
				t.Fatalf("injectable slots %v", s)
			}
			bound := sqlTextOnlySQL(sqlTextUses(t, sqlTextFollowBody(form, `'$1'`, "pg_query_params($c, %s, [$_GET['x']]);")))
			if len(bound) != 1 {
				t.Fatalf("bound: records %d", len(bound))
			}
			if s := sqlTextSlots(bound[0]); len(s) != 1 || s[parse.SQLTextParametersSlot] != 1 {
				t.Fatalf("bound slots %v", s)
			}
			// A format conversion or a helper parameter is a hole whatever the
			// argument; the other forms have no hole in the bound twin.
			_, hasPlacement := bound[0].Completeness.Evidence[parse.SQLTextPlacementKind]
			holeInTwin := form.name == "sprintf" || form.name == "vsprintf" || strings.Contains(form.name, "function") || strings.Contains(form.name, "method")
			if hasPlacement != holeInTwin {
				t.Fatalf("placement evidence %v in the bound twin, want %v", hasPlacement, holeInTwin)
			}
			if none := sqlTextUses(t, sqlTextFollowBody(form, `'5'`, "pg_query($c, %s);")); len(none) != 0 {
				t.Fatalf("no request value: records %d", len(none))
			}
			// The text argument is the query text and the sink holds the call.
			qt := inject[0].Completeness.Evidence["query_text"]
			if len(qt) != 1 || qt[0].Kind != "query_text" {
				t.Fatalf("query_text %+v", qt)
			}
		})
	}
}

func TestPHPSQLTextFollowThisMethod(t *testing.T) {
	uses := sqlTextUses(t, `class Qs { function sql($i) { return "SELECT a FROM t WHERE b = " . $i; } function run($c, $i) { return pg_query($c, $this->sql($i)); } }
$o = new Qs; $o->run(pg_connect('h'), $_GET['x']);`)
	if got := sqlTextOnlySQL(uses); len(got) != 1 || sqlTextSlots(got[0])[parse.SQLTextSlot] != 1 {
		t.Fatalf("records %+v", uses)
	}
}

// Prose that is not SQL gives no record in any of the forms.
func TestPHPSQLTextFollowProse(t *testing.T) {
	for _, body := range []string{
		`pg_query($c, implode(" ", ["Select a file", "from the list", $_GET['x']]));`,
		`function msg($n) { return "Update your settings, " . $n; } pg_query($c, msg($_GET['x']));`,
		`function msg($n) { if ($n) { return "Delete from the list"; } return "Hello " . $n; } pg_query($c, msg($_GET['x']));`,
		`const M = "Select a file from the list "; pg_query($c, M . $_GET['x']);`,
		`$v = $_GET['x']; pg_query($c, <<<TXT\nSelect a file from the list {$v}\nTXT\n);`,
		`pg_query($c, sprintf("Select a file from the list %s", $_GET['x']));`,
	} {
		if uses := sqlTextUses(t, "$c = pg_connect('h');\n"+body); len(uses) != 0 {
			t.Errorf("%s: records %+v", body, uses)
		}
	}
}

// A helper with two returns, one SQL and one not: the record is made whichever
// comes first.
func TestPHPSQLTextHelperTwoReturns(t *testing.T) {
	for _, order := range []string{
		`if ($n) { return "nothing"; } return "SELECT a FROM t WHERE b = " . $n;`,
		`if ($n) { return "SELECT a FROM t WHERE b = " . $n; } return "nothing";`,
	} {
		uses := sqlTextUses(t, "function pick($n) { "+order+" }\n$c = pg_connect('h'); pg_query($c, pick($_GET['x']));")
		if len(sqlTextOnlySQL(uses)) != 1 {
			t.Errorf("%s: records %d", order, len(uses))
		}
	}
}

// The hook follows one function body from the text argument: a helper call inside
// the helper is a hole. A chain longer than the flow's own bound gives no panic.
func TestPHPSQLTextHelperDepthLimit(t *testing.T) {
	const inner = `function inner() { return implode(" ", ["SELECT a FROM t WHERE b =", "1"]); }` + "\n"
	one := inner + `$c = pg_connect('h'); pg_query($c, inner() . $_GET['x']);`
	if uses := sqlTextOnlySQL(sqlTextUses(t, one)); len(uses) != 1 {
		t.Fatalf("one level: records %d", len(uses))
	}
	two := inner + `function outer() { return inner(); } $c = pg_connect('h'); pg_query($c, outer() . $_GET['x']);`
	if uses := sqlTextOnlySQL(sqlTextUses(t, two)); len(uses) != 0 {
		t.Fatalf("two levels: records %d", len(uses))
	}
	var b strings.Builder
	b.WriteString(inner)
	for i := 1; i <= 12; i++ {
		prev := "inner"
		if i > 1 {
			prev = fmt.Sprintf("h%d", i-1)
		}
		fmt.Fprintf(&b, "function h%d() { return %s(); }\n", i, prev)
	}
	b.WriteString(`$c = pg_connect('h'); pg_query($c, h12() . $_GET['x']);`)
	if uses := sqlTextOnlySQL(sqlTextUses(t, b.String())); len(uses) != 0 {
		t.Fatalf("long chain: records %d", len(uses))
	}
	// A list of more elements than the bound is a hole.
	var many []string
	for i := 0; i < 100; i++ {
		many = append(many, `"x"`)
	}
	body := `$c = pg_connect('h'); pg_query($c, implode(" ", [` + strings.Join(many, ",") + `, $_GET['x']]));`
	if uses := sqlTextUses(t, body); len(uses) != 0 {
		t.Fatalf("long list: records %d", len(uses))
	}
}

// Text from another module: a function, a class constant behind a static method
// and a const of another file. The context holds the sink's file and an excerpt
// of the other file with the definition.
func TestPHPSQLTextFollowOtherFile(t *testing.T) {
	uses := phpUsesOfKind(phpAnalyze(t, "testdata/sql-text/follow", "index.php"), "sql_query_candidate")
	uses = sqlTextOnlySQL(uses)
	if len(uses) != 3 {
		t.Fatalf("records %d: %+v", len(uses), uses)
	}
	for _, u := range uses {
		if s := sqlTextSlots(u); len(s) != 1 || s[parse.SQLTextSlot] != 1 {
			t.Errorf("%d slots %v", u.Sink.Span.StartLine, s)
		}
		sink, def := false, false
		for _, e := range u.Context {
			if !sqlTextJudgeKind(e.Kind) {
				continue
			}
			if e.Span.File == u.Sink.Span.File && e.Span.StartByte <= u.Sink.Span.StartByte && e.Span.EndByte >= u.Sink.Span.EndByte {
				sink = true
			}
			if e.Span.File == "queries.php" && strings.Contains(e.Text, "SELECT id FROM") {
				def = true
			}
		}
		if !sink || !def {
			t.Errorf("line %d: sink excerpt %v, definition of queries.php %v: %+v", u.Sink.Span.StartLine, sink, def, u.Context)
		}
	}
}

// A definition in the sink's file that the sent excerpt does not hold is
// attached as referenced_definition.
func TestPHPSQLTextReferencedDefinition(t *testing.T) {
	var b strings.Builder
	b.WriteString("<?php\nfunction build($id) { return \"SELECT a FROM t WHERE b = \" . $id; }\n")
	for i := 0; i < 1200; i++ {
		fmt.Fprintf(&b, "// filler line %d to push the call out of the excerpt window\n", i)
	}
	b.WriteString("$c = pg_connect('h');\npg_query($c, build($_GET['x']));\n")
	root := phpFixture(t, map[string]string{"index.php": b.String()})
	uses := sqlTextOnlySQL(phpUsesOfKind(phpAnalyze(t, root, "index.php"), "sql_query_candidate"))
	if len(uses) != 1 {
		t.Fatalf("records %d", len(uses))
	}
	found := false
	for _, e := range uses[0].Context {
		if sqlTextJudgeKind(e.Kind) && e.Span.File == "index.php" && strings.Contains(e.Text, "function build") && (e.Kind == "referenced_definition" || e.Kind == "helper_definition" || e.Kind == parse.SQLTextSourceExcerptKind) {
			found = true
		}
	}
	if !found {
		t.Fatalf("no evidence holds the helper: %+v", uses[0].Context)
	}
}

// A statement text built by a formatting or joining call is recorded once, at the
// call that takes it, not also at the formatting call.
func TestPHPSQLTextFormatCallIsNotASink(t *testing.T) {
	for _, body := range []string{
		`pg_query($c, sprintf("SELECT a FROM t WHERE b = '%s'", $_GET['x']));`,
		`pg_query($c, vsprintf("SELECT a FROM t WHERE b = '%s'", [$_GET['x']]));`,
	} {
		uses := sqlTextUses(t, "$c = pg_connect('h');\n"+body)
		if len(uses) != 1 || !strings.HasPrefix(uses[0].Sink.Text, "pg_query") {
			t.Errorf("%s: %+v", body, uses)
		}
	}
}

// Where each hole sits: outside quotes, inside a single-quoted literal; a text
// with no hole has no such evidence.
func TestPHPSQLTextPlacementEvidence(t *testing.T) {
	for _, c := range []struct{ name, body, want string }{
		{"concatenated outside quotes", `pg_query($c, "SELECT a FROM t WHERE b = " . $_GET['x']);`, "{1}: outside quotes"},
		{"inside single quotes", `pg_query($c, "SELECT a FROM t WHERE b = '" . $_GET['x'] . "'");`, "{1}: inside a single-quoted literal"},
		{"interpolated", `pg_query($c, "SELECT a FROM t WHERE b = '$_GET[x]'");`, "{1}: inside a single-quoted literal"},
		{"joined", `pg_query($c, implode(" ", ["SELECT a FROM t WHERE b =", $_GET['x']]));`, "{1}: outside quotes"},
		{"formatted", `pg_query($c, sprintf("SELECT a FROM t WHERE b = '%s'", $_GET['x']));`, "{1}: inside a single-quoted literal"},
		{"prepared text and bind", `$s = $db->prepare("SELECT a FROM t WHERE b = " . $_GET['x'] . " AND c = :c"); $s->bindValue(':c', $_GET['c']); $s->execute();`, "{1}: outside quotes"},
	} {
		t.Run(c.name, func(t *testing.T) {
			uses := sqlTextOnlySQL(sqlTextUses(t, "$c = pg_connect('h');\n"+c.body))
			if len(uses) != 1 {
				t.Fatalf("records %d", len(uses))
			}
			ev := uses[0].Completeness.Evidence[parse.SQLTextPlacementKind]
			if len(ev) != 1 || ev[0].Kind != parse.SQLTextPlacementKind || ev[0].ModelText != c.want {
				t.Fatalf("placement %+v, want %s", ev, c.want)
			}
		})
	}
	for _, body := range []string{
		`pg_query_params($c, "SELECT a FROM t WHERE b = $1", [$_GET['x']]);`,
		`$s = $db->prepare("SELECT a FROM t WHERE b = :b"); $s->bindValue(':b', $_GET['x']); $s->execute();`,
	} {
		uses := sqlTextOnlySQL(sqlTextUses(t, "$c = pg_connect('h');\n"+body))
		if len(uses) != 1 {
			t.Fatalf("%s: records %d", body, len(uses))
		}
		if _, ok := uses[0].Completeness.Evidence[parse.SQLTextPlacementKind]; ok {
			t.Errorf("%s: placement evidence for a text with no hole", body)
		}
	}
}
