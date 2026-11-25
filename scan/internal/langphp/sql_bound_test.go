package langphp

import (
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/guidelines"
)

// TestPHPBoundFacts states the fact of a constant statement with bound values. It
// is stated only for a literal in its own prepare call, with nothing but bind calls
// before the execution.
func TestPHPBoundFacts(t *testing.T) {
	const (
		connect = "<?php\n$db = new PDO('mysql:host=h;dbname=d', 'u', 'p');\n$id = $_GET['id'];\n"
		literal = `$s = $db->prepare("SELECT a FROM u WHERE id = :id"); `
		built   = `$s = $db->prepare("SELECT a FROM u WHERE id = :id AND n = " . $_GET["z"]); `
		bind    = `$s->bindParam(":id", $id); `
		run     = bind + `$s->execute();`
	)
	cases := []struct {
		name, body string
		want       bool
	}{
		{"literal and bind", literal + run, true},
		{"single quotes", `$s = $db->prepare('SELECT a FROM u WHERE id = :id'); ` + run, true},
		{"transformed before the bind", `$id = stripslashes(trim($id)); ` + literal + run, true},
		{"escaped before the bind", `$c = mysqli_connect("h"); $id = isset($c) ? mysqli_real_escape_string($c, $id) : ""; ` + literal + run, true},
		{"update", `$s = $db->prepare("UPDATE u SET n = 1 WHERE id = :id"); ` + run, true},
		{"insert values", `$s = $db->prepare("INSERT INTO u (a, b) VALUES (:id, 1)"); ` + run, true},
		{"delete", `$s = $db->prepare("DELETE FROM u WHERE id = :id"); ` + run, true},
		{"bindValue, comment, result in a condition", literal + "// bind\n$s->bindValue(':id', $id, PDO::PARAM_INT); if ($s->execute()) { echo 1; }", true},
		{"result assigned", literal + bind + `$ok = $s->execute();`, true},
		{"inside one switch case", `switch ($_GET["m"]) { case "a": ` + literal + run + ` break; default: exit; }`, true},
		{"grouped placeholder", `$s = $db->prepare("SELECT a FROM u WHERE (id = (:id) AND n IN (1, 2)) ORDER BY lower(a)"); ` + run, true},
		{"sqlite3", `$l = new SQLite3("a.db"); $s = $l->prepare("SELECT a FROM u WHERE id = :id"); $s->bindValue(":id", $id); $r = $s->execute();`, true},

		{"interpolated table", `$t = $_GET["t"]; $s = $db->prepare("SELECT a FROM $t WHERE id = :id"); ` + run, false},
		{"unresolved interpolation", `$s = $db->prepare("SELECT a FROM ${t} WHERE id = :id"); ` + run, false},
		{"concatenated", built + run, false},
		{"sprintf", `$s = $db->prepare(sprintf("SELECT a FROM u WHERE id = :id AND n = %s", $_GET["z"])); ` + run, false},
		{"implode", `$s = $db->prepare("SELECT a FROM u WHERE id = :id AND n IN (" . implode(",", $_GET["z"]) . ")"); ` + run, false},
		{"heredoc", "$s = $db->prepare(<<<S\nSELECT a FROM {$_GET[\"t\"]} WHERE id = :id\nS); " + run, false},
		{"text in a variable", `$q = "SELECT a FROM u WHERE id = :id"; $s = $db->prepare($q); ` + run, false},
		{"text passed to a call", `$q = "SELECT a FROM u WHERE id = :id"; alter($q); $s = $db->prepare($q); ` + run, false},
		{"text by reference", `$q = "SELECT a FROM u WHERE id = :id"; $r = &$q; $r .= $_GET["z"]; $s = $db->prepare($q); ` + run, false},
		{"text after extract", `$q = "SELECT a FROM u WHERE id = :id"; extract($_GET); $s = $db->prepare($q); ` + run, false},
		{"text after a variable variable", `$q = "SELECT a FROM u WHERE id = :id"; $n = $_GET["n"]; $$n = $_GET["z"]; $s = $db->prepare($q); ` + run, false},
		{"text in a global", `function add() { $GLOBALS["q"] .= $_GET["z"]; } $q = "SELECT a FROM u WHERE id = :id"; add(); $s = $db->prepare($q); ` + run, false},
		{"text from an unknown call", `$s = $db->prepare(build("SELECT a FROM u WHERE id = :id")); ` + run, false},

		{"replaced in a branch", literal + `if ($x) { ` + built + `} ` + run, false},
		{"replaced by an unknown call in a branch", literal + `if ($x) { $s = $db->prepare(build($_GET["z"])); } ` + run, false},
		{"literal only in a later branch", built + `if ($x) { ` + literal + `} ` + run, false},
		{"literal in the first arm", `if ($x) { ` + literal + `} else { ` + built + `} ` + run, false},
		{"literal in the last arm", `if ($x) { ` + built + `} else { ` + literal + `} ` + run, false},
		{"literal in an arm without braces", built + `if ($x) ` + literal + run, false},
		{"literal in the last case", `switch ($_GET["m"]) { case "a": ` + built + ` break; default: ` + literal + `} ` + run, false},
		{"case falls through to a built text", `switch ($_GET["m"]) { case "a": ` + literal + ` case "b": ` + built + run + ` }`, false},
		{"case reached without the literal", built + `switch ($_GET["m"]) { case "a": ` + literal + ` case "b": ` + run + ` }`, false},
		{"literal after a short circuit", built + `isset($_GET["q"]) && ` + literal + run, false},
		{"one arm of a conditional", `$s = $x ? $db->prepare("SELECT a FROM u WHERE id = :id") : $db->prepare("SELECT a FROM u WHERE id = :id AND n = " . $_GET["z"]); ` + run, false},
		{"assigned in a try", built + `try { f(); ` + literal + `} catch (Exception $e) {} ` + run, false},
		{"label between", built + `if ($x) goto run; ` + literal + `run: ` + run, false},
		{"reassigned", literal + built + run, false},

		{"statement passed to a call", literal + `alter($s); ` + run, false},
		{"statement returned by a call", literal + `$s = wrap($s); ` + run, false},
		{"statement aliased", literal + `$r = &$s; $r = $db->prepare("SELECT a FROM u WHERE id = :id AND n = " . $_GET["z"]); ` + run, false},
		{"statement variable variable", literal + `$k = "s"; $$k = $db->prepare("SELECT a FROM u WHERE id = :id AND n = " . $_GET["z"]); ` + run, false},
		{"file included between", literal + `include "x.php"; ` + run, false},
		{"function that replaces a global", `function swap() { global $s, $db; $s = $db->prepare("SELECT a FROM u WHERE id = :id AND n = " . $_GET["z"]); } ` + literal + `swap(); ` + run, false},
		{"function called inside a bind", `function swap() { global $s, $db; $s = $db->prepare("SELECT a FROM u WHERE id = :id AND n = " . $_GET["z"]); return 1; } ` + literal + bind + `$s->bindValue(":n", swap()); $s->execute();`, false},
		{"replaced in a loop after the execution", literal + `foreach ($_GET["f"] as $f) { ` + run + ` $s = $db->prepare("SELECT a FROM u WHERE id = :id AND n = " . $f); }`, false},

		{"wrapped connection", `$db = wrap($db); ` + literal + run, false},
		{"connection wrapped in a branch", `if ($x) { $db = wrap($db); } ` + literal + run, false},

		{"stored procedure", `$s = $db->prepare("CALL run_sql(:id)"); ` + run, false},
		{"dynamic statement", `$s = $db->prepare("EXECUTE IMMEDIATE :id"); ` + run, false},
		{"second dynamic statement", `$s = $db->prepare("SELECT 1; EXEC(:id)"); ` + run, false},
		{"placeholder after a nested function", `$s = $db->prepare("SELECT run(lower('x'), :id) FROM u"); ` + run, false},
		{"placeholder nested in functions", `$s = $db->prepare("SELECT run(lower(:id)) FROM u"); ` + run, false},
		{"placeholder in a function beside a quoted parenthesis", `$s = $db->prepare("SELECT run('(', :id) FROM u"); ` + run, false},
		{"placeholder in a function after a quoted quote", `$s = $db->prepare("SELECT run('a''(', :id) FROM u"); ` + run, false},
		{"backslash in a literal", `$s = $db->prepare("SELECT run('\\\\\'(', :id) FROM u"); ` + run, false},
		{"grouped placeholder in a function", `$s = $db->prepare("SELECT run((:id)) FROM u"); ` + run, false},
		{"function in a comment", `$s = $db->prepare("SELECT a FROM u WHERE id = /*! run( */ :id"); ` + run, false},
		{"second statement", `$s = $db->prepare("SELECT 1; SET GLOBAL init_connect = :id"); ` + run, false},
		{"connection wrapped by a method", `$db = $x->wrap($db); ` + literal + run, false},
		{"connection wrapped by a static method", `$db = X::wrap($db); ` + literal + run, false},
		{"dynamic bind method", literal + `$m = $_GET["m"]; ` + literal + `$s->$m(":id", $id); ` + run, false},
		{"placeholder in a database function", `$s = $db->prepare("SELECT query_to_xml(:id, true, true, 0)"); ` + run, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := phpAnalyze(t, phpFixture(t, map[string]string{"index.php": connect + c.body + "\n"}), "index.php")
			uses := phpUsesOfKind(r, "sql_query_candidate")
			if len(uses) == 0 {
				t.Fatal("no record: the form tests nothing")
			}
			got := false
			for _, u := range uses {
				for _, fact := range u.Completeness.ModelFacts {
					got = got || strings.HasPrefix(fact, "constant_sql_bound_values: ")
					if code, ok := guidelines.FactCode(fact); !ok || !guidelines.KnownFact(code) {
						t.Errorf("fact %q has no note", fact)
					}
				}
			}
			if got != c.want {
				t.Fatalf("fact stated: %v, want %v", got, c.want)
			}
		})
	}
}

// TestPHPBoundFactsOwnClass withholds the fact from a namespace's own PDO class,
// declared once or in two files, and states it for the built-in class.
func TestPHPBoundFactsOwnClass(t *testing.T) {
	const own = "<?php\nnamespace App;\nclass PDO { function prepare($q) { return mystery($q); } }\n"
	const use = "$id = $_GET['id']; $s = $db->prepare('SELECT a FROM u WHERE id = :id'); $s->bindParam(':id', $id); $s->execute();\n"
	for _, c := range []struct {
		name  string
		files map[string]string
		want  bool
	}{
		{"built-in", map[string]string{"index.php": "<?php\nnamespace App;\nuse PDO;\n$db = new PDO('mysql:host=h');\n" + use, "own.php": own}, true},
		{"own class", map[string]string{"index.php": "<?php\nnamespace App;\n$db = new PDO('mysql:host=h');\n" + use, "own.php": own}, false},
		{"own class twice", map[string]string{"index.php": "<?php\nnamespace App;\n$db = new PDO('mysql:host=h');\n" + use, "own.php": own, "other.php": own}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := phpAnalyze(t, phpFixture(t, c.files), "index.php")
			got := false
			for _, u := range phpUsesOfKind(r, "sql_query_candidate") {
				got = got || strings.Contains(strings.Join(u.Completeness.ModelFacts, " "), "constant_sql_bound_values")
			}
			if got != c.want {
				t.Fatalf("fact stated: %v, want %v", got, c.want)
			}
		})
	}
}
