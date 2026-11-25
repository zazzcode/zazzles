package langphp

import (
	"os"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/guidelines"
)

// phpSQLRecordFacts returns the SQL records of a program and the facts they state.
func phpSQLRecordFacts(t *testing.T, files map[string]string) (int, []string) {
	t.Helper()
	uses := phpUsesOfKind(phpAnalyze(t, phpFixture(t, files), "index.php"), "sql_query_candidate")
	var facts []string
	for _, u := range uses {
		for _, fact := range u.Completeness.ModelFacts {
			if code, ok := guidelines.FactCode(fact); !ok || !guidelines.KnownFact(code) {
				t.Errorf("fact %q has no note", fact)
			}
		}
		facts = append(facts, u.Completeness.ModelFacts...)
	}
	return len(uses), facts
}

const digitQuery = `mysqli_query($db, "SELECT a FROM t WHERE id = $id");`

const (
	phpFactConnect = "<?php\n$db = mysqli_connect('h', 'u', 'p', 'd');\n"
	phpFactEscape  = `$v = mysqli_real_escape_string($db, $_POST['v']); `
	phpFactQuery   = `mysqli_query($db, "SELECT a FROM t WHERE b = '$v'");`
)

// TestPHPSQLFacts states operand facts for the plain pattern only.
func TestPHPSQLFacts(t *testing.T) {
	const escaped, hash, integer, digits = "escaped_in_quoted_literal: ", "hash_hex_result: ", "integer_conversion_result: ", "digit_pattern_value: "
	cases := []struct {
		name, body string
		want       []string
	}{
		{"interpolated", phpFactEscape + phpFactQuery, []string{escaped + "$v from mysqli_real_escape_string($db, $_POST['v']) at index.php; quoted literal"}},
		{"concatenated", phpFactEscape + `mysqli_query($db, "SELECT a FROM t WHERE b = '" . $v . "'");`, []string{escaped + "$v"}},
		{"braces", phpFactEscape + `mysqli_query($db, 'SELECT a ' . ("FROM t WHERE b = '{$v}'"));`, []string{escaped + "$v"}},
		{"text in a variable", phpFactEscape + `$q = "SELECT a FROM t WHERE b = '$v'"; mysqli_query($db, $q);`, []string{escaped + "$v"}},
		{"no variable", `mysqli_query($db, "SELECT a FROM t WHERE b = '" . mysqli_real_escape_string($db, $_POST['v']) . "'");`, []string{escaped + "mysqli_real_escape_string($db, $_POST['v'])"}},
		{"hash", `$v = md5($_POST['v']); ` + phpFactQuery, []string{hash + "$v from md5($_POST['v']) at index.php"}},
		{"sha1", `$v = sha1(trim($_POST['v'])); ` + phpFactQuery, []string{hash + "$v"}},
		{"two operands, prepared in steps", `$v = $_POST['v']; $v = stripslashes($v); $v = mysqli_real_escape_string($db, $v); $p = $_POST['p']; $p = stripslashes($p); $p = mysqli_real_escape_string($db, $p); $p = md5($p); $q = "SELECT a FROM t WHERE b = '$v' AND c = '$p'"; $r = @mysqli_query($db, $q) or die('x');`,
			[]string{escaped + "$v", hash + "$p"}},
		{"text alone before the query", `$q = "SELECT a FROM t WHERE b = '" . mysqli_real_escape_string($db, $_POST['v']) . "'"; mysqli_query($db, $q);`, []string{escaped + "mysqli_real_escape_string($db, $_POST['v'])"}},
		{"plain parts of an argument", `$v = md5("a\n$x" . $_GET['g'] . $_REQUEST['r'] . $_COOKIE['c'] . SALT); ` + phpFactQuery, []string{hash + "$v"}},
		{"integer compared", `$n = intval($_GET['n']); ` + "// id\n" + `$q = "SELECT a FROM t WHERE id = $n"; $r = mysqli_query($db, $q);`, []string{integer + "$n from intval($_GET['n']) at index.php"}},
		{"integer cast, every bare place", `$n = (int) $_GET['n']; $m = (integer) trim($_POST['m']); mysqli_query($db, "SELECT a FROM t WHERE (id >= $n) AND c IN ($m, {$n}) ORDER BY a LIMIT $n OFFSET $m;");`, []string{integer + "$n from (int) $_GET['n']", integer + "$m", integer + "$n", integer + "$n", integer + "$m"}},
		{"integer quoted, with others", `$n = intval($_GET['n']); ` + phpFactEscape + `$h = md5($_POST['h']); mysqli_query($db, "INSERT INTO t (a, b, c) VALUES ('$n', '$v', '$h'), ($n, '$v', '$h')");`, []string{integer + "$n", escaped + "$v", hash + "$h", integer + "$n", escaped + "$v", hash + "$h"}},
		{"integer in the call", `mysqli_query($db, "SELECT a FROM t WHERE id = " . intval($_GET['n']) . ";");`, []string{integer + "intval($_GET['n'])"}},
		{"digits checked, else branch", `if (!preg_match('/^\d+$/', $_GET['id'])) { exit; } else { ` + "// read\n" + `$id = $_GET['id']; $found = false; $q = "SELECT a FROM t WHERE id = '$id'"; $r = mysqli_query($db, $q); }`, []string{digits + `$id from preg_match('/^\d+$/', $_GET['id']) at index.php`}},
		{"digits checked, then branch", `if (preg_match("/^[0-9]+$/D", $_POST["id"])) { $id = $_POST['id']; $e = null; $f = 0; mysqli_query($db, "SELECT a FROM t WHERE id = $id"); }`, []string{digits + "$id"}},
		{"used twice", phpFactEscape + `mysqli_query($db, "SELECT a FROM t WHERE b = '$v' OR c LIKE '%$v%'");`, []string{escaped + "$v", escaped + "$v"}},
		{"conditional", `$v = (isset($db) && !is_object($db) ? mysqli_real_escape_string($db, $_POST['v']) : (trigger_error("x", E_USER_ERROR) ? "" : '')); ` + phpFactQuery, []string{escaped + "$v"}},
		{"conditional, call last", `$v = empty($_POST['v']) ? "" : mysqli_real_escape_string($db, $_POST['v']); ` + phpFactQuery, []string{escaped + "$v"}},
		{"both alternatives", `$v = $x ? mysqli_real_escape_string($db, $_POST['v']) : mysqli_real_escape_string($db, $_GET['v']); ` + phpFactQuery, []string{escaped + "$v"}},
		{"connection in a global", `$GLOBALS['c'] = $db; $v = mysqli_real_escape_string($GLOBALS["c"], $_POST['v']); mysqli_query($GLOBALS['c'], "SELECT a FROM t WHERE b = '$v'");`, []string{escaped + "$v"}},
		{"in a function", `function go($db, $v) { $v = mysqli_real_escape_string($db, $v); return mysqli_query($db, "SELECT a FROM t WHERE b = '$v'"); } go($db, $_GET['v']);`, []string{escaped + "$v"}},
		{"in a case", `switch ($_GET['m']) { case 'a': ` + phpFactEscape + phpFactQuery + ` break; default: ` + phpFactEscape + phpFactQuery + ` }`, []string{escaped + "$v", escaped + "$v"}},
		{"in a condition", phpFactEscape + "// run\n" + `if (!($r = mysqli_query($db, "SELECT a FROM t WHERE b = '$v'"))) { exit; }`, []string{escaped + "$v"}},
		{"name reused for the text", phpFactEscape + `$v = "SELECT a FROM t WHERE b = '$v'"; mysqli_query($db, $v);`, []string{escaped + "$v"}},
		{"bitwise and, logical and beside the name", phpFactEscape + phpFactQuery + ` if ($x && $v) { exit; }`, []string{escaped + "$v"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, got := phpSQLRecordFacts(t, map[string]string{"index.php": phpFactConnect + c.body + "\n"})
			if len(got) != len(c.want) {
				t.Fatalf("facts %q, want %q", got, c.want)
			}
			for i, fact := range got {
				if !strings.HasPrefix(fact+" ", c.want[i]+" ") {
					t.Errorf("fact %q, want %q", fact, c.want[i])
				}
			}
		})
	}
}

// TestPHPSQLFactTraps withholds the fact when one part of the plain pattern is
// missing. Each form makes a record.
func TestPHPSQLFactTraps(t *testing.T) {
	const hashed = `$v = md5($_POST['v']); `
	const inline = `mysqli_real_escape_string($db, $_POST['v'])`
	cases := []struct{ name, body string }{
		{"raw", `$v = $_POST['v']; ` + phpFactQuery},
		{"multiple statements", phpFactEscape + `mysqli_multi_query($db, "SELECT a FROM t WHERE b = '$v'");`},
		{"real query", phpFactEscape + `mysqli_real_query($db, "SELECT a FROM t WHERE b = '$v'");`},
		{"method", phpFactEscape + `$db->query("SELECT a FROM t WHERE b = '$v'");`},
		{"third argument", phpFactEscape + `mysqli_query($db, "SELECT a FROM t WHERE b = '$v'", $m);`},
		{"spread argument", phpFactEscape + `mysqli_query($db, ...["SELECT a FROM t WHERE b = '$v'"]);`},
		{"qualified name", phpFactEscape + `\mysqli_query($db, "SELECT a FROM t WHERE b = '$v'");`},

		{"connection from a call", `$v = mysqli_real_escape_string(db(), $_POST['v']); mysqli_query(db(), "SELECT a FROM t WHERE b = '$v'");`},
		{"connection in a property", `$v = mysqli_real_escape_string($o->db, $_POST['v']); mysqli_query($o->db, "SELECT a FROM t WHERE b = '$v'");`},
		{"connection in an array", `$v = mysqli_real_escape_string($o['db'], $_POST['v']); mysqli_query($o['db'], "SELECT a FROM t WHERE b = '$v'");`},
		{"connection under a chosen key", `$v = mysqli_real_escape_string($GLOBALS[$k], $_POST['v']); mysqli_query($GLOBALS[$k], "SELECT a FROM t WHERE b = '$v'");`},
		{"another connection", `$v = mysqli_real_escape_string($other, $_POST['v']); ` + phpFactQuery},
		{"another global connection", `$v = mysqli_real_escape_string($GLOBALS['a'], $_POST['v']); mysqli_query($GLOBALS['b'], "SELECT a FROM t WHERE b = '$v'");`},
		{"global and local connection", `$v = mysqli_real_escape_string($GLOBALS['db'], $_POST['v']); ` + phpFactQuery},
		{"connection replaced", phpFactEscape + `$db = $other; ` + phpFactQuery},
		{"connection is an operand", `$db = mysqli_real_escape_string($db, $_POST['v']); mysqli_query($db, "SELECT a FROM t WHERE b = '$db'");`},
		{"global connection is an operand", `$v = mysqli_real_escape_string($GLOBALS['v'], $_POST['v']); mysqli_query($GLOBALS['v'], "SELECT a FROM t WHERE b = '$v'");`},
		{"global connection is the text", `$v = mysqli_real_escape_string($GLOBALS['q'], $_POST['v']); $q = "SELECT a FROM t WHERE b = '$v'"; mysqli_query($GLOBALS['q'], $q);`},

		{"too many escape arguments", `$v = mysqli_real_escape_string($db, $_POST['v'], 'x'); ` + phpFactQuery},
		{"escape argument writes", `$v = mysqli_real_escape_string($db, $db = $other); ` + phpFactQuery},
		{"escape argument runs code", `$v = mysqli_real_escape_string($db, swap($_POST['v'])); ` + phpFactQuery},
		{"escape undone", `$v = stripslashes(mysqli_real_escape_string($db, $_POST['v'])); ` + phpFactQuery},
		{"escape in a string undone", phpFactEscape + `$w = stripslashes("$v"); mysqli_query($db, "SELECT a FROM t WHERE b = '$w'");`},
		{"escape cut", `$v = substr(mysqli_real_escape_string($db, $_POST['v']), 0, 9); ` + phpFactQuery},
		{"escape complemented", `$v = ~mysqli_real_escape_string($db, $_POST['v']); ` + phpFactQuery},
		{"escape appended to", `$v = mysqli_real_escape_string($db, $_POST['v']) . $_POST['w']; ` + phpFactQuery},
		{"copied operand", phpFactEscape + `$w = $v; mysqli_query($db, "SELECT a FROM t WHERE b = '$w'");`},
		{"own hash function", `$v = crc32($_POST['v']); ` + phpFactQuery},
		{"binary hash", `$v = md5($_POST['v'], true); ` + phpFactQuery},
		{"binary hash by a variable", `$v = md5($_POST['v'], $raw); ` + phpFactQuery},
		{"plain call on the connection", `$v = trim($db, $_POST['v']); ` + phpFactQuery},
		{"element without a key", `$v = md5($_POST[]); ` + phpFactQuery},
		{"empty, or another connection", `$v = $x ? "" : mysqli_real_escape_string($other, $_POST['v']); ` + phpFactQuery},
		{"another connection in the first alternative", `$v = $x ? mysqli_real_escape_string($other, $_POST['v']) : mysqli_real_escape_string($db, $_POST['v']); ` + phpFactQuery},
		{"another connection in the last alternative", `$v = $x ? mysqli_real_escape_string($db, $_POST['v']) : mysqli_real_escape_string($other, $_POST['v']); ` + phpFactQuery},
		{"binary hash, named", `$v = md5(string: $_POST['v'], binary: true); ` + phpFactQuery},
		{"binary hash by spread", `$v = md5(...$_POST); ` + phpFactQuery},
		{"hash argument runs code", `$v = md5(swap($_POST['v'])); ` + phpFactQuery},
		{"one operand raw first", `$w = $_POST['w']; ` + phpFactEscape + `mysqli_query($db, "SELECT a FROM t WHERE c = '$w' AND b = '$v'");`},
		{"one operand raw last", phpFactEscape + `$w = $_POST['w']; mysqli_query($db, "SELECT a FROM t WHERE b = '$v' AND c = '$w'");`},
		{"one operand unknown", phpFactEscape + `mysqli_query($db, "SELECT a FROM t WHERE b = '$v' AND c = '$w'");`},
		{"one operand from a call", phpFactEscape + `mysqli_query($db, "SELECT a FROM t WHERE b = '$v' AND c = '" . param('c') . "'");`},

		{"code in an earlier write of an operand", `$w = md5($_POST['w']); $v = swap(); ` + phpFactEscape + `mysqli_query($db, "SELECT a FROM t WHERE b = '$v' AND c = '$w'");`},
		{"code in a call in the text", hashed + `mysqli_query($db, "SELECT a FROM t WHERE b = '$v' AND c = '" . md5(swap()) . "'");`},
		{"code in an escape in the text", phpFactEscape + `mysqli_query($db, "SELECT a FROM t WHERE b = '$v' AND c = '" . mysqli_real_escape_string($db, swap()) . "'");`},
		{"hash appended", `$v = $_POST['v']; $v .= md5($_POST['w']); ` + phpFactQuery},
		{"written by an echo", `echo $v = md5($_POST['v']); ` + phpFactQuery},
		{"named argument runs code", `$v = md5(trim(string: swap())); ` + phpFactQuery},
		{"comment among the arguments", `$v = md5($_POST['v'] /* c */); ` + phpFactQuery},
		{"hash, connection from a call", hashed + `mysqli_query(db(), "SELECT a FROM t WHERE b = '$v'");`},
		{"hash, connection in a property", hashed + `mysqli_query($o->db, "SELECT a FROM t WHERE b = '$v'");`},
		{"hash, connection in an array", hashed + `mysqli_query($o['db'], "SELECT a FROM t WHERE b = '$v'");`},
		{"hash, connection under a built key", hashed + `mysqli_query($GLOBALS["a$k"], "SELECT a FROM t WHERE b = '$v'");`},
		{"hash, connection under a key from a call", hashed + `mysqli_query($GLOBALS[key()], "SELECT a FROM t WHERE b = '$v'");`},
		{"hash, connection from an expression", hashed + `mysqli_query($GLOBALS . 'c', "SELECT a FROM t WHERE b = '$v'");`},
		{"hash, connection under a key with a property", hashed + `mysqli_query($GLOBALS["a" . $o->k], "SELECT a FROM t WHERE b = '$v'");`},
		{"text after a property", hashed + `mysqli_query($db, $o->head . "SELECT a FROM t WHERE b = '$v'");`},
		{"text before a property", hashed + `mysqli_query($db, "SELECT a FROM t WHERE b = '$v'" . $o->tail);`},
		{"element under a built key", `$v = md5($_POST["a$k"]); ` + phpFactQuery},
		{"other text ran", `$w = "SELECT a FROM t WHERE b = '$x'"; ` + phpFactEscape + `$q = "SELECT a FROM t WHERE b = '$v'"; mysqli_query($db, $w);`},

		{"integer after a minus", `$n = intval($_GET['n']); mysqli_query($db, "SELECT a FROM t WHERE x = 5-$n AND owner = 1");`},
		{"integer after a minus and a space", `$n = intval($_GET['n']); mysqli_query($db, "SELECT a FROM t WHERE x = 5 - $n AND owner = 1");`},
		{"integer after a sign", `$n = intval($_GET['n']); mysqli_query($db, "SELECT a FROM t WHERE x = -$n");`},
		{"integer before letters", `$n = intval($_GET['n']); mysqli_query($db, "SELECT a FROM t WHERE x = {$n}e5");`},
		{"integer before a point", `$n = intval($_GET['n']); mysqli_query($db, "SELECT a FROM t WHERE x = {$n}.5");`},
		{"integer after a point", `$n = intval($_GET['n']); mysqli_query($db, "SELECT a FROM t WHERE x = 1.$n");`},
		{"integer after letters", `$n = intval($_GET['n']); mysqli_query($db, "SELECT a FROM t WHERE x = id$n");`},
		{"integer after digits", `$n = intval($_GET['n']); mysqli_query($db, "SELECT a FROM t WHERE x = 1$n");`},
		{"two integers together", `$n = intval($_GET['n']); mysqli_query($db, "SELECT a FROM t WHERE x = $n$n");`},
		{"integer as a name", `$n = intval($_GET['n']); mysqli_query($db, "SELECT a FROM t ORDER BY $n");`},
		{"integer as a column", `$n = intval($_GET['n']); mysqli_query($db, "SELECT $n FROM t");`},
		{"integer in a function", `$n = intval($_GET['n']); mysqli_query($db, "SELECT a FROM t WHERE x = run($n)");`},
		{"integer as a second count", `$n = intval($_GET['n']); mysqli_query($db, "SELECT a FROM t LIMIT 1, $n");`},
		{"integer in an identifier", "$n = intval($_GET['n']); mysqli_query($db, \"SELECT a FROM `t$n`\");"},
		{"integer before a word", `$n = intval($_GET['n']); mysqli_query($db, "SELECT a FROM t WHERE x = $n UNION SELECT 1");`},
		{"float", `$n = floatval($_GET['n']); mysqli_query($db, "SELECT a FROM t WHERE x = $n");`},
		{"float cast", `$n = (float) $_GET['n']; mysqli_query($db, "SELECT a FROM t WHERE x = $n");`},
		{"string cast", `$n = (string) $_GET['n']; mysqli_query($db, "SELECT a FROM t WHERE x = '$n'");`},
		{"integer of a call", `$n = (int) swap(); mysqli_query($db, "SELECT a FROM t WHERE x = $n");`},
		{"integer in a base", `$n = intval($_GET['n'], 16); mysqli_query($db, "SELECT a FROM t WHERE x = $n");`},
		{"integer glued", `$n = (int) $_GET['n'] . $_GET['x']; mysqli_query($db, "SELECT a FROM t WHERE x = $n");`},
		{"integer or empty", `$n = $x ? intval($_GET['n']) : ""; mysqli_query($db, "SELECT a FROM t WHERE x = $n");`},
		{"integer or empty, quoted", `$n = $x ? intval($_GET['n']) : ""; mysqli_query($db, "SELECT a FROM t WHERE x = '$n'");`},
		{"integer changed after", `$n = intval($_GET['n']); $n = $_GET['n']; mysqli_query($db, "SELECT a FROM t WHERE x = $n");`},
		{"integer of another variable used", `$raw = $_GET['id']; $n = (int) $raw; mysqli_query($db, "SELECT a FROM t WHERE id = " . $raw);`},
		{"integer in a branch", `$n = $_GET['n']; if ($x) { $n = intval($n); } mysqli_query($db, "SELECT a FROM t WHERE x = $n");`},
		{"own integer function", `function intval($x) { return $x; } $n = intval($_GET['n']); mysqli_query($db, "SELECT a FROM t WHERE x = $n");`},
		{"digits, other element", `if (!preg_match('/^\d+$/', $_GET['id'])) { exit; } else { $id = $_GET['ix']; ` + digitQuery + ` }`},
		{"digits, other array", `if (!preg_match('/^\d+$/', $_GET['id'])) { exit; } else { $id = $_POST['id']; ` + digitQuery + ` }`},
		{"digits, element of a variable", `if (!preg_match('/^\d+$/', $a['id'])) { exit; } else { $id = $a['id']; ` + digitQuery + ` }`},
		{"digits, not negated", `if (preg_match('/^\d+$/', $_GET['id'])) { exit; } else { $id = $_GET['id']; ` + digitQuery + ` }`},
		{"digits, negated then branch", `if (!preg_match('/^\d+$/', $_GET['id'])) { $id = $_GET['id']; ` + digitQuery + ` }`},
		{"digits, else if between", `if (!preg_match('/^\d+$/', $_GET['id'])) { exit; } elseif (swap()) { exit; } else { $id = $_GET['id']; ` + digitQuery + ` }`},
		{"digits, else of an else if", `if ($x) { exit; } elseif (!preg_match('/^\d+$/', $_GET['id'])) { exit; } else { $id = $_GET['id']; ` + digitQuery + ` }`},
		{"digits, positive with an else", `if (preg_match('/^\d+$/', $_GET['id'])) { $id = $_GET['id']; ` + digitQuery + ` } else { exit; }`},
		{"digits, loop body", `while (preg_match('/^\d+$/', $_GET['id'])) { $id = $_GET['id']; ` + digitQuery + ` }`},
		{"digits, condition with more", `if (preg_match('/^\d+$/', $_GET['id']) || $x) { $id = $_GET['id']; ` + digitQuery + ` }`},
		{"digits, not first in the block", `if (preg_match('/^\d+$/', $_GET['id'])) { $z = 1; $id = $_GET['id']; ` + digitQuery + ` }`},
		{"digits, call first in the block", `if (preg_match('/^\d+$/', $_GET['id'])) { swap(); $id = $_GET['id']; ` + digitQuery + ` }`},
		{"digits, unanchored", `if (preg_match('/\d+/', $_GET['id'])) { $id = $_GET['id']; ` + digitQuery + ` }`},
		{"digits, start only", `if (preg_match('/^\d+/', $_GET['id'])) { $id = $_GET['id']; ` + digitQuery + ` }`},
		{"digits, multiline", `if (preg_match('/^\d+$/m', $_GET['id'])) { $id = $_GET['id']; ` + digitQuery + ` }`},
		{"digits, unicode", `if (preg_match('/^\d+$/u', $_GET['id'])) { $id = $_GET['id']; ` + digitQuery + ` }`},
		{"digits, wider class", `if (preg_match('/^[0-9-]+$/', $_GET['id'])) { $id = $_GET['id']; ` + digitQuery + ` }`},
		{"digits, pattern in a variable", `$p = '/^\d+$/'; if (preg_match($p, $_GET['id'])) { $id = $_GET['id']; ` + digitQuery + ` }`},
		{"digits, interpolated pattern", `if (preg_match("/^\d+$p/", $_GET['id'])) { $id = $_GET['id']; ` + digitQuery + ` }`},
		{"digits, matches written", `if (preg_match('/^\d+$/', $_GET['id'], $mm)) { $id = $_GET['id']; ` + digitQuery + ` }`},
		{"digits, own preg_match", `function preg_match($p, $s) { return 1; } if (preg_match('/^\d+$/', $_GET['id'])) { $id = $_GET['id']; ` + digitQuery + ` }`},
		{"digits, element replaced", `if (preg_match('/^\d+$/', $_GET['id'])) { $id = $_GET['id']; $id = $_GET['z']; ` + digitQuery + ` }`},
		{"digits, superglobal by reference", `$r = &$_GET; if (preg_match('/^\d+$/', $_GET['id'])) { $id = $_GET['id']; ` + digitQuery + ` }`},
		{"digits after a minus", `if (preg_match('/^\d+$/', $_GET['id'])) { $id = $_GET['id']; mysqli_query($db, "SELECT a FROM t WHERE x = 5-$id"); }`},
		{"digits, sign instead of not", `if (-preg_match('/^\d+$/', $_GET['id'])) { exit; } else { $id = $_GET['id']; ` + digitQuery + ` }`},
		{"digits, complement instead of not", `if (~preg_match('/^\d+$/', $_GET['id'])) { exit; } else { $id = $_GET['id']; ` + digitQuery + ` }`},
		{"request element in the text", `if (preg_match('/^\d+$/', $_GET['id'])) { mysqli_query($db, "SELECT a FROM t WHERE id = " . $_GET['id']); }`},
		{"digits after a block", `if (preg_match('/^\d+$/', $_GET['id'])) { exit; } $id = $_GET['id']; ` + digitQuery},
		{"non-operand text written after", phpFactEscape + `$w = 'x'; ` + phpFactQuery},
		{"raw alternative", `$v = $x ? mysqli_real_escape_string($db, $_POST['v']) : $_POST['v']; ` + phpFactQuery},
		{"raw first alternative", `$v = $x ? $_POST['v'] : mysqli_real_escape_string($db, $_POST['v']); ` + phpFactQuery},
		{"unknown alternative", `$v = $x ? mysqli_real_escape_string($db, $_POST['v']) : $o->raw(); ` + phpFactQuery},
		{"backslash alternative", `$v = $x ? mysqli_real_escape_string($db, $_POST['v']) : '\\'; ` + phpFactQuery},
		{"quote alternative", `$v = $x ? mysqli_real_escape_string($db, $_POST['v']) : "'"; ` + phpFactQuery},
		{"text alternative to a hash", `$v = $x ? md5($_POST['v']) : "none"; ` + phpFactQuery},
		{"interpolated alternative", `$v = $x ? mysqli_real_escape_string($db, $_POST['v']) : "$w"; ` + phpFactQuery},
		{"short conditional", `$v = $_POST['v'] ?: mysqli_real_escape_string($db, $_POST['v']); ` + phpFactQuery},
		{"null coalescing", `$v = $_POST['w'] ?? mysqli_real_escape_string($db, $_POST['v']); ` + phpFactQuery},
		{"escape or hash", `$v = $x ? mysqli_real_escape_string($db, $_POST['v']) : md5($_POST['v']); ` + phpFactQuery},
		{"condition writes", `$v = ($db = $other) ? mysqli_real_escape_string($db, $_POST['v']) : ""; ` + phpFactQuery},
		{"condition runs code", `$v = swap() ? mysqli_real_escape_string($db, $_POST['v']) : ""; ` + phpFactQuery},
		{"empty in both alternatives", `$v = $x ? "" : ''; $w = $_POST['w']; mysqli_query($db, "SELECT a FROM t WHERE b = '$v' AND c = '$w'");`},
		{"constant operand", `$v = ""; mysqli_query($db, "SELECT a FROM t WHERE b = '$v' AND c = '" . ` + inline + ` . "'");`},

		{"passed to a call", phpFactEscape + `undo($v); ` + phpFactQuery},
		{"any call between", phpFactEscape + `loadmore(); ` + phpFactQuery},
		{"call in a write between", phpFactEscape + `$v = undo($v); ` + phpFactEscape + `$w = swap(); ` + phpFactQuery},
		{"include between", phpFactEscape + `include $f; ` + phpFactQuery},
		{"extract between", phpFactEscape + `extract($_GET); ` + phpFactQuery},
		{"global array between", phpFactEscape + `$GLOBALS['v'] = $_POST['z']; ` + phpFactQuery},
		{"variable variable between", phpFactEscape + `$n = 'v'; $$n = $_POST['z']; ` + phpFactQuery},
		{"closure between", phpFactEscape + `$f(); ` + phpFactQuery},
		{"branch between", phpFactEscape + `if ($x) { $v = $o->raw(); } ` + phpFactQuery},
		{"branch without braces between", phpFactEscape + `if ($x) $v = $o->raw(); ` + phpFactQuery},
		{"loop between", phpFactEscape + `foreach ($rows as $v) {} ` + phpFactQuery},
		{"block between", phpFactEscape + `{ $v = $_POST['z']; } ` + phpFactQuery},
		{"label between", `if ($x) goto run; ` + phpFactEscape + `run: ` + phpFactQuery},
		{"list between", phpFactEscape + `[$v] = [$_POST['z']]; ` + phpFactQuery},
		{"element written between", phpFactEscape + `$v[0] = $c; ` + phpFactQuery},
		{"appended between", phpFactEscape + `$v .= $_POST['z']; ` + phpFactQuery},
		{"incremented between", phpFactEscape + `$v++; ` + phpFactQuery},
		{"static call between", phpFactEscape + `$w = X::run(); ` + phpFactQuery},
		{"new object between", phpFactEscape + `$w = new X; ` + phpFactQuery},
		{"property read between", phpFactEscape + `$w = $o->p; ` + phpFactQuery},
		{"element read between", `$v = md5($_POST['v']); $v = md5($o['p']); ` + phpFactQuery},
		{"comparison with code", `$v = md5($_POST['v'] == $o); ` + phpFactQuery},
		{"negated call", `$v = md5(!swap()); ` + phpFactQuery},
		{"arithmetic", `$v = md5(-$o); ` + phpFactQuery},
		{"interpolated element", `$v = md5("$o[p]"); ` + phpFactQuery},
		{"interpolated property", `$v = md5("{$o->p}"); ` + phpFactQuery},
		{"call in an alternative", `$v = md5($x ? 'a' : swap()); ` + phpFactQuery},
		{"call in a first alternative", `$v = md5($x ? swap() : 'a'); ` + phpFactQuery},
		{"call in a condition", `$v = md5(swap() ? 'a' : 'b'); ` + phpFactQuery},
		{"call in an argument", `$v = md5(trim(swap())); ` + phpFactQuery},
		{"call on the left", `$v = md5(swap() . 'x'); ` + phpFactQuery},
		{"call on the right", `$v = md5('x' . swap()); ` + phpFactQuery},
		{"call by a variable name", `$v = md5($f($_POST['v'])); ` + phpFactQuery},
		{"operand of another block", `if ($x) { ` + phpFactEscape + `} else { $v = mystery(); } ` + phpFactQuery},
		{"operand only in a branch", `$v = mystery(); if ($x) { ` + phpFactEscape + `} ` + phpFactQuery},
		{"operand of an earlier case", `switch ($x) { case 1: ` + phpFactEscape + ` case 2: ` + phpFactQuery + ` }`},
		{"operand replaced in a loop", `for ($i = 0; $i < 2; $i++) { if ($i) { undo($v); } else { ` + phpFactEscape + `} ` + phpFactQuery + ` }`},
		{"operand of the caller", phpFactEscape + `function go($db, $v) { mysqli_query($db, "SELECT a FROM t WHERE b = '$v'"); } go($db, $v);`},
		{"operand replaced after the escape", phpFactEscape + `$v = $_POST['z']; ` + phpFactQuery},
		{"another variable written after the operand", `$r = &$x; ` + phpFactEscape + `$r = $_POST['z']; ` + phpFactQuery},
		{"operand changed after the text", phpFactEscape + `$q = "SELECT a FROM t WHERE b = '$v'"; $v = $_POST['z']; mysqli_query($db, $q);`},
		{"text passed to a call", phpFactEscape + `$q = "SELECT a FROM t WHERE b = '$v'"; filters($q); mysqli_query($db, $q);`},
		{"text appended to", phpFactEscape + `$q = "SELECT a FROM t WHERE b = '$v'"; $q .= $_POST['z']; mysqli_query($db, $q);`},
		{"text written in a branch", phpFactEscape + `$q = "SELECT a FROM t WHERE b = '$v'"; if ($x) { $q = $_POST['z']; } mysqli_query($db, $q);`},
		{"text earlier written raw", phpFactEscape + `$q = $_POST['z']; $q = "SELECT a FROM t WHERE b = '$v'"; mysqli_query($db, $q);`},
		{"text of another variable", phpFactEscape + `$q = "SELECT a FROM t WHERE b = '$v'"; mysqli_query($db, $w . $q);`},
		{"text by an unknown call", phpFactEscape + `mysqli_query($db, build("SELECT a FROM t WHERE b = '$v'"));`},
		{"text in a nested variable", phpFactEscape + `$w = "'$v'"; mysqli_query($db, "SELECT a FROM t WHERE b = $w");`},

		{"reference parameter of the same name", `function f(&$v) {} ` + phpFactEscape + phpFactQuery},
		{"reference taken before", `$r = &$v; ` + phpFactEscape + phpFactQuery},
		{"made a reference before", `$v =& $r; ` + phpFactEscape + phpFactQuery},
		{"closure by reference", `$f = function () use (&$v) {}; ` + phpFactEscape + phpFactQuery},
		{"reference to the text", `$r = &$q; ` + phpFactEscape + `$q = "SELECT a FROM t WHERE b = '$v'"; mysqli_query($db, $q);`},

		{"call before the query in one statement", phpFactEscape + `undo($v) or mysqli_query($db, "SELECT a FROM t WHERE b = '$v'");`},
		{"call in the assigned element", phpFactEscape + `$a[undo($v)] = mysqli_query($db, "SELECT a FROM t WHERE b = '$v'");`},
		{"call in an earlier argument", phpFactEscape + `run(undo($v), mysqli_query($db, "SELECT a FROM t WHERE b = '$v'"));`},
		{"loop condition", phpFactEscape + `while (mysqli_query($db, "SELECT a FROM t WHERE b = '$v'")) { undo($v); }`},
		{"else-if condition", phpFactEscape + `if (undo($v)) { exit; } elseif (mysqli_query($db, "SELECT a FROM t WHERE b = '$v'")) { exit; }`},
		{"branch of the query", phpFactEscape + `if (undo($v)) mysqli_query($db, "SELECT a FROM t WHERE b = '$v'");`},

		{"escape sequence in the text", phpFactEscape + `mysqli_query($db, "SELECT a FROM t\nWHERE b = '$v'");`},
		{"escaped apostrophes", phpFactEscape + `mysqli_query($db, "SELECT a FROM t WHERE b = 'it\'s' AND c = $v AND d = 'can\'t'");`},
		{"escaped apostrophes in single quotes", phpFactEscape + `mysqli_query($db, 'SELECT a FROM t WHERE c = \'x\\\' AND b = \'' . $v . '\'');`},
		{"hexadecimal quote", phpFactEscape + `mysqli_query($db, "SELECT a FROM t WHERE b = 'a\x27 AND c = $v AND d = \x27b'");`},
		{"string offset", phpFactEscape + `$w = ` + inline + `; mysqli_query($db, "SELECT a FROM t WHERE b = '$v[0]' AND c = '$w'");`},
		{"braced offset", phpFactEscape + `mysqli_query($db, "SELECT a FROM t WHERE b = '{$v[0]}'");`},
		{"interpolated property of the operand", phpFactEscape + `mysqli_query($db, "SELECT a FROM t WHERE b = '$v->p'");`},
		{"dollar braces", phpFactEscape + `mysqli_query($db, "SELECT a FROM t WHERE b = '${v}'");`},
		{"heredoc", phpFactEscape + "mysqli_query($db, <<<S\nSELECT a FROM t WHERE b = '$v'\nS);"},
		{"number in the text", phpFactEscape + `mysqli_query($db, "SELECT a FROM t WHERE b = '" . $v . "' LIMIT " . 5);`},
		{"sum in the text", phpFactEscape + `mysqli_query($db, "SELECT a FROM t WHERE b = '" + $v . "'");`},
		{"sprintf", phpFactEscape + `mysqli_query($db, sprintf("SELECT a FROM t WHERE b = '%s'", $v));`},
		{"binary string moves the quotes", phpFactEscape + `mysqli_query($db, 'SELECT a FROM t WHERE b = ' . b'' . $v . b'');`},
		{"binary string prefix", phpFactEscape + `mysqli_query($db, b"SELECT a FROM t WHERE b = '$v'");`},
		{"not quoted", phpFactEscape + `mysqli_query($db, "SELECT a FROM t WHERE b = $v");`},
		{"hash not quoted", hashed + `mysqli_query($db, "SELECT a FROM t WHERE b = $v");`},
		{"name that ends in other letters", `$vé = mysqli_real_escape_string($db, $_POST['v']); mysqli_query($db, "SELECT a FROM t WHERE b = '$vé'");`},
		{"name with other letters", `$é = mysqli_real_escape_string($db, $_POST['v']); mysqli_query($db, "SELECT a FROM t WHERE b = '$é'");`},
		{"statement that does not parse", `$v = mysqli_real_escape_string($db, $_POST['v'] $x); ` + phpFactQuery},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			records, facts := phpSQLRecordFacts(t, map[string]string{"index.php": phpFactConnect + c.body + "\n"})
			if records == 0 {
				t.Fatal("no record: the form tests nothing")
			}
			if len(facts) > 0 {
				t.Fatalf("facts %q, want none", facts)
			}
		})
	}
}

// TestPHPSQLFactPrograms withholds the fact for what another file declares or sends.
func TestPHPSQLFactPrograms(t *testing.T) {
	const index = phpFactConnect + phpFactEscape + phpFactQuery + "\n"
	cases := []struct {
		name  string
		files map[string]string
		want  int
	}{
		{"plain program", map[string]string{"index.php": index, "other.php": "<?php function unrelated($v, &$vv) { return $v && $w; }"}, 1},
		{"own escape", map[string]string{"index.php": index, "other.php": "<?php if (1) { function mysqli_real_escape_string($c, $s) { return $s; } }"}, 0},
		{"own query", map[string]string{"index.php": index, "other.php": "<?php if (1) { function MySQLi_Query($c, $s) { return 1; } }"}, 0},
		{"own plain function", map[string]string{"index.php": strings.Replace(index, "$_POST['v']", "trim($_POST['v'])", 1), "other.php": "<?php class C { function m() { function trim($s) { global $db; $db = 1; } } }"}, 0},
		{"namespace", map[string]string{"index.php": strings.Replace(index, "<?php", "<?php\nnamespace App;", 1)}, 0},
		{"imported function", map[string]string{"index.php": strings.Replace(index, "<?php", "<?php\nuse function Vendor\\mysqli_real_escape_string;", 1)}, 0},
		{"imported function in a group", map[string]string{"index.php": strings.Replace(index, "<?php", "<?php\nuse Vendor\\{function mysqli_real_escape_string};", 1)}, 0},
		{"own hash in a namespace", map[string]string{"index.php": strings.Replace(phpFactConnect, "<?php", "<?php\nnamespace App;", 1) + `$v = md5($_POST['v']); ` + phpFactQuery}, 0},
		{"file too large to read", map[string]string{"index.php": index, "a.php": "<?php //" + strings.Repeat("x", 2<<20)}, 0},
		{"reference with a space", map[string]string{"index.php": index, "a.php": "<?php f($a, & $v);"}, 0},
		{"file that does not parse", map[string]string{"index.php": index + "if ("}, 0},
		{"reference in another file", map[string]string{"index.php": index, "other.php": "<?php foreach ($a as &$v) {}"}, 0},
	}
	for _, text := range []string{"set_error_handler('f');", "register_tick_function('f');", "pcntl_signal(1, 'f');", "pcntl_async_signals(true);", "extract($a, EXTR_REFS);", "echo $php_errormsg;",
		"class A { function __destruct() {} }", "class A { function __toString() { return ''; } }", "class A { function offsetGet($k) {} }", "class A { function offsetExists($k) {} }",
		"runkit7_function_redefine('md5', '', '');", "runkit_function_redefine('md5', '', '');", "uopz_set_return('md5', 1);", "$q = 'SET NAMES gbk';", "$q = 'set character set gbk';", "$q = 'SET CHARSET gbk';", "$q = \"SET\n SESSION names 'gbk'\";", "$q = 'SET char set gbk';", "$q = 'SET GLOBAL charset gbk';", "$q = 'SET LOCAL charset gbk';", "$q = 'SET @@session.names gbk';",
		"$q = 'SET @@session.sql_mode = 0';", "$q = 'NO_BACKSLASH_ESCAPES';", "$q = 'character_set_client';", "$q = 'SET collation_connection = gbk_bin';", "$q = 'SET/**/NAMES gbk';", "$q = \"SET\\tNAMES gbk\";", "$q = sprintf('SET %s gbk', 'NAMES');", "$q = 'SET ' . 'NAMES gbk';", "$q = 'init_connect';", "mysqli_options($db, MYSQLI_INIT_COMMAND, $x);"} {
		cases = append(cases, struct {
			name  string
			files map[string]string
			want  int
		}{text, map[string]string{"index.php": index, "a.php": "<?php " + text}, 0})
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			records, facts := phpSQLRecordFacts(t, c.files)
			if records == 0 || len(facts) != c.want {
				t.Fatalf("records %d, facts %q, want %d", records, facts, c.want)
			}
		})
	}
}

// TestPHPSQLFactReviewForms keeps the forms of an independent review that stated a
// fact a path did not prove. Each makes a record and states none.
func TestPHPSQLFactReviewForms(t *testing.T) {
	raw, err := os.ReadFile("testdata/sql-fact-review-forms.txt")
	if err != nil {
		t.Fatal(err)
	}
	forms := strings.Split("\n"+string(raw), "\n=== ")[1:]
	if len(forms) != 89 {
		t.Fatalf("%d forms", len(forms))
	}
	for _, form := range forms {
		name, body, _ := strings.Cut(form, "\n")
		t.Run(name, func(t *testing.T) {
			files := map[string]string{}
			for i, part := range strings.Split("\n"+body, "\n--- ") {
				file := "index.php"
				if i > 0 {
					file, part, _ = strings.Cut(part, "\n")
				}
				files[file] = strings.TrimPrefix(part, "\n")
			}
			records, facts := phpSQLRecordFacts(t, files)
			if records == 0 || len(facts) > 0 {
				t.Fatalf("records %d, facts %q", records, facts)
			}
		})
	}
}
