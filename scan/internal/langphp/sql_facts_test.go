package langphp

import (
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/guidelines"
)

// TestPHPSQLFacts states the facts of constructed SQL operands. A fact is stated
// only when every path proves it and nothing later can change the text.
func TestPHPSQLFacts(t *testing.T) {
	const connect = "<?php\n$db = mysqli_connect('h', 'u', 'p', 'd');\n"
	esc := func(key string) string { return `mysqli_real_escape_string($db, $_POST["` + key + `"])` }
	cases := []struct {
		name, body string
		want       []string
	}{
		{"int cast", `$n = (int) $_POST["q"]; mysqli_query($db, "SELECT a FROM t WHERE id = $n");`, []string{"numeric_conversion_result: $n"}},
		{"intval concatenated", `$n = intval($_GET["p"]); mysqli_query($db, "SELECT a FROM t LIMIT " . $n);`, []string{"numeric_conversion_result: $n"}},
		{"escaped in single quotes", `$v = ` + esc("v") + `; mysqli_query($db, "SELECT a FROM t WHERE b = '$v'");`, []string{"escaped_in_quoted_literal: $v"}},
		{"escaped in double quotes", `$v = ` + esc("v") + `; mysqli_query($db, "SELECT a FROM t WHERE b = \"$v\"");`, []string{"escaped_in_quoted_literal: $v"}},
		{"escaped and appended", `$v = ` + esc("v") + `; $q = "SELECT a FROM t WHERE b = '"; $q .= $v . "'"; mysqli_query($db, $q);`, []string{"escaped_in_quoted_literal: $v"}},
		{"escaped ternary", `$v = isset($db) ? ` + esc("v") + ` : ""; mysqli_query($db, "SELECT a FROM t WHERE b = '$v'");`, []string{"escaped_in_quoted_literal: $v"}},
		{"trimmed before the escape", `$v = mysqli_real_escape_string($db, trim($_POST["v"])); mysqli_query($db, "SELECT a FROM t WHERE b = '$v'");`, []string{"escaped_in_quoted_literal: $v"}},
		{"two operands", `$n = (int) $_POST["n"]; $v = ` + esc("v") + `; mysqli_query($db, "SELECT a FROM t WHERE id = $n AND b = '$v'");`, []string{"numeric_conversion_result: $n", "escaped_in_quoted_literal: $v"}},
		{"hash", `$h = md5($_POST["p"]); mysqli_query($db, "SELECT a FROM t WHERE b = '$h'");`, []string{"hash_hex_result: $h"}},

		{"raw", `$v = $_POST["v"]; mysqli_query($db, "SELECT a FROM t WHERE b = '$v'");`, nil},
		{"escaped, not quoted", `$v = ` + esc("v") + `; mysqli_query($db, "SELECT a FROM t WHERE id = $v");`, nil},
		{"escaped after a closed literal", `$v = ` + esc("v") + `; mysqli_query($db, "SELECT a FROM t WHERE b = 'x' AND id = $v");`, nil},
		{"escaped identifier", "$v = " + esc("v") + "; mysqli_query($db, \"SELECT a FROM t ORDER BY `$v`\");", nil},
		{"escape undone", `$v = stripslashes(` + esc("v") + `); mysqli_query($db, "SELECT a FROM t WHERE b = '$v'");`, nil},
		{"escape then cut", `$v = substr(` + esc("v") + `, 0, 9); mysqli_query($db, "SELECT a FROM t WHERE b = '$v'");`, nil},
		{"raw ternary branch", `$v = isset($_GET["s"]) ? ` + esc("v") + ` : $_POST["v"]; mysqli_query($db, "SELECT a FROM t WHERE b = '$v'");`, nil},
		{"cast of another variable", `$raw = $_GET["id"]; $n = (int) $raw; mysqli_query($db, "SELECT a FROM t WHERE id = " . $raw);`, nil},
		{"check that does not stop", `$v = $_GET["id"]; if (!is_numeric($v)) { error_log("x"); } mysqli_query($db, "SELECT a FROM t WHERE id = $v");`, nil},
		{"binary hash", `$h = md5($_POST["p"], true); mysqli_query($db, "SELECT a FROM t WHERE b = '$h'");`, nil},
		{"one operand raw first", `$a = $_POST["a"]; $v = ` + esc("v") + `; mysqli_query($db, "SELECT a FROM t WHERE b = '$a' AND c = '$v'");`, nil},
		{"one operand raw last", `$v = ` + esc("v") + `; $b = $_POST["b"]; mysqli_query($db, "SELECT a FROM t WHERE c = '$v' AND b = '$b'");`, nil},
		{"escaped then raw appended", `$v = ` + esc("v") + `; $v .= $_POST["z"]; mysqli_query($db, "SELECT a FROM t WHERE b = '$v'");`, nil},
		{"escaped then unresolved appended", `$v = ` + esc("v") + `; $v .= mystery(); mysqli_query($db, "SELECT a FROM t WHERE b = '$v'");`, nil},
		{"unresolved ternary branch", `$v = $x ? ` + esc("v") + ` : mystery(); mysqli_query($db, "SELECT a FROM t WHERE b = '$v'");`, nil},
		{"unresolved if branch", `$v = ` + esc("v") + `; if ($x) { $v = mystery(); } mysqli_query($db, "SELECT a FROM t WHERE b = '$v'");`, nil},
		{"unresolved write through a copy", `$w = ` + esc("v") + `; if ($x) { $w = mystery(); } $v = $w; mysqli_query($db, "SELECT a FROM t WHERE b = '$v'");`, nil},
		{"number replaced in a branch", `$n = (int) $_GET["n"]; if ($x) { $n = mystery(); } mysqli_query($db, "SELECT a FROM t WHERE id = $n");`, nil},
		{"undone in a loop", `$v = ` + esc("v") + `; for ($i = 0; $i < 2; $i++) { $v = stripslashes($v); } mysqli_query($db, "SELECT a FROM t WHERE b = '$v'");`, nil},
		{"quote in a comment", `$v = ` + esc("v") + `; mysqli_query($db, "SELECT a FROM t /* it's */ WHERE id = $v");`, nil},
		{"quote in a line comment", `$v = ` + esc("v") + `; mysqli_query($db, "SELECT a FROM t -- it's\n WHERE id = $v");`, nil},
		{"quoted once, bare once", `$v = ` + esc("v") + `; mysqli_query($db, "SELECT a FROM t WHERE b = '$v' AND id = $v");`, nil},
		{"own function of the same name", `function mysqli_real_escape_string($a, $b) { return $b; } $v = ` + esc("v") + `; mysqli_query($db, "SELECT a FROM t WHERE b = '$v'");`, nil},
		{"pattern literal", `$v = ` + esc("v") + `; mysqli_query($db, "SELECT a FROM t WHERE b LIKE '%$v%'");`, []string{"escaped_in_quoted_literal: $v"}},
		{"nested literal branches", `$v = isset($db) ? ` + esc("v") + ` : (trigger_error("x") ? "" : ""); mysqli_query($db, "SELECT a FROM t WHERE b = '$v'");`, []string{"escaped_in_quoted_literal: $v"}},
		{"straight-line rewrite", `$v = $_POST["v"]; $v = stripslashes($v); $v = mysqli_real_escape_string($db, $v); mysqli_query($db, "SELECT a FROM t WHERE b = '$v'");`, []string{"escaped_in_quoted_literal: $v"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := phpAnalyze(t, phpFixture(t, map[string]string{"index.php": connect + c.body + "\n"}), "index.php")
			uses := phpUsesOfKind(r, "sql_query_candidate")
			if len(uses) != 1 || uses[0].Completeness == nil {
				t.Fatalf("records: %d", len(uses))
			}
			got := uses[0].Completeness.ModelFacts
			if len(got) != len(c.want) {
				t.Fatalf("facts %q, want %q", got, c.want)
			}
			for i, fact := range got {
				if !strings.HasPrefix(fact, c.want[i]+" ") {
					t.Errorf("fact %q, want %q", fact, c.want[i])
				}
				if code, ok := guidelines.FactCode(fact); !ok || !guidelines.KnownFact(code) {
					t.Errorf("fact %q has no note", fact)
				}
			}
		})
	}
}
