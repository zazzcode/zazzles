package parse

import "testing"

// Flow-semantics regressions from the independent PHP review. Each case pins
// a source-reviewed vulnerable flow (or near-miss guard) the bounded flow must
// keep visible; none of them may silently become safe or disappear.

// phpCommandProtections returns the command path protections recorded for the
// single command candidate of a one-file fixture.
func phpCommandProtections(t *testing.T, src string) []string {
	t.Helper()
	r := phpAnalyze(t, phpFixture(t, map[string]string{"index.php": src}), "")
	uses := phpUsesOfKind(r, "command_execution_candidate")
	if len(uses) != 1 {
		t.Fatalf("want one command candidate, got %d: %#v", len(uses), uses)
	}
	var out []string
	for _, p := range uses[0].Command.Paths {
		out = append(out, p.Protection)
	}
	return out
}

func phpHasProtection(list []string, want string) bool {
	for _, p := range list {
		if p == want {
			return true
		}
	}
	return false
}

func TestPHPFlowNestedBranchWriteSurvivesMerge(t *testing.T) {
	got := phpCommandProtections(t, `<?php
$cmd = 'ls';
if ($a) {
  if ($b) {
    $cmd = $_GET['c'];
  }
}
system($cmd);
`)
	if !phpHasProtection(got, "raw") {
		t.Fatalf("nested-branch request write was dropped at the outer merge: %v", got)
	}
}

func TestPHPFlowNestedHelperGlobalWriteSurvivesMerge(t *testing.T) {
	got := phpCommandProtections(t, `<?php
function load() { global $cmd; $cmd = $_GET['c']; }
$cmd = 'ls';
if ($a) { load(); }
system($cmd);
`)
	if !phpHasProtection(got, "raw") {
		t.Fatalf("helper global write inside a branch was dropped: %v", got)
	}
}

func TestPHPFlowNegatedTypeGuardIsNotProtection(t *testing.T) {
	got := phpCommandProtections(t, `<?php
$ip = $_GET['ip'];
if (!is_numeric($ip)) {
  system('ping ' . $ip);
}
`)
	if phpHasProtection(got, "constrained") || !phpHasProtection(got, "raw") {
		t.Fatalf("!is_numeric true branch must stay raw: %v", got)
	}
}

func TestPHPFlowDisjunctiveGuardIsNotProtection(t *testing.T) {
	got := phpCommandProtections(t, `<?php
$ip = $_GET['ip'];
if (is_numeric($ip) || $force) {
  system('ping ' . $ip);
}
`)
	if !phpHasProtection(got, "raw") {
		t.Fatalf("is_numeric(x) || other does not constrain x on the true branch: %v", got)
	}
}

// phpPathProtections returns the path flow protections of the single
// filesystem candidate of a one-file fixture.
func phpPathProtections(t *testing.T, src string) []string {
	t.Helper()
	r := phpAnalyze(t, phpFixture(t, map[string]string{"index.php": src}), "")
	uses := phpUsesOfKind(r, "path_traversal_candidate")
	if len(uses) != 1 {
		t.Fatalf("want one path candidate, got %d: %#v", len(uses), uses)
	}
	var out []string
	for _, p := range uses[0].Path.Paths {
		out = append(out, p.Protection)
	}
	return out
}

func TestPHPFlowConjunctiveRejectionIsNotProtection(t *testing.T) {
	// The fall-through of `if (!in_array(...) && $strict) exit;` admits
	// non-members whenever $strict is false.
	got := phpPathProtections(t, `<?php
$f = $_GET['f'];
if (!in_array($f, array('a', 'b')) && $strict) { exit; }
readfile($f);
`)
	if phpHasProtection(got, "guarded") || !phpHasProtection(got, "raw") {
		t.Fatalf("conjunctive rejection must not certify membership: %v", got)
	}
}

func TestPHPFlowDisjunctiveRejectionProtects(t *testing.T) {
	// Near-miss control: `if (!isset($f) || !in_array($f, [...])) die();`
	// leaves only members on the fall-through.
	got := phpPathProtections(t, `<?php
$f = $_GET['f'];
if (!isset($f) || !in_array($f, array('a', 'b'))) { die('no'); }
readfile($f);
`)
	if !phpHasProtection(got, "guarded") || phpHasProtection(got, "raw") {
		t.Fatalf("terminating disjunctive rejection should guard the fall-through: %v", got)
	}
}

func TestPHPFlowMembershipGuardScopedToItsValue(t *testing.T) {
	// Near-miss control: the allowlist checks $a, the sink reads $b.
	got := phpPathProtections(t, `<?php
$a = $_GET['a'];
$b = $_GET['b'];
if (!in_array($a, array('x', 'y'))) { exit; }
readfile($b);
`)
	if !phpHasProtection(got, "raw") || phpHasProtection(got, "guarded") {
		t.Fatalf("a guard on another value must not protect the sink operand: %v", got)
	}
}

func TestPHPFlowNegatedTypeGuardRejectionProtects(t *testing.T) {
	// Near-miss control: a terminating !is_numeric rejection does constrain
	// the fall-through, and must not protect the rejecting branch itself.
	got := phpCommandProtections(t, `<?php
$ip = $_GET['ip'];
if (!is_numeric($ip)) { die('bad'); }
system('ping ' . $ip);
`)
	if !phpHasProtection(got, "constrained") || phpHasProtection(got, "raw") {
		t.Fatalf("terminating !is_numeric rejection should constrain the fall-through: %v", got)
	}
}

func TestPHPFlowBuiltinNotShadowedBySameNamedVariable(t *testing.T) {
	r := phpAnalyze(t, phpFixture(t, map[string]string{"index.php": `<?php
$file = $_GET['f'];
$lines = file($file);
$system = $_GET['c'];
system($system);
`}), "")
	if len(phpUsesOfKind(r, "path_traversal_candidate")) != 1 {
		t.Fatalf("file($file) must stay a filesystem sink: %#v", r.Uses)
	}
	if len(phpUsesOfKind(r, "command_execution_candidate")) != 1 {
		t.Fatalf("system($system) must stay a command sink: %#v", r.Uses)
	}
}

func TestPHPFlowLoopBreakDoesNotEndEntry(t *testing.T) {
	got := phpCommandProtections(t, `<?php
while ($row = next_row()) {
  break;
}
system($_GET['c']);
`)
	if !phpHasProtection(got, "raw") {
		t.Fatalf("statements after a loop with break were treated as unreachable: %v", got)
	}
}

func TestPHPFlowLoopReturnDoesNotEndEntry(t *testing.T) {
	// A loop body may execute zero times, so its return never ends the path.
	got := phpCommandProtections(t, `<?php
foreach ($items as $item) {
  return;
}
system($_GET['c']);
`)
	if !phpHasProtection(got, "raw") {
		t.Fatalf("statements after a returning loop were treated as unreachable: %v", got)
	}
}

func TestPHPFlowMalformedCallsDoNotPanic(t *testing.T) {
	r := phpAnalyze(t, phpFixture(t, map[string]string{"index.php": `<?php
$a = trim();
$b = sprintf();
$db = new mysqli('h', 'u', 'p', 'd');
$db->query();
$db->prepare();
$p = new PDO('sqlite::memory:');
$p->query();
`}), "")
	if r == nil {
		t.Fatal("no report")
	}
}

func TestPHPFlowIncludeCycleTerminates(t *testing.T) {
	r := phpAnalyze(t, phpFixture(t, map[string]string{
		"a.php": "<?php\nrequire_once 'b.php';\nsystem($_GET['c']);\n",
		"b.php": "<?php\nrequire_once 'a.php';\n",
		"c.php": "<?php\ninclude 'c.php';\n",
	}), "")
	found := false
	for _, u := range phpUsesOfKind(r, "command_execution_candidate") {
		found = found || u.Sink.Span.File == "a.php"
	}
	if !found {
		t.Fatalf("a.php command candidate missing after include cycle: %#v", r.Uses)
	}
	limited := false
	for _, e := range r.Entries {
		for _, g := range e.Gaps {
			limited = limited || g.Kind == "work_limit"
		}
	}
	if !limited {
		t.Fatalf("include cycle must surface a work_limit gap: %#v", r.Entries)
	}
}

func TestPHPFlowDispatchAlternativeGapsReachEntry(t *testing.T) {
	r := phpAnalyze(t, phpFixture(t, map[string]string{
		"index.php": `<?php
switch ($level) {
  case 'low': $f = 'low.php'; break;
  default: $f = 'high.php'; break;
}
require_once "source/{$f}";
`,
		"source/low.php":  "<?php\ninclude $_GET['page'];\n",
		"source/high.php": "<?php\n$x = 1;\n",
	}), "index.php")
	found := false
	for _, e := range r.Entries {
		for _, g := range e.Gaps {
			found = found || (g.Kind == "php_dynamic_include" && g.At.File == "source/low.php")
		}
	}
	if !found {
		t.Fatalf("gaps recorded inside a dispatch alternative must reach the entry: %#v", r.Entries)
	}
}

func TestPHPFlowMysqliObjectQueryTextOperand(t *testing.T) {
	r := phpAnalyze(t, phpFixture(t, map[string]string{"index.php": `<?php
$db = new mysqli('h', 'u', 'p', 'd');
$db->query("SELECT * FROM t WHERE id = '" . $_GET['id'] . "'", MYSQLI_STORE_RESULT);
`}), "")
	uses := phpUsesOfKind(r, "sql_query_candidate")
	if len(uses) != 1 {
		t.Fatalf("want one SQL candidate: %#v", r.Uses)
	}
	text := uses[0].Completeness.Evidence["query_text"]
	if len(text) != 1 || text[0].Text == "MYSQLI_STORE_RESULT" {
		t.Fatalf("OO mysqli query text is argument 0, got %#v", text)
	}
}

func TestPHPFlowBracelessBodiesExecuteAsStatements(t *testing.T) {
	got := phpCommandProtections(t, `<?php
$cmd = 'ls';
if ($a) $cmd = $_GET['c']; else $cmd = 'pwd';
system($cmd);
`)
	if !phpHasProtection(got, "raw") {
		t.Fatalf("braceless branch assignment was dropped: %v", got)
	}
	path := phpPathProtections(t, `<?php
$f = $_GET['f'];
if (!in_array($f, array('a', 'b'))) exit;
readfile($f);
`)
	if !phpHasProtection(path, "guarded") || phpHasProtection(path, "raw") {
		t.Fatalf("braceless terminating rejection should guard the fall-through: %v", path)
	}
}

func TestPHPFlowElseIfChainWalksEveryAlternative(t *testing.T) {
	r := phpAnalyze(t, phpFixture(t, map[string]string{"index.php": `<?php
if ($a == 1) {
  $x = 'one';
} elseif ($a == 2) {
  echo $_GET['two'];
} else {
  system($_GET['three']);
}
`}), "")
	if len(phpUsesOfKind(r, "xss_candidate")) != 1 {
		t.Fatalf("elseif body echo must be a render sink: %#v", r.Uses)
	}
	if len(phpUsesOfKind(r, "command_execution_candidate")) != 1 {
		t.Fatalf("else after elseif must be walked: %#v", r.Uses)
	}
}

func TestPHPFlowElseOverwriteReplacesPriorValue(t *testing.T) {
	// php-goof tasks.php shape: both alternatives assign $query, so the
	// earlier request-derived $query must not reach the sink.
	r := phpAnalyze(t, phpFixture(t, map[string]string{"index.php": `<?php
$conn = mysqli_connect('h', 'u', 'p', 'd');
$query = "SELECT * FROM t WHERE id = " . $_GET['old'];
if (isset($_POST['edid'])) {
  $query = "UPDATE t SET a = 1 WHERE id = '" . $_POST['edid'] . "'";
}
else $query = "INSERT INTO t(a) VALUES (1)";
mysqli_query($conn, $query);
`}), "")
	for _, u := range phpUsesOfKind(r, "sql_query_candidate") {
		if u.Sink.Span.StartLine != 8 {
			continue
		}
		for _, d := range u.Dependencies {
			if d.Source.Text == "$_GET['old']" {
				t.Fatalf("overwritten value reached the sink: %#v", u.Dependencies)
			}
		}
		return
	}
	t.Fatalf("missing SQL candidate at line 8: %#v", r.Uses)
}

func TestPHPFlowPlainDoubleQuotedSQLIsLiteral(t *testing.T) {
	r := phpAnalyze(t, phpFixture(t, map[string]string{"index.php": `<?php
$conn = mysqli_connect('h', 'u', 'p', 'd');
$result = mysqli_query($conn, "SELECT * FROM task");
`}), "")
	if uses := phpUsesOfKind(r, "sql_query_candidate"); len(uses) != 0 {
		t.Fatalf("constant SQL text is not a candidate: %#v", uses)
	}
}

func TestPHPFlowWholeSuperglobalAndForeachBindings(t *testing.T) {
	r := phpAnalyze(t, phpFixture(t, map[string]string{"index.php": `<?php
eval(reset($_GET));
foreach ($_POST as $k => $v) {
  echo $v;
}
`}), "")
	if len(phpUsesOfKind(r, "code_execution_candidate")) != 1 {
		t.Fatalf("eval(reset($_GET)) must be a code candidate: %#v", r.Uses)
	}
	xss := phpUsesOfKind(r, "xss_candidate")
	if len(xss) != 1 || xss[0].XSS.Protection != "raw" {
		t.Fatalf("foreach value of $_POST must render raw: %#v", xss)
	}
}

func TestPHPFlowDispatchAlternativeNarrowsSelector(t *testing.T) {
	// DVWA xss_s/index.php shape: a braceless impossible-only append must not
	// reach the low alternative, and must reach the impossible one.
	r := phpAnalyze(t, phpFixture(t, map[string]string{
		"index.php": `<?php
$vulnerabilityFile = '';
switch ($level) {
  case 'low': $vulnerabilityFile = 'low.php'; break;
  default: $vulnerabilityFile = 'impossible.php'; break;
}
require_once "source/{$vulnerabilityFile}";
$body = 'page';
if ($vulnerabilityFile == 'impossible.php') $body .= $_GET['token'];
echo $body;
`,
		"source/low.php":        "<?php\n$x = 1;\n",
		"source/impossible.php": "<?php\n$y = 2;\n",
	}), "index.php")
	xss := phpUsesOfKind(r, "xss_candidate")
	if len(xss) != 1 {
		t.Fatalf("only the impossible alternative renders request content, got %d records: %#v", len(xss), xss)
	}
	found := false
	for _, e := range xss[0].Context {
		found = found || (e.Kind == "dispatch_condition" && e.Span.StartLine == 5)
	}
	if !found {
		t.Fatalf("rendered record must carry the impossible alternative's selecting condition: %#v", xss[0].Context)
	}
}

func TestPHPFlowLooseNumericComparisonStaysUndecided(t *testing.T) {
	// "1e1" == "10" is true in PHP; loose numeric comparison is not folded.
	got := phpCommandProtections(t, `<?php
$v = '1e1';
if ($v == '10') { system($_GET['c']); }
`)
	if !phpHasProtection(got, "raw") {
		t.Fatalf("loose numeric equality must not be decided: %v", got)
	}
}
