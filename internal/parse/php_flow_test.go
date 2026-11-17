package parse

import (
	"strings"
	"testing"
)

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
	if phpHasProtection(got, "guarded") || !phpHasProtection(got, "raw") {
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
	if !phpHasProtection(got, "guarded") || phpHasProtection(got, "raw") {
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

func TestPHPRenderOutputContextFromInlineHTML(t *testing.T) {
	// php-goof index.php shape: echo inside a quoted attribute value, and a
	// short echo tag inside an href.
	r := phpAnalyze(t, phpFixture(t, map[string]string{"index.php": `<form>
<input type="hidden" name="edid" value="<?php echo $_GET['edid']?>">
<a href="pdf.php?title=<?= $_GET['title'] ?>">pdf</a>
<p><?php echo $_GET['msg']; ?></p>
</form>
`}), "")
	got := map[int]string{}
	for _, u := range phpUsesOfKind(r, "xss_candidate") {
		got[u.Sink.Span.StartLine] = u.XSS.OutputContext + "/" + u.XSS.Protection
	}
	want := map[int]string{2: "html_attribute/raw", 3: "url/raw", 4: "html_text/raw"}
	for line, w := range want {
		if got[line] != w {
			t.Fatalf("line %d: got %q want %q (all %v)", line, got[line], w, got)
		}
	}
}

func TestPHPRenderShortEchoTagIsOutput(t *testing.T) {
	r := phpAnalyze(t, phpFixture(t, map[string]string{"index.php": "<p><?= $_GET['q'] ?></p>\n<p><?= htmlspecialchars($_GET['s']) ?></p>\n"}), "")
	byLine := map[int]string{}
	for _, u := range phpUsesOfKind(r, "xss_candidate") {
		byLine[u.Sink.Span.StartLine] = u.XSS.Protection
	}
	if byLine[1] != "raw" || byLine[2] != "encoded" {
		t.Fatalf("short echo tags must render with their own protection: %v", byLine)
	}
}

func TestPHPInterpolatedSelectRowsStayStoredValues(t *testing.T) {
	// php-goof func.php/index.php shape: the row of an interpolated SELECT
	// reaches an attribute; it must stay a stored-origin record.
	r := phpAnalyze(t, phpFixture(t, map[string]string{"index.php": `<?php
$conn = mysqli_connect('h', 'u', 'p', 'd');
$id = $_GET['edid'];
$result = mysqli_query($conn, "SELECT * FROM task where id = $id");
$row = mysqli_fetch_array($result);
$title = $row['title'];
?>
<input value="<?php echo $title; ?>">
`}), "")
	xss := phpUsesOfKind(r, "xss_candidate")
	if len(xss) != 1 || xss[0].XSS.Type != "stored" || xss[0].XSS.StorageKey != "php-sql:task.title" {
		t.Fatalf("row of an interpolated SELECT must render as a stored value: %#v", xss)
	}
}

func TestPHPStoredWritesSurviveJoinedInsertUpdate(t *testing.T) {
	// php-goof tasks.php shape: the executed query is a join of an UPDATE and
	// an INSERT alternative; both writes to task.title must link to the read.
	r := phpAnalyze(t, phpFixture(t, map[string]string{
		"tasks.php": `<?php
$conn = mysqli_connect('h', 'u', 'p', 'd');
$title = urlencode($_POST['title']);
if (isset($_POST['edid'])) {
  $edid = $_POST['edid'];
  $query = "UPDATE task SET title = '$title' WHERE id = '$edid'";
}
else $query = "INSERT INTO task(title) VALUES ('$title')";
mysqli_query($conn, $query);
`,
		"index.php": `<?php
$conn = mysqli_connect('h', 'u', 'p', 'd');
$result = mysqli_query($conn, "SELECT * FROM task");
$row = mysqli_fetch_array($result);
echo $row['title'];
`}), "")
	for _, u := range phpUsesOfKind(r, "xss_candidate") {
		if u.XSS.StorageKey != "php-sql:task.title" {
			continue
		}
		if !u.XSS.OriginResolved || len(u.XSS.Paths) != 2 {
			t.Fatalf("UPDATE and INSERT writes must both link: resolved=%v paths=%#v", u.XSS.OriginResolved, u.XSS.Paths)
		}
		return
	}
	t.Fatalf("missing stored task.title render: %#v", r.Uses)
}

func TestPHPURLEncodeProtectsOnlyMarkupContexts(t *testing.T) {
	r := phpAnalyze(t, phpFixture(t, map[string]string{"index.php": `<a href="x?q=<?php echo urlencode($_GET['q']); ?>">x</a>
<script>var q = <?php echo urlencode($_GET['s']); ?>;</script>
<p><?php echo urldecode(urlencode($_GET['d'])); ?></p>
`}), "")
	got := map[int]string{}
	for _, u := range phpUsesOfKind(r, "xss_candidate") {
		got[u.Sink.Span.StartLine] = u.XSS.Protection
	}
	if got[1] != "encoded" || got[2] != "unknown" || got[3] == "encoded" {
		t.Fatalf("urlencode protects url/attribute/text only, never script or after urldecode: %v", got)
	}
}

func TestPHPFlowDispatchAlternativeGapsStayInTheirAlternative(t *testing.T) {
	// The low alternative's loop gap must not become a blocker of the
	// high alternative's SQL claim.
	r := phpAnalyze(t, phpFixture(t, map[string]string{
		"index.php": `<?php
$f = '';
switch ($level) {
  case 'low': $f = 'low.php'; break;
  default: $f = 'high.php'; break;
}
require_once "source/{$f}";
`,
		"source/low.php":  "<?php\nwhile ($x) { $y = 1; }\n",
		"source/high.php": "<?php\n$conn = mysqli_connect('h', 'u', 'p', 'd');\nmysqli_query($conn, \"SELECT * FROM t WHERE id = '\" . $_GET['id'] . \"'\");\n",
	}), "index.php")
	for _, u := range phpUsesOfKind(r, "sql_query_candidate") {
		for _, g := range u.Completeness.Blockers {
			if g.Kind == "php_loop_unresolved" {
				t.Fatalf("sibling alternative gap leaked into the claim: %#v", u.Completeness.Blockers)
			}
		}
	}
	found := false
	for _, e := range r.Entries {
		for _, g := range e.Gaps {
			found = found || g.Kind == "php_loop_unresolved"
		}
	}
	if !found {
		t.Fatalf("alternative gaps must still reach the entry: %#v", r.Entries)
	}
}

func TestPHPSessionReadLinksWritesFromAnyEntry(t *testing.T) {
	// The writer entry sorts after the reader; the session link is made once
	// every entry was analyzed.
	r := phpAnalyze(t, phpFixture(t, map[string]string{
		"a_read.php":  "<?php\necho $_SESSION['msg'];\n",
		"b_write.php": "<?php\n$_SESSION['msg'] = $_POST['m'];\n",
	}), "")
	xss := phpUsesOfKind(r, "xss_candidate")
	if len(xss) != 1 || !xss[0].XSS.OriginResolved || xss[0].XSS.Protection != "raw" || len(xss[0].XSS.RelatedEntries) != 1 {
		t.Fatalf("session read must link the request write of another entry: %#v", xss)
	}
}

func TestPHPDirectRawWitnessSurvivesUnresolvedStoredSibling(t *testing.T) {
	// DVWA sqli page shape: the reflected id and an unwritten DB column are
	// rendered together; the raw reflected path stays a reflected claim.
	r := phpAnalyze(t, phpFixture(t, map[string]string{"index.php": `<?php
$conn = mysqli_connect('h', 'u', 'p', 'd');
$id = $_GET['id'];
$result = mysqli_query($conn, "SELECT first_name FROM users");
$row = mysqli_fetch_assoc($result);
echo "ID: {$id} First: {$row['first_name']}";
`}), "")
	xss := phpUsesOfKind(r, "xss_candidate")
	if len(xss) != 1 || xss[0].XSS.Type != "reflected" || xss[0].XSS.OriginResolved || xss[0].XSS.StorageKey != "php-sql:users.first_name" {
		t.Fatalf("raw reflected witness with an unresolved stored sibling: %#v", xss)
	}
}

func TestPHPServerGeneratedSessionRenderIsNotACandidate(t *testing.T) {
	r := phpAnalyze(t, phpFixture(t, map[string]string{
		"index.php": "<?php\n$_SESSION['token'] = md5(uniqid());\necho \"<input value='{$_SESSION['token']}'>\";\n",
	}), "")
	if xss := phpUsesOfKind(r, "xss_candidate"); len(xss) != 0 {
		t.Fatalf("a server-generated session value is not request content: %#v", xss)
	}
}

func TestPHPShellDenylistLeavingMetacharactersStaysRaw(t *testing.T) {
	// DVWA exec medium/high shapes: neither deny-list removes a bare `|`.
	medium := phpCommandProtections(t, `<?php
$target = $_REQUEST['ip'];
$substitutions = array('&&' => '', ';' => '');
$target = str_replace(array_keys($substitutions), $substitutions, $target);
shell_exec('ping -c 4 ' . $target);
`)
	high := phpCommandProtections(t, "<?php\n"+
		"$target = trim($_REQUEST['ip']);\n"+
		"$substitutions = array('||' => '', '&' => '', ';' => '', '| ' => '', '-' => '', '$' => '', '(' => '', ')' => '', '`' => '');\n"+
		"$target = str_replace(array_keys($substitutions), $substitutions, $target);\n"+
		"shell_exec('ping -c 4 ' . $target);\n")
	if !phpHasProtection(medium, "raw") || !phpHasProtection(high, "raw") {
		t.Fatalf("incomplete shell deny-lists stay raw: medium %v high %v", medium, high)
	}
	complete := phpCommandProtections(t, "<?php\n"+
		"$t = str_replace(array(';', '&', '|', '`', '$', '(', ')', '<', '>', \"\\n\"), '', $_GET['ip']);\n"+
		"shell_exec('ping ' . $t);\n")
	if phpHasProtection(complete, "raw") {
		t.Fatalf("a deny-list removing every metacharacter is not raw: %v", complete)
	}
	r := phpAnalyze(t, phpFixture(t, map[string]string{"index.php": `<?php
$t = str_replace(array(';'), '', $_GET['q']);
echo $t;
`}), "")
	if xss := phpUsesOfKind(r, "xss_candidate"); len(xss) != 1 || xss[0].XSS.Protection != "unknown" {
		t.Fatalf("the shell deny-list label must stay unknown outside command sinks: %#v", xss)
	}
}

func TestPHPElementTypeGuardsConstrainReassembledValue(t *testing.T) {
	// DVWA exec impossible shape: every octet is checked before reassembly.
	got := phpCommandProtections(t, `<?php
$octet = explode('.', $_REQUEST['ip']);
if (is_numeric($octet[0]) && is_numeric($octet[1]) && sizeof($octet) == 2) {
  $target = $octet[0] . '.' . $octet[1];
  shell_exec('ping ' . $target);
}
`)
	if phpHasProtection(got, "raw") || phpHasProtection(got, "unknown") {
		t.Fatalf("checked octets are constrained: %v", got)
	}
	// Near-miss: an unchecked element stays raw.
	miss := phpCommandProtections(t, `<?php
$octet = explode('.', $_REQUEST['ip']);
if (is_numeric($octet[0])) {
  shell_exec('ping ' . $octet[0] . '.' . $octet[1]);
}
`)
	if !phpHasProtection(miss, "raw") {
		t.Fatalf("an unchecked element must stay raw: %v", miss)
	}
}

func TestPHPFlowConstantsAndEntryRelativeIncludes(t *testing.T) {
	// DVWA shape: the entry defines the root prefix, an included helper uses
	// it to include config relative to the entry's working directory. Another
	// file (sorting first) defines the same constant differently.
	r := phpAnalyze(t, phpFixture(t, map[string]string{
		"about.php":                   "<?php\ndefine('ROOT', '');\n",
		"config/config.php":           "<?php\n$cfg = array();\n$cfg['cmd'] = $_GET['c'];\n",
		"inc/page.php":                "<?php\nrequire_once ROOT . 'config/config.php';\n",
		"vulnerabilities/x/index.php": "<?php\ndefine('ROOT', '../../');\nrequire_once ROOT . 'inc/page.php';\nsystem($cfg['cmd']);\n",
	}), "vulnerabilities/x/index.php")
	if len(phpUsesOfKind(r, "command_execution_candidate")) != 1 {
		t.Fatalf("config composed through the entry's constant must reach the sink: %#v %#v", r.Uses, r.Entries)
	}
}

func TestPHPFlowDirConstantInclude(t *testing.T) {
	r := phpAnalyze(t, phpFixture(t, map[string]string{
		"app/index.php": "<?php\nrequire __DIR__ . '/lib.php';\nrequire dirname(__FILE__) . '/lib2.php';\nsystem($a . $b);\n",
		"app/lib.php":   "<?php\n$a = $_GET['a'];\n",
		"app/lib2.php":  "<?php\n$b = $_GET['b'];\n",
	}), "app/index.php")
	uses := phpUsesOfKind(r, "command_execution_candidate")
	if len(uses) != 1 || len(uses[0].Dependencies) != 2 {
		t.Fatalf("__DIR__ and dirname(__FILE__) includes must compose: %#v", uses)
	}
}

func TestPHPFlowReferenceAssignment(t *testing.T) {
	got := phpCommandProtections(t, `<?php
function &grab() { return $_GET['c']; }
$c =& grab();
system($c);
`)
	if !phpHasProtection(got, "raw") {
		t.Fatalf("`$x =& f()` must assign: %v", got)
	}
}

func TestPHPRenderSuppliesMarkupContextEvidence(t *testing.T) {
	r := phpAnalyze(t, phpFixture(t, map[string]string{"index.php": `<form>
<input type="hidden" name="edid" value="<?php echo $_GET['edid']?>">
</form>
`}), "")
	xss := phpUsesOfKind(r, "xss_candidate")
	if len(xss) != 1 {
		t.Fatalf("want one record: %#v", xss)
	}
	for _, e := range xss[0].Completeness.Evidence["render_context"] {
		if e.Kind == "render_markup_context" && strings.Contains(e.Text, `value="`) {
			return
		}
	}
	t.Fatalf("render_context must carry the surrounding markup: %#v", xss[0].Completeness.Evidence["render_context"])
}

func TestPHPGuardedFactsSatisfySharedContracts(t *testing.T) {
	// Every guarded PHP path must validate against the shared fact contracts
	// (raw/guarded/unknown with cited controls); invalid facts can never be
	// judged Protected.
	r := phpAnalyze(t, phpFixture(t, map[string]string{"index.php": `<?php
shell_exec('ping ' . escapeshellarg($_GET['h']));
shell_exec('ping ' . intval($_GET['n']));
eval('return ' . intval($_GET['e']) . ';');
header('Location: /item.php?id=' . intval($_GET['r']));
readfile('/srv/' . basename($_GET['f']));
`}), "")
	guarded := 0
	for _, u := range r.Uses {
		var err error
		var protections []string
		switch {
		case u.Command != nil:
			err = u.Command.Validate(len(u.Dependencies), len(u.Context))
			for _, p := range u.Command.Paths {
				protections = append(protections, p.Protection)
			}
		case u.Code != nil:
			err = u.Code.Validate(len(u.Dependencies), len(u.Context))
			for _, p := range u.Code.Paths {
				protections = append(protections, p.Protection)
			}
		case u.Redirect != nil:
			err = u.Redirect.Validate(len(u.Dependencies), len(u.Context))
			for _, p := range u.Redirect.Paths {
				protections = append(protections, p.Protection)
			}
		case u.Path != nil:
			err = u.Path.Validate(len(u.Dependencies), len(u.Context))
			for _, p := range u.Path.Paths {
				protections = append(protections, p.Protection)
			}
		default:
			continue
		}
		if err != nil {
			t.Fatalf("%s %d: shared facts contract rejects the record: %v", u.Kind, u.Sink.Span.StartLine, err)
		}
		if phpHasProtection(protections, "guarded") {
			guarded++
		}
	}
	if guarded != 5 {
		t.Fatalf("want five guarded records, got %d: %#v", guarded, r.Uses)
	}
}

func TestPHPStoredOnlyInjectionStaysReview(t *testing.T) {
	// DVWA csrf/captcha shape: the request password is md5-hashed and the
	// only content is a session value with no request-linked writer.
	r := phpAnalyze(t, phpFixture(t, map[string]string{"index.php": `<?php
$conn = mysqli_connect('h', 'u', 'p', 'd');
$_SESSION['dvwa'] = array();
$pass = md5($_GET['password_new']);
$user = $_SESSION['dvwa'];
mysqli_query($conn, "UPDATE users SET password = '$pass' WHERE user = '$user'");
`}), "")
	uses := phpUsesOfKind(r, "sql_query_candidate")
	if len(uses) != 1 {
		t.Fatalf("want one SQL record: %#v", uses)
	}
	blocked := false
	for _, g := range uses[0].Completeness.Blockers {
		blocked = blocked || g.Kind == "storage_origin_unresolved"
	}
	if !blocked {
		t.Fatalf("stored-only content must stay Review: %#v", uses[0].Completeness.Blockers)
	}
	// Near-miss: a request-linked session write is a request path.
	r = phpAnalyze(t, phpFixture(t, map[string]string{"index.php": `<?php
$conn = mysqli_connect('h', 'u', 'p', 'd');
$_SESSION['id'] = $_POST['id'];
$id = $_SESSION['id'];
mysqli_query($conn, "SELECT * FROM users WHERE id = '$id'");
`}), "")
	for _, u := range phpUsesOfKind(r, "sql_query_candidate") {
		for _, g := range u.Completeness.Blockers {
			if g.Kind == "storage_origin_unresolved" {
				t.Fatalf("a request-linked session write must not be stored-only: %#v", u.Completeness.Blockers)
			}
		}
	}
}

func TestPHPStoredOnlySQLLinksLaterSessionWriter(t *testing.T) {
	// DVWA sqli high shape: the reader entry sorts before the entry that
	// writes the session id from the request.
	r := phpAnalyze(t, phpFixture(t, map[string]string{
		"a_high.php":          "<?php\n$conn = mysqli_connect('h', 'u', 'p', 'd');\n$id = $_SESSION['id'];\nmysqli_query($conn, \"SELECT * FROM users WHERE id = '$id'\");\n",
		"b_session_input.php": "<?php\n$_SESSION['id'] = $_POST['id'];\n",
	}), "")
	uses := phpUsesOfKind(r, "sql_query_candidate")
	if len(uses) != 1 {
		t.Fatalf("want one SQL record: %#v", uses)
	}
	for _, g := range uses[0].Completeness.Blockers {
		if g.Kind == "storage_origin_unresolved" {
			t.Fatalf("a later request-derived session writer must resolve the claim: %#v", uses[0].Completeness.Blockers)
		}
	}
	found := false
	for _, d := range uses[0].Dependencies {
		found = found || d.Source.Text == "$_POST['id']"
	}
	if !found {
		t.Fatalf("the writer's request source must join the claim: %#v", uses[0].Dependencies)
	}
}

func TestPHPStoredOnlyRuleIgnoresBoundParameters(t *testing.T) {
	// DVWA csrf impossible shape: the session user is a bound parameter.
	r := phpAnalyze(t, phpFixture(t, map[string]string{"index.php": `<?php
$db = new PDO('sqlite::memory:');
$_SESSION['dvwa'] = array();
$user = $_SESSION['dvwa'];
$stmt = $db->prepare('UPDATE users SET password = (:password) WHERE user = (:user);');
$stmt->bindParam(':user', $user);
$stmt->execute();
`}), "")
	for _, u := range phpUsesOfKind(r, "sql_query_candidate") {
		for _, g := range u.Completeness.Blockers {
			if g.Kind == "storage_origin_unresolved" {
				t.Fatalf("a bound stored value must not block a protection judgment: %#v", u.Completeness.Blockers)
			}
		}
	}
}

func TestPHPXSSTypeNamesTheRawWitness(t *testing.T) {
	// DVWA page shape: a raw cookie and an encoded, resolved stored value
	// render together; the witness is reflected.
	r := phpAnalyze(t, phpFixture(t, map[string]string{
		"write.php": "<?php\n$conn = mysqli_connect('h', 'u', 'p', 'd');\n$c = htmlspecialchars($_POST['c']);\nmysqli_query($conn, \"INSERT INTO notes (body) VALUES ('$c')\");\n",
		"read.php":  "<?php\n$conn = mysqli_connect('h', 'u', 'p', 'd');\n$row = mysqli_fetch_assoc(mysqli_query($conn, \"SELECT body FROM notes\"));\necho \"<body class='\" . $_COOKIE['theme'] . \"'>\" . $row['body'];\n",
	}), "")
	for _, u := range phpUsesOfKind(r, "xss_candidate") {
		if u.Sink.Span.File != "read.php" {
			continue
		}
		if u.XSS.Type != "reflected" || u.XSS.StorageKey != "php-sql:notes.body" || !u.XSS.OriginResolved {
			t.Fatalf("direct raw witness with an encoded stored sibling is reflected: %#v", u.XSS)
		}
		return
	}
	t.Fatalf("missing read.php render: %#v", r.Uses)
}
