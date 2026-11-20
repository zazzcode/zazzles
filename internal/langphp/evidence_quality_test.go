package langphp

import (
	"strings"
	"testing"
)

// TestPHPPreparedStatementProvenance (judge evidence quality P): the claim on
// execute() of a prepared statement carries the prepare call that makes the
// query text the statement, including the variable it is assigned to, in its
// query_text role and its context. Without it the request shows a literal, a
// bindParam call and execute() with nothing linking them.
func TestPHPPreparedStatementProvenance(t *testing.T) {
	for name, src := range map[string]string{
		"pdo":           `<?php $db = new PDO('sqlite:x'); $user = $_POST['u']; $data = $db->prepare( 'UPDATE users SET n = 0 WHERE user = (:user) LIMIT 1;' ); $data->bindParam( ':user', $user, PDO::PARAM_STR ); $data->execute();`,
		"pdo bindValue": `<?php $db = new PDO('sqlite:x'); $q = $_GET['q']; $s = $db->prepare( 'SELECT a FROM t WHERE b = :b' ); $s->bindValue( ':b', $q, PDO::PARAM_STR ); $s->execute();`,
	} {
		t.Run(name, func(t *testing.T) {
			r := phpAnalyze(t, phpFixture(t, map[string]string{"index.php": src}), "index.php")
			var executed bool
			for _, u := range phpUsesOfKind(r, "sql_query_candidate") {
				if !strings.Contains(u.Sink.Text, "execute") {
					continue
				}
				executed = true
				found := false
				for _, e := range u.Completeness.Evidence["query_text"] {
					found = found || e.Kind == "statement_preparation" && strings.Contains(e.Text, "->prepare(") && strings.HasPrefix(strings.TrimSpace(e.Text), "$")
				}
				inContext := false
				for _, e := range u.Context {
					inContext = inContext || e.Kind == "statement_preparation"
				}
				if !found || !inContext {
					t.Fatalf("execute claim lacks the prepare assignment: query_text %#v", u.Completeness.Evidence["query_text"])
				}
			}
			if !executed {
				t.Fatalf("no execute claim: %#v", r.Uses)
			}
		})
	}
}

// TestPHPXSSPathOutputContext (judge evidence quality O): each XSS path states
// the HTML context at the place its value lands in the constructed output,
// including values built into markup inside a helper before they are echoed.
// The record states the context its raw paths share, else the echo-level
// context as before.
func TestPHPXSSPathOutputContext(t *testing.T) {
	src := `<?php
function theme() { if (isset($_COOKIE['theme'])) { return $_COOKIE['theme']; } return 'light'; }
function button($s) { return "<input type=\"button\" data-url='" . ROOT . "view.php?security={$s}' />"; }
$a = $_GET['a'];
$b = $_GET['b'];
$html = button($_COOKIE['security']);
echo "<html><body class=\"home " . theme() . "\">" . $html . "<p>{$a}</p><a href=\"" . $b . "\">x</a></body></html>";
`
	r := phpAnalyze(t, phpFixture(t, map[string]string{"index.php": src}), "index.php")
	uses := phpUsesOfKind(r, "xss_candidate")
	if len(uses) != 1 {
		t.Fatalf("xss uses: %d", len(uses))
	}
	u := uses[0]
	want := map[string]string{"$_COOKIE['theme']": "html_attribute", "$_COOKIE['security']": "html_attribute", "$_GET['a']": "html_text", "$_GET['b']": "url"}
	got := map[string]string{}
	for _, p := range u.XSS.Paths {
		got[u.Dependencies[p.Dependency].Source.Text] = p.OutputContext
	}
	for source, context := range want {
		if got[source] != context {
			t.Errorf("%s: path context %q, want %q (all %v)", source, got[source], context, got)
		}
	}
	if u.XSS.OutputContext != "html_text" {
		t.Errorf("mixed raw paths: record context %q, want the echo-level html_text", u.XSS.OutputContext)
	}
	shared := phpUsesOfKind(phpAnalyze(t, phpFixture(t, map[string]string{"index.php": `<?php echo "<body class=\"" . $_COOKIE['theme'] . "\">";`}), "index.php"), "xss_candidate")
	if len(shared) != 1 || shared[0].XSS.OutputContext != "html_attribute" {
		t.Errorf("one raw path in an attribute: %+v", shared)
	}
	for name, page := range map[string]string{"text": `<p><?php echo $_GET['x']; ?></p>`, "attribute": `<input value="<?php echo $_GET['x']; ?>">`} {
		r := phpAnalyze(t, phpFixture(t, map[string]string{"index.php": page}), "index.php")
		u := phpUsesOfKind(r, "xss_candidate")
		want := map[string]string{"text": "html_text", "attribute": "html_attribute"}[name]
		if len(u) != 1 || u[0].XSS.OutputContext != want || u[0].XSS.Paths[0].OutputContext != want {
			t.Errorf("%s: inline echo context changed: %+v", name, u)
		}
	}
}

// TestPHPNestedConcatenationTransfers (judge evidence quality T): a value in a
// left-nested concatenation records one string_construction transfer, the
// innermost one that shows where it lands, not one per enclosing level that
// repeats the template from its start.
func TestPHPNestedConcatenationTransfers(t *testing.T) {
	r := phpAnalyze(t, phpFixture(t, map[string]string{"index.php": `<?php $x = $_GET['x']; echo "<p class=\"" . $x . "\">" . "a" . "b" . "c";`}), "index.php")
	uses := phpUsesOfKind(r, "xss_candidate")
	if len(uses) != 1 || len(uses[0].Dependencies) != 1 {
		t.Fatalf("uses: %+v", uses)
	}
	var built []string
	for _, e := range uses[0].Dependencies[0].Transfers {
		if e.Kind == "string_construction" {
			built = append(built, e.Text)
		}
	}
	if len(built) != 1 || built[0] != `"<p class=\"" . $x` {
		t.Fatalf("string_construction transfers: %q", built)
	}
}

// TestPHPSuperglobalElementState (judge evidence quality V): a request
// superglobal element that page-level code checks against an allow-list and
// resets when invalid is no longer raw input where a helper reads it later;
// an element nothing checks stays raw, and a written literal carries no input.
func TestPHPSuperglobalElementState(t *testing.T) {
	src := `<?php
$levels = array('low', 'medium', 'high', 'impossible');
function levelSet($l) { $_COOKIE['security'] = $l; }
function levelGet() { if (isset($_COOKIE['security'])) { return $_COOKIE['security']; } return 'impossible'; }
function themeGet() { if (isset($_COOKIE['theme'])) { return $_COOKIE['theme']; } return 'light'; }
if (!isset($_COOKIE['security']) || !in_array($_COOKIE['security'], $levels)) {
	levelSet('impossible');
}
echo "<body class=\"" . themeGet() . "\"><a data-level='" . levelGet() . "'>x</a>";
`
	r := phpAnalyze(t, phpFixture(t, map[string]string{"index.php": src}), "index.php")
	uses := phpUsesOfKind(r, "xss_candidate")
	if len(uses) != 1 {
		t.Fatalf("xss uses: %d", len(uses))
	}
	got := map[string][]string{}
	for _, p := range uses[0].XSS.Paths {
		s := uses[0].Dependencies[p.Dependency].Source.Text
		got[s] = append(got[s], p.Protection)
	}
	for source, protections := range got {
		for _, p := range protections {
			if strings.Contains(source, "security") && p == "raw" {
				t.Errorf("allow-listed and reset cookie still raw: %v", got)
			}
		}
	}
	theme := got["$_COOKIE['theme']"]
	if len(theme) != 1 || theme[0] != "raw" {
		t.Errorf("unchecked cookie: %v", got)
	}
	written := phpAnalyze(t, phpFixture(t, map[string]string{"index.php": `<?php $_GET['x'] = 'fixed'; echo "<p>" . $_GET['x'] . "</p>";`}), "index.php")
	if u := phpUsesOfKind(written, "xss_candidate"); len(u) != 0 {
		t.Errorf("a written literal is rendered as request input: %+v", u[0].Dependencies)
	}
}
