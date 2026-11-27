package parse

import (
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

// pieces builds pieces from a string in which "\x01" marks a hole.
func pieces(s string) []SQLTextPiece {
	var out []SQLTextPiece
	for i, part := range strings.Split(s, "\x01") {
		if i > 0 {
			out = append(out, SQLTextPiece{Hole: true})
		}
		if part != "" {
			out = append(out, SQLTextPiece{Text: part})
		}
	}
	return out
}

func TestSQLStatementText(t *testing.T) {
	const H = "\x01"
	for _, tt := range []struct {
		name, text, class, rule string
	}{
		{"select", "SELECT * FROM users WHERE id = " + H, "statement", "select_from"},
		{"select lowercase", "select name, email from users", "statement", "select_from"},
		{"select distinct", "SELECT DISTINCT name FROM users", "statement", "select_from"},
		{"select top", "SELECT TOP 10 name FROM users", "statement", "select_from"},
		{"select alias", "SELECT name AS n FROM users", "statement", "select_from"},
		{"select function", "SELECT count(*) FROM users", "statement", "select_from"},
		{"select hole table", "SELECT * FROM " + H, "statement", "select_from"},
		{"select hole projection", "SELECT " + H + " FROM users", "statement", "select_from"},
		{"select subquery", "SELECT * FROM (SELECT 1) t", "statement", "select_from"},
		{"select multiline", "SELECT id,\n\t name\n  FROM\n users", "statement", "select_from"},
		{"select leading paren", "(SELECT 1 FROM dual)", "statement", "select_from"},
		{"select leading space", "   \n SELECT x FROM t", "statement", "select_from"},
		{"insert", "INSERT INTO users (a) VALUES (" + H + ")", "statement", "insert_into"},
		{"insert or replace", "INSERT OR REPLACE INTO t VALUES (1)", "statement", "insert_into"},
		{"insert ignore", "insert ignore into t values (1)", "statement", "insert_into"},
		{"replace into", "REPLACE INTO t (a) VALUES (1)", "statement", "insert_into"},
		{"merge into", "MERGE INTO t USING s ON t.id = s.id", "statement", "insert_into"},
		{"update", "UPDATE users SET name = " + H + " WHERE id = 1", "statement", "update_set"},
		{"update join", "UPDATE t1 JOIN t2 ON t1.id = t2.id SET t1.x = 1", "statement", "update_set"},
		{"update open set", "UPDATE users SET " + H, "statement", "update_set"},
		{"delete", "DELETE FROM users WHERE id = " + H, "statement", "delete_from"},
		{"delete low priority", "delete low_priority from t", "statement", "delete_from"},
		{"with", "WITH x AS (SELECT 1) SELECT * FROM x", "statement", "with_select"},
		{"with recursive columns", "WITH RECURSIVE r(n) AS (SELECT 1 UNION SELECT n+1 FROM r) SELECT n FROM r", "statement", "with_select"},
		{"create table", "CREATE TABLE t (id int)", "statement", "ddl_table"},
		{"create temp table", "create temporary table t (id int)", "statement", "ddl_table"},
		{"create table if not exists", "CREATE TABLE IF NOT EXISTS t (id int)", "statement", "ddl_table"},
		{"alter table", "ALTER TABLE t ADD c int", "statement", "ddl_table"},
		{"drop table", "DROP TABLE " + H, "statement", "ddl_table"},
		{"exec bracket", "EXEC [dbo].[GetUser] @id = 1", "statement", "exec_call"},
		{"exec at", "EXEC @sql", "statement", "exec_call"},
		{"exec hole", "EXEC " + H, "statement", "exec_call"},
		{"exec name end", "EXEC sp_who2", "statement", "exec_call"},
		{"execute paren", "EXECUTE get_user(1)", "statement", "exec_call"},
		{"exec with parameter", "EXEC sp_x @a = 1", "statement", "exec_call"},
		{"call paren", "CALL get_user(" + H + ")", "statement", "exec_call"},
		{"call end", "CALL do_cleanup", "statement", "exec_call"},
		{"where fragment", " WHERE name = '" + H + "'", "fragment", "where_comparison"},
		{"where like", " WHERE name LIKE '%" + H + "%'", "fragment", "where_comparison"},
		{"where in", "WHERE id IN (" + H + ")", "fragment", "where_comparison"},
		{"order by hole", " ORDER BY " + H, "fragment", "order_by"},
		{"order by desc", "ORDER BY created DESC", "fragment", "order_by"},
		{"order by multiline", "ORDER\n BY name, id", "fragment", "order_by"},
		{"values", " VALUES (" + H + ", " + H + ")", "fragment", "values"},
		{"pieces split across a keyword", "SEL" + H, "", ""},
		{"hole at start then statement", H + "SELECT * FROM t", "", ""},
	} {
		got := SQLStatementText(pieces(tt.text))
		if got.Class != tt.class || got.Rule != tt.rule || got.Matched != (tt.rule != "") {
			t.Errorf("%s: %q -> %+v; want class %q rule %q", tt.name, tt.text, got, tt.class, tt.rule)
		}
	}
}

func TestSQLStatementTextRejects(t *testing.T) {
	const H = "\x01"
	for _, text := range []string{
		"",
		"   \n\t ",
		H,
		H + H,
		" " + H + " ",
		"Select a file from the list",
		"Select one from a list of options",
		"select an item from your cart",
		"update your settings",
		"Update the settings and set a reminder",
		"Update profile set to default",
		"Delete from the list",
		"delete from your account",
		"Insert into the document",
		"Create table of contents",
		"Execute order 66",
		"Call me later",
		"Call John",
		"Call cleanup",
		"You can order by phone or by mail",
		"Our values are simple",
		"Where are you from?",
		"Please select a date from the calendar.",
		"The data comes from the sensor and flows into a file",
		"https://example.com/search?q=select+from&where=1",
		"<option value=\"1\">Select from list</option>",
		"<div class=\"from\">where = here</div>",
		"{\"select\": \"from\"}",
		"with great power comes great responsibility",
		"INSERT",
		"SELECT",
		"SELECT FROM",
	} {
		if got := SQLStatementText(pieces(text)); got.Matched {
			t.Errorf("%q matched as %s/%s", text, got.Class, got.Rule)
		}
	}
}

func TestSQLStatementTextPieces(t *testing.T) {
	got := SQLStatementText([]SQLTextPiece{{Text: "SELECT * FROM users WHERE name = '"}, {Hole: true}, {Text: "'"}})
	if !got.Matched || got.Holes != 1 || got.Text != "SELECT * FROM users WHERE name = '{}'" {
		t.Errorf("%+v", got)
	}
	// A literal "{}" or a NUL in the text is not a hole.
	got = SQLStatementText(SQLTextLiteral("SELECT '{}' FROM t\x00"))
	if !got.Matched || got.Holes != 0 {
		t.Errorf("%+v", got)
	}
	if got := SQLStatementText(nil); got.Matched || got.Holes != 0 {
		t.Errorf("nil pieces: %+v", got)
	}
	// Holes between keywords.
	got = SQLStatementText([]SQLTextPiece{{Text: "SELECT "}, {Hole: true}, {Text: " FROM "}, {Hole: true}})
	if !got.Matched || got.Rule != "select_from" || got.Holes != 2 {
		t.Errorf("%+v", got)
	}
}

func TestSQLTextExcerpt(t *testing.T) {
	small := []byte("a\nb\nc\n")
	text, line, start, end, ok := SQLTextExcerpt(small, analysis.Span{StartLine: 2, EndLine: 2})
	if !ok || text != string(small) || line != 1 || start != 0 || end != len(small) {
		t.Fatalf("small: %q %d %d %d %v", text, line, start, end, ok)
	}
	if _, _, _, _, ok := SQLTextExcerpt(nil, analysis.Span{}); ok {
		t.Error("empty file")
	}
	// 500 lines of 40 bytes: larger than the whole-file limit.
	var b strings.Builder
	offsets := []int{0}
	for i := 1; i <= 500; i++ {
		b.WriteString(strings.Repeat("x", 38) + "\n")
		offsets = append(offsets, b.Len())
	}
	big := []byte(b.String())
	sp := analysis.Span{File: "f.js", StartLine: 200, EndLine: 202, StartByte: offsets[199] + 3, EndByte: offsets[201] + 5}
	text, line, start, end, ok = SQLTextExcerpt(big, sp)
	if !ok || line != 140 || start != offsets[139] || end != offsets[262]-1 {
		t.Fatalf("window: line %d start %d end %d", line, start, end)
	}
	if strings.Count(text, "\n") != 262-140 || text != string(big[start:end]) {
		t.Errorf("window text has %d newlines", strings.Count(text, "\n"))
	}
	ev, ok := SQLTextExcerptEvidence(big, sp)
	if !ok || ev.Kind != SQLTextSourceExcerptKind || ev.Span.File != "f.js" || ev.Span.StartLine != 140 || ev.Span.EndLine != 262 ||
		ev.Span.StartByte > sp.StartByte || ev.Span.EndByte < sp.EndByte || ev.SHA256 == "" {
		t.Errorf("evidence: %+v", ev.Span)
	}
	// Near the start and the end of the file the window is clamped.
	_, line, start, _, _ = SQLTextExcerpt(big, analysis.Span{StartLine: 10, EndLine: 10})
	if line != 1 || start != 0 {
		t.Errorf("start clamp: line %d start %d", line, start)
	}
	_, line, _, end, _ = SQLTextExcerpt(big, analysis.Span{StartLine: 495, EndLine: 498})
	if line != 435 || end != len(big) {
		t.Errorf("end clamp: line %d end %d of %d", line, end, len(big))
	}
	// One line shorter than the whole-file limit is sent whole, one byte over is windowed.
	edge := []byte(strings.Repeat("y\n", SQLTextExcerptWholeFileLimit/2))
	if _, l, s, e, _ := SQLTextExcerpt(edge, analysis.Span{StartLine: 4000, EndLine: 4000}); l != 1 || s != 0 || e != len(edge) {
		t.Errorf("limit: %d %d %d", l, s, e)
	}
	if _, l, _, _, _ := SQLTextExcerpt(append(edge, 'z'), analysis.Span{StartLine: 4000, EndLine: 4000}); l != 3940 {
		t.Errorf("over the limit: window starts at line %d", l)
	}
}

func TestSQLTextPlacement(t *testing.T) {
	h := SQLTextPiece{Hole: true}
	lit := func(s string) SQLTextPiece { return SQLTextPiece{Text: s} }
	for name, c := range map[string]struct {
		pieces []SQLTextPiece
		text   string
		parts  []string
	}{
		"outside quotes":  {[]SQLTextPiece{lit("SELECT a FROM t WHERE id = "), h}, "SELECT a FROM t WHERE id = {1}", []string{"{1}: outside quotes"}},
		"inside a quote":  {[]SQLTextPiece{lit("SELECT a FROM t WHERE n = '"), h, lit("' AND id = "), h}, "SELECT a FROM t WHERE n = '{1}' AND id = {2}", []string{"{1}: inside a single-quoted literal", "{2}: outside quotes"}},
		"doubled quote":   {[]SQLTextPiece{lit("SELECT a FROM t WHERE n = 'it''s' AND m = "), h}, "SELECT a FROM t WHERE n = 'it''s' AND m = {1}", []string{"{1}: outside quotes"}},
		"other quotes":    {[]SQLTextPiece{lit("SELECT a FROM `"), h, lit("` WHERE \""), h, lit("\" = 1")}, "SELECT a FROM `{1}` WHERE \"{2}\" = 1", []string{"{1}: inside backquotes", "{2}: inside double quotes"}},
		"quote in quotes": {[]SQLTextPiece{lit("SELECT a FROM t WHERE n = \"o'\" AND m = "), h}, "SELECT a FROM t WHERE n = \"o'\" AND m = {1}", []string{"{1}: outside quotes"}},
	} {
		text, parts, ok := SQLTextPlacement(c.pieces)
		if !ok || text != c.text || strings.Join(parts, "|") != strings.Join(c.parts, "|") {
			t.Errorf("%s: %q %v %v", name, text, parts, ok)
		}
	}
	for name, pieces := range map[string][]SQLTextPiece{
		"no hole":             {lit("SELECT a FROM t")},
		"backslash in quotes": {lit("SELECT a FROM t WHERE n = 'a\\' AND m = "), h},
	} {
		if _, _, ok := SQLTextPlacement(pieces); ok {
			t.Errorf("%s: placement given", name)
		}
	}
	e, ok := SQLTextPlacementEvidence([]SQLTextPiece{lit("SELECT a FROM t WHERE id = "), h}, analysis.Span{File: "a", StartByte: 1, EndByte: 9})
	if !ok || e.Kind != SQLTextPlacementKind || e.ModelText != "{1}: outside quotes" || e.Span.File != "a" {
		t.Errorf("evidence %+v", e)
	}
}
