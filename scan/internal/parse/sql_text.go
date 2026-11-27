package parse

import (
	"crypto/sha256"
	"fmt"
	"regexp"
	"strings"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
)

// SQL statement text recognition shared by every language.
//
// A language hook reads the syntax of one argument of a call and reduces it to
// literal pieces with holes (see SQLTextPiece), then asks SQLStatementText
// whether those pieces are SQL statement text. The test is purely textual: it
// never looks at the callee, the package or the database, so a new driver needs
// no change. A hook that finds a match records a sql_query_candidate with the
// contract analysispacks.SQLTextContract, puts the dependencies of the matched
// argument in slot SQLTextSlot and every other argument's dependencies in slot
// SQLTextParametersSlot, and attaches SQLTextSourceExcerptKind context evidence
// built with SQLTextExcerptEvidence.

const (
	// SQLTextSlot is the sink slot of the dependencies of the argument that holds
	// the statement text.
	SQLTextSlot = analysispacks.SQLTextSlot
	// SQLTextParametersSlot is the sink slot of the dependencies of every other
	// argument of the call: values passed apart from the statement text.
	SQLTextParametersSlot = analysispacks.SQLTextParametersSlot
	// SQLTextSourceExcerptKind is the context evidence kind of a source excerpt
	// the judge sends for a SQL text record. The judge reads no file; it sends only
	// the context evidence of this kind and of the handler and helper kinds.
	SQLTextSourceExcerptKind = "source_excerpt"
	// SQLTextExcerptWholeFileLimit is the largest file, in bytes, sent whole.
	SQLTextExcerptWholeFileLimit = 16000
	// SQLTextExcerptWindowLines is the number of lines kept on each side of the
	// call when the file is larger than SQLTextExcerptWholeFileLimit.
	SQLTextExcerptWindowLines = 60
)

// SQLTextPiece is one part of the string an argument evaluates to: either
// literal text (Hole false) or a place where a value the scanner cannot read as
// a literal sits (Hole true; Text is ignored). The pieces of one argument are in
// source order. A string literal is one piece; "a" + x + "b", a template literal
// or an interpolated string is three. A hook gives a hole for any
// part it cannot resolve to literal text; it must not guess.
type SQLTextPiece struct {
	Text string
	Hole bool
}

// SQLTextMatch is the result of SQLStatementText.
type SQLTextMatch struct {
	// Matched reports that the pieces are SQL statement text or a SQL fragment.
	Matched bool
	// Class is "statement" for a whole statement or "fragment" for a clause that
	// only appears inside a statement (WHERE with a comparison, ORDER BY, VALUES).
	// Empty when not matched.
	Class string
	// Rule names the rule that matched: select_from, insert_into, update_set,
	// delete_from, with_select, ddl_table, exec_call, where_comparison, order_by or
	// values. Empty when not matched.
	Rule string
	// Holes is the number of holes in the pieces.
	Holes int
	// Text is the pieces joined with SQLTextHoleMarker in place of each hole.
	Text string
}

// SQLTextHoleMarker stands for a hole in SQLTextMatch.Text.
const SQLTextHoleMarker = "{}"

const sqlHole = "\x00"

// SQLTextLiteral returns the pieces of an argument that is one literal string.
func SQLTextLiteral(text string) []SQLTextPiece { return []SQLTextPiece{{Text: text}} }

// SQLStatementText reports whether the argument whose string is built from
// pieces is SQL statement text. It is language-neutral and deterministic.
//
// What matches (case-insensitive, any whitespace including newlines, one leading
// "(" allowed; the text must begin with the statement keyword):
//
//   - select_from:  SELECT <projection> FROM <table or subquery>
//   - insert_into:  INSERT [OR x | IGNORE] INTO / REPLACE INTO / MERGE INTO <table>
//   - update_set:   UPDATE <table> ... SET with an assignment (or nothing yet)
//   - delete_from:  DELETE [LOW_PRIORITY|QUICK|IGNORE] FROM <table>
//   - with_select:  WITH [RECURSIVE] name [(cols)] AS ( SELECT | VALUES | ...
//   - ddl_table:    CREATE | ALTER | DROP [TEMP|VIRTUAL|UNIQUE|...] TABLE <table>
//   - exec_call:    EXEC | EXECUTE <procedure> (a name with _ or ., a bracketed or
//     @ name, a hole, or a name followed by "(", "@", a quote or the end);
//     CALL <procedure> followed by "(", or ending the text when the name has _ or .
//
// and as a fragment, anywhere in the text: WHERE <operand> with a comparison
// operator, LIKE, IN, IS or BETWEEN (where_comparison); ORDER BY <column> at the
// end or before ASC, DESC, LIMIT and similar (order_by); VALUES followed by "("
// (values).
//
// To keep ordinary prose and UI text out ("Select a file from the list",
// "update your settings", "Delete from the list"), the table after FROM, INTO,
// UPDATE, DELETE FROM and TABLE must not be a determiner or pronoun (a, an, the,
// your, this, ...), a SELECT projection of several bare words must be
// "x AS y", and an UPDATE needs an assignment after SET. Text that is empty, only
// holes, a URL or markup does not match. Comments before the statement are not
// skipped.
func SQLStatementText(pieces []SQLTextPiece) SQLTextMatch {
	var b strings.Builder
	holes := 0
	for _, p := range pieces {
		if p.Hole {
			holes++
			b.WriteString(sqlHole)
			continue
		}
		b.WriteString(strings.ReplaceAll(p.Text, sqlHole, ""))
	}
	joined := b.String()
	out := SQLTextMatch{Holes: holes, Text: strings.ReplaceAll(joined, sqlHole, SQLTextHoleMarker)}
	if class, rule := sqlTextRule(joined); rule != "" {
		out.Matched, out.Class, out.Rule = true, class, rule
	}
	return out
}

var (
	sqlWhitespace = regexp.MustCompile(`\s+`)
	sqlTable      = `[A-Z_@#$"` + "`" + `\[\x00][A-Z0-9_@#$."` + "`" + `\[\]\x00]*`
	sqlTableToken = regexp.MustCompile(`^` + sqlTable)
	sqlSelectFrom = regexp.MustCompile(`^SELECT\s+(.+?)\s+FROM(?:\s+(\S.*))?$`)
	sqlInsertInto = regexp.MustCompile(`^(?:INSERT\s+(?:OR\s+\w+\s+|IGNORE\s+)?INTO|REPLACE\s+INTO|MERGE\s+INTO)\s+(` + sqlTable + `)`)
	sqlUpdateSet  = regexp.MustCompile(`^UPDATE\s+(?:(?:LOW_PRIORITY|IGNORE|ONLY)\s+|OR\s+\w+\s+)*(\S+)(?:\s.*?)?\s+SET(?:\s*$|\s+\x00|\s+[^=\s]+\s*=)`)
	sqlDeleteFrom = regexp.MustCompile(`^DELETE\s+(?:(?:LOW_PRIORITY|QUICK|IGNORE)\s+)*FROM\s+(\S+)`)
	sqlWithSelect = regexp.MustCompile(`^WITH\s+(?:RECURSIVE\s+)?[A-Z_\x00"` + "`" + `\[][^\s(]*\s*(?:\([^)]*\)\s*)?AS\s*(?:(?:NOT\s+)?MATERIALIZED\s*)?\(\s*(?:SELECT\b|VALUES\b|WITH\b|INSERT\b|UPDATE\b|DELETE\b|\x00)`)
	sqlDDLTable   = regexp.MustCompile(`^(?:CREATE|ALTER|DROP)\s+(?:(?:OR\s+REPLACE|TEMP\w*|VIRTUAL|UNIQUE|GLOBAL|LOCAL|UNLOGGED)\s+)*TABLE\s+(?:IF\s+(?:NOT\s+)?EXISTS\s+)?(\S+)`)
	sqlExec       = regexp.MustCompile(`^(EXEC|EXECUTE|CALL)\s+(\[[^\]]+\](?:\.\[[^\]]+\])*|@\w+|\x00|[A-Z_][A-Z0-9_.$#]*)(.*)$`)
	sqlWhere      = regexp.MustCompile(`(?:^|\s)WHERE\s+\S+(?:\s*(?:=|<>|!=|<=|>=|<|>)|\s+(?:NOT\s+)?(?:LIKE|ILIKE|IN|IS|BETWEEN)\b)`)
	sqlOrderBy    = regexp.MustCompile(`(?:^|\s)ORDER\s+BY\s+[A-Z_\x00"` + "`" + `\[(][^\s,;)]*(?:\s+(?:ASC|DESC)\b)?\s*(?:,|;|\)|$|\b(?:LIMIT|OFFSET|FETCH)\b)`)
	sqlValues     = regexp.MustCompile(`(?:^|[\s)])VALUES\s*\(`)
	sqlProjPrefix = regexp.MustCompile(`^(?:DISTINCT\s+|ALL\s+|TOP\s+(?:\d+|\([^)]*\)|\x00)\s+)+`)
	sqlProjPunct  = regexp.MustCompile(`[*,(.\x00"'` + "`" + `\[]`)
)

// sqlProse are determiners and pronouns that open a noun phrase, never a table.
var sqlProse = map[string]bool{"A": true, "AN": true, "THE": true, "YOUR": true, "YOU": true, "THIS": true, "THAT": true, "THESE": true, "THOSE": true,
	"MY": true, "OUR": true, "ITS": true, "THEIR": true, "HIS": true, "HER": true, "SOME": true, "ANY": true, "EACH": true, "EVERY": true,
	"OF": true, "TO": true, "IN": true, "ON": true, "FOR": true, "AT": true}

// sqlTableOK reports a plausible table token: identifier-like or a hole or a
// subquery, and not a prose word.
func sqlTableOK(tok string) bool {
	if tok == "" {
		return false
	}
	if tok[0] == '(' {
		return true
	}
	head := tok
	if i := strings.IndexAny(head, ".("); i > 0 {
		head = head[:i]
	}
	head = strings.Trim(head, "\"`[]")
	if sqlProse[head] {
		return false
	}
	return sqlTableToken.MatchString(tok)
}

func sqlFirstToken(s string) string {
	if i := strings.IndexAny(s, " ;,"); i >= 0 {
		return s[:i]
	}
	return s
}

func sqlTextRule(joined string) (class, rule string) {
	u := strings.TrimSpace(sqlWhitespace.ReplaceAllString(strings.ToUpper(joined), " "))
	u = strings.TrimSpace(strings.TrimPrefix(u, "("))
	if u == "" || strings.Trim(u, sqlHole+" ") == "" {
		return "", ""
	}
	switch {
	case strings.HasPrefix(u, "SELECT "):
		if m := sqlSelectFrom.FindStringSubmatch(u); m != nil && sqlProjectionOK(m[1]) && sqlTableOK(sqlFirstToken(m[2])) {
			return "statement", "select_from"
		}
	case strings.HasPrefix(u, "INSERT "), strings.HasPrefix(u, "REPLACE "), strings.HasPrefix(u, "MERGE "):
		if m := sqlInsertInto.FindStringSubmatch(u); m != nil && sqlTableOK(m[1]) {
			return "statement", "insert_into"
		}
	case strings.HasPrefix(u, "UPDATE "):
		if m := sqlUpdateSet.FindStringSubmatch(u); m != nil && sqlTableOK(m[1]) {
			return "statement", "update_set"
		}
	case strings.HasPrefix(u, "DELETE "):
		if m := sqlDeleteFrom.FindStringSubmatch(u); m != nil && sqlTableOK(m[1]) {
			return "statement", "delete_from"
		}
	case strings.HasPrefix(u, "WITH "):
		if sqlWithSelect.MatchString(u) {
			return "statement", "with_select"
		}
	case strings.HasPrefix(u, "CREATE "), strings.HasPrefix(u, "ALTER "), strings.HasPrefix(u, "DROP "):
		if m := sqlDDLTable.FindStringSubmatch(u); m != nil && sqlTableOK(m[1]) {
			return "statement", "ddl_table"
		}
	case strings.HasPrefix(u, "EXEC "), strings.HasPrefix(u, "EXECUTE "), strings.HasPrefix(u, "CALL "):
		if sqlExecOK(u) {
			return "statement", "exec_call"
		}
	}
	switch {
	case sqlWhere.MatchString(u):
		return "fragment", "where_comparison"
	case sqlOrderBy.MatchString(u):
		return "fragment", "order_by"
	case sqlValues.MatchString(u):
		return "fragment", "values"
	}
	return "", ""
}

// sqlProjectionOK: a projection is "*", a hole, a list, a call, a qualified or
// quoted name, one bare word, or "x AS y" after DISTINCT, ALL or TOP n. Several
// bare words with no punctuation is a sentence.
func sqlProjectionOK(proj string) bool {
	proj = strings.TrimSpace(sqlProjPrefix.ReplaceAllString(proj, ""))
	if proj == "" {
		return false
	}
	words := strings.Fields(proj)
	if len(words) == 1 || sqlProjPunct.MatchString(proj) {
		return true
	}
	return words[1] == "AS"
}

// sqlExecOK: EXEC and EXECUTE take a procedure name; CALL needs a parenthesis or
// the end of the text.
func sqlExecOK(u string) bool {
	m := sqlExec.FindStringSubmatch(u)
	if m == nil {
		return false
	}
	verb, name, rest := m[1], m[2], strings.TrimSpace(m[3])
	if sqlProse[strings.Trim(name, "\"`[]")] {
		return false
	}
	strong := name[0] == '[' || name[0] == '@' || name == sqlHole
	if verb == "CALL" {
		return strings.HasPrefix(rest, "(") || rest == "" && (strong || strings.ContainsAny(name, "_."))
	}
	if strong {
		return true
	}
	switch {
	case rest == "", strings.HasPrefix(rest, "("), strings.HasPrefix(rest, "@"):
		return true
	case strings.HasPrefix(rest, sqlHole), strings.HasPrefix(rest, "'"), strings.HasPrefix(rest, `"`), strings.HasPrefix(rest, "?"):
		return strings.ContainsAny(name, "_.")
	}
	return false
}

// SQLTextExcerpt returns the text of the source excerpt a SQL text record
// attaches for the call at span sp, from the bytes of the file that holds it: the
// whole file when it is at most SQLTextExcerptWholeFileLimit bytes; otherwise the
// whole lines from SQLTextExcerptWindowLines before the span's start line to
// SQLTextExcerptWindowLines after its end line (clamped to the file). It returns
// the text, its first line (1-based), and the byte offsets of the text in the file
// [startByte, endByte). ok is false when src is empty.
func SQLTextExcerpt(src []byte, sp analysis.Span) (text string, startLine, startByte, endByte int, ok bool) {
	if len(src) == 0 {
		return "", 0, 0, 0, false
	}
	if len(src) <= SQLTextExcerptWholeFileLimit {
		return string(src), 1, 0, len(src), true
	}
	from, to := sp.StartLine-SQLTextExcerptWindowLines, sp.EndLine+SQLTextExcerptWindowLines
	if from < 1 {
		from = 1
	}
	line, start, end := 1, 0, len(src)
	started := from == 1
	for i := 0; i < len(src); i++ {
		if src[i] != '\n' {
			continue
		}
		line++
		if !started && line == from {
			start, started = i+1, true
		}
		if line == to+1 {
			end = i
			break
		}
	}
	if !started {
		// The span lies below the last line: keep the last lines of the file.
		start = 0
		from = 1
	}
	return string(src[start:end]), from, start, end, true
}

// SQLTextExcerptEvidence builds the SQLTextSourceExcerptKind context evidence
// for the call at span sp from the bytes of its file (see SQLTextExcerpt). Its
// span carries the file name of sp, the excerpt's lines and byte offsets (which
// contain sp when sp is inside the file), and its SHA256 is the hash of the whole
// file. ok is false when src is empty.
func SQLTextExcerptEvidence(src []byte, sp analysis.Span) (analysis.Evidence, bool) {
	text, startLine, startByte, endByte, ok := SQLTextExcerpt(src, sp)
	if !ok {
		return analysis.Evidence{}, false
	}
	return analysis.Evidence{Kind: SQLTextSourceExcerptKind, Text: text, SHA256: fmt.Sprintf("%x", sha256.Sum256(src)),
		Span: analysis.Span{File: sp.File, StartLine: startLine, EndLine: startLine + strings.Count(text, "\n"), StartByte: startByte, EndByte: endByte}}, true
}

// Where a hole sits in statement text. A hook attaches it to a SQL text record
// as Completeness.Evidence[SQLTextPlacementKind]; the judge sends it as the
// scanner's reading of the literal text. It is a fact about quotes in the text
// the scanner read, not about the value that fills the hole.
const (
	// SQLTextPlacementKind is the evidence kind and the Completeness.Evidence key.
	SQLTextPlacementKind = "statement_shape"
	// SQLTextPlacementMaxHoles and SQLTextPlacementMaxBytes bound the evidence.
	SQLTextPlacementMaxHoles = 12
	SQLTextPlacementMaxBytes = 4000
)

// SQLTextPlacement renders the pieces as statement text with {1}, {2}, ... for
// the holes, and says for each hole whether it sits inside a quoted literal or
// outside quotes. Quotes are read the way every SQL dialect agrees on: a quote
// opens a literal, the same quote closes it, and a doubled quote inside is one
// character. ok is false when the pieces have no hole, exceed the bounds, or
// hold a backslash inside a quoted literal: dialects disagree on whether it
// escapes the quote, so the scanner does not say.
func SQLTextPlacement(pieces []SQLTextPiece) (text string, parts []string, ok bool) {
	var b strings.Builder
	var quote byte
	holes := 0
	for _, p := range pieces {
		if p.Hole {
			holes++
			if holes > SQLTextPlacementMaxHoles {
				return "", nil, false
			}
			where := "outside quotes"
			switch quote {
			case '\'':
				where = "inside a single-quoted literal"
			case '"':
				where = "inside double quotes"
			case '`':
				where = "inside backquotes"
			}
			fmt.Fprintf(&b, "{%d}", holes)
			parts = append(parts, fmt.Sprintf("{%d}: %s", holes, where))
			continue
		}
		t := p.Text
		for i := 0; i < len(t); i++ {
			ch := t[i]
			switch {
			case quote == 0 && (ch == '\'' || ch == '"' || ch == '`'):
				quote = ch
			case quote != 0 && ch == '\\':
				return "", nil, false
			case quote != 0 && ch == quote:
				if i+1 < len(t) && t[i+1] == quote {
					i++
				} else {
					quote = 0
				}
			}
		}
		b.WriteString(t)
	}
	if holes == 0 || b.Len() > SQLTextPlacementMaxBytes {
		return "", nil, false
	}
	return b.String(), parts, true
}

// SQLTextPlacementEvidence builds the SQLTextPlacementKind evidence of a text
// argument at span sp: Text is the statement text with numbered holes and
// ModelText one line per hole.
func SQLTextPlacementEvidence(pieces []SQLTextPiece, sp analysis.Span) (analysis.Evidence, bool) {
	text, parts, ok := SQLTextPlacement(pieces)
	if !ok {
		return analysis.Evidence{}, false
	}
	return analysis.Evidence{Kind: SQLTextPlacementKind, Text: text, ModelText: strings.Join(parts, "\n"), Span: sp}, true
}
