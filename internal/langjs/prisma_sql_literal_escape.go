package langjs

import (
	"path"
	"strconv"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
	"github.com/zazzcode/zazzles/internal/parse"
)

// sqlQuoteDoublingDialects are the Prisma datasource providers whose single-quoted
// string literals treat a doubled quote as the only escape: SQLite, and PostgreSQL
// (standard_conforming_strings on, the default) with its CockroachDB wire dialect.
// MySQL, SQL Server and unknown providers are excluded: MySQL also honors backslash
// escapes, so a doubled quote does not make a literal safe there.
var sqlQuoteDoublingDialects = map[string]bool{"sqlite": true, "postgresql": true, "postgres": true, "cockroachdb": true}

// prismaProviderFor returns the datasource provider of the nearest prisma schema.
func (s *moduleSet) prismaProviderFor(file string) string {
	for dir := path.Dir(file); ; dir = path.Dir(dir) {
		if schema, ok := s.readBounded(joinDir(dir, "prisma/schema.prisma"), 2<<20); ok {
			if match := prismaDatasource.FindStringSubmatch(schema.Text); match != nil {
				return match[1]
			}
			return ""
		}
		if dir == "." || dir == "/" || dir == "" {
			return ""
		}
	}
}

// sqlLiteralEscapeFacts marks, per operand, a verified quote-doubling escape of a
// substitution that sits inside a single-quoted SQL string literal of a Prisma raw
// statement on a quote-doubling dialect. The fact names only the escaped
// operands: every other substitution of the same statement keeps no fact, so a raw
// operand beside escaped ones stays raw and the record is unchanged in kind.
func (s *moduleSet) sqlLiteralEscapeFacts(use *analysis.CandidateUse) {
	if use.Kind != "sql_query_candidate" || use.Completeness == nil {
		return
	}
	m := s.modules[use.Sink.Span.File]
	if m == nil {
		return
	}
	call := parse.NodeAt(m.tree.RootNode(), use.Sink.Span.StartByte, use.Sink.Span.EndByte)
	if call == nil || call.Kind() != "call_expression" {
		return
	}
	if contract, _, _, ok := s.sqlLibraryCall(m, call); !ok || contract != analysispacks.PrismaRawContract {
		return
	}
	dialect := s.prismaProviderFor(m.file)
	if !sqlQuoteDoublingDialects[dialect] {
		return
	}
	args := call.ChildByFieldName("arguments")
	if args == nil || args.NamedChildCount() == 0 {
		return
	}
	arg := unwrapTS(args.NamedChild(0))
	if arg != nil && arg.Kind() == "identifier" {
		name := arg.Utf8Text(m.src)
		if bindingReassigned(m, name) {
			return
		}
		arg = unwrapTS(localInitializer(m, call, name))
	}
	if arg == nil || arg.Kind() != "template_string" {
		return
	}
	seen := map[string]bool{}
	for _, operand := range escapedLiteralOperands(m, arg, 0) {
		fact := "sql_literal_quote_doubling: " + operand.Utf8Text(m.src) + " at " + m.file + "; dialect " + dialect + "; single-quoted literal"
		if !seen[fact] {
			seen[fact] = true
			use.Completeness.ModelFacts = append(use.Completeness.ModelFacts, fact)
		}
	}
}

// escapedLiteralOperands returns the quote-doubling calls of a SQL template that are
// complete substitutions inside a single-quoted literal. A conditional substitution
// is searched per arm, but only from outside any literal; a nested template is
// scanned from its own start.
func escapedLiteralOperands(m *sourceModule, tmpl *sitter.Node, depth int) []*sitter.Node {
	if depth > 3 {
		return nil
	}
	text, subs, ok := pgliteSQLText(m, tmpl)
	if !ok {
		return nil
	}
	var out []*sitter.Node
	for i, sub := range subs {
		state := sqlLiteralState(text, "\x00"+strconv.Itoa(i)+"\x00")
		sub = unwrapTS(sub)
		if sub == nil {
			continue
		}
		switch {
		case state == sqlInLiteral && isQuoteDoubling(m, sub):
			out = append(out, sub)
		case state == sqlOutside && sub.Kind() == "ternary_expression":
			for _, field := range []string{"consequence", "alternative"} {
				if arm := unwrapTS(sub.ChildByFieldName(field)); arm != nil && arm.Kind() == "template_string" {
					out = append(out, escapedLiteralOperands(m, arm, depth+1)...)
				}
			}
		}
	}
	return out
}

const (
	sqlOutside = iota
	sqlInLiteral
	sqlInEscapeLiteral
	sqlInDoubleQuoted
	sqlInBacktick
	sqlInLineComment
	sqlInBlockComment
	// sqlOther is any state where a doubled quote is not the escape.
	sqlOther = sqlInEscapeLiteral
)

// sqlLiteralState scans statement text up to a substitution marker and reports
// sqlOutside, sqlInLiteral (an ordinary single-quoted literal) or sqlOther: a
// double-quoted or backtick identifier, a comment, or a backslash-escape E'...'
// string, where quote doubling is not the escape. A doubled quote toggles the
// literal twice, so plain tracking follows the real lexer state.
func sqlLiteralState(text, marker string) int {
	at := strings.Index(text, marker)
	if at < 0 {
		return sqlOther
	}
	state := sqlOutside
	closes := map[int]byte{sqlInLiteral: '\'', sqlInEscapeLiteral: '\'', sqlInDoubleQuoted: '"', sqlInBacktick: '`', sqlInLineComment: '\n'}
	for i := 0; i < at; i++ {
		c := text[i]
		switch {
		case state == sqlInBlockComment:
			if c == '*' && i+1 < len(text) && text[i+1] == '/' {
				state = sqlOutside
				i++
			}
		case state != sqlOutside:
			if c == closes[state] {
				state = sqlOutside
			}
		case c == '\'':
			state = sqlInLiteral
			if i > 0 && (text[i-1] == 'E' || text[i-1] == 'e') && (i < 2 || !isWordByte(text[i-2])) {
				state = sqlInEscapeLiteral
			}
		case c == '"':
			state = sqlInDoubleQuoted
		case c == '`':
			state = sqlInBacktick
		case c == '-' && i+1 < len(text) && text[i+1] == '-':
			state = sqlInLineComment
		case c == '/' && i+1 < len(text) && text[i+1] == '*':
			state = sqlInBlockComment
			i++
		}
	}
	if state != sqlOutside && state != sqlInLiteral {
		return sqlOther
	}
	return state
}

func isWordByte(c byte) bool {
	return c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// isQuoteDoubling reports `<value>.replace(/'/g, "”")` or `<value>.replaceAll("'", "”")`
// as the whole substitution: the only replaced character is the single quote, every
// occurrence is replaced, and the replacement is exactly two quotes.
func isQuoteDoubling(m *sourceModule, n *sitter.Node) bool {
	if n.Kind() != "call_expression" {
		return false
	}
	fn, args := n.ChildByFieldName("function"), n.ChildByFieldName("arguments")
	if fn == nil || args == nil || fn.Kind() != "member_expression" || args.NamedChildCount() != 2 {
		return false
	}
	obj, prop := fn.ChildByFieldName("object"), fn.ChildByFieldName("property")
	if obj == nil || prop == nil {
		return false
	}
	method := prop.Utf8Text(m.src)
	if method != "replace" && method != "replaceAll" {
		return false
	}
	pattern, replacement := unwrapTS(args.NamedChild(0)), unwrapTS(args.NamedChild(1))
	if pattern == nil || replacement == nil {
		return false
	}
	switch pattern.Kind() {
	case "regex":
		text := pattern.Utf8Text(m.src)
		end := strings.LastIndex(text, "/")
		if len(text) < 3 || text[0] != '/' || end < 2 || text[1:end] != "'" || text[end+1:] != "g" {
			return false
		}
	case "string":
		inner, _ := stringLiteral(pattern, m.src)
		if method != "replaceAll" || (inner != "'" && inner != `\'`) {
			return false
		}
	default:
		return false
	}
	if replacement.Kind() != "string" {
		return false
	}
	inner, _ := stringLiteral(replacement, m.src)
	return inner == "''" || inner == `\'\'`
}
