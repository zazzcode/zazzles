package parse

import (
	"regexp"
	"strconv"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
)

// Raw-SQL storage for stored XSS: a verified PGlite query whose SQL text is a
// literal names its table and columns. A SELECT returns { rows } whose row
// fields are storage reads of "sql:<table>.<column>"; an INSERT records each
// column's value (a bound $n parameter or an interpolated '${v}') as a write
// of the same key. Anything else (joins, aliases, dynamic SQL) is not linked.

var (
	sqlSelectFrom = regexp.MustCompile(`(?is)^\s*select\s+(.+?)\s+from\s+([a-z_][a-z0-9_]*)\b`)
	sqlInsertInto = regexp.MustCompile(`(?is)^\s*insert\s+into\s+([a-z_][a-z0-9_]*)\s*\(([^)]*)\)\s*values\s*\((.*)\)`)
	sqlJoin       = regexp.MustCompile(`(?i)\bjoin\b`)
)

// pgliteSQLText returns a literal SQL argument; a template's substitutions are
// replaced by their index markers (\x00n\x00) so INSERT values can be mapped.
func pgliteSQLText(m *sourceModule, n *sitter.Node) (string, []*sitter.Node, bool) {
	n = unwrapTS(n)
	if n == nil {
		return "", nil, false
	}
	if s, ok := stringLiteral(n, m.src); ok {
		return s, nil, true
	}
	if n.Kind() != "template_string" {
		return "", nil, false
	}
	var b strings.Builder
	var subs []*sitter.Node
	for i := uint(0); i < n.NamedChildCount(); i++ {
		c := n.NamedChild(i)
		switch c.Kind() {
		case "string_fragment":
			b.WriteString(c.Utf8Text(m.src))
		case "template_substitution":
			if c.NamedChildCount() != 1 {
				return "", nil, false
			}
			b.WriteString("\x00" + strconv.Itoa(len(subs)) + "\x00")
			subs = append(subs, c.NamedChild(0))
		default:
			b.WriteString(c.Utf8Text(m.src))
		}
	}
	return b.String(), subs, true
}

func (f *flow) pgliteModelCall(call, obj, prop *sitter.Node) (value, bool) {
	if f.set == nil || obj.Kind() != "identifier" {
		return value{}, false
	}
	method := prop.Utf8Text(f.module.src)
	if method != "query" && method != "exec" {
		return value{}, false
	}
	args := call.ChildByFieldName("arguments")
	if args == nil || args.NamedChildCount() == 0 || len(f.set.pgliteCall(f.module, call, obj.Utf8Text(f.module.src), method)) == 0 {
		return value{}, false
	}
	text, _, ok := pgliteSQLText(f.module, args.NamedChild(0))
	if !ok {
		return value{}, false
	}
	if m := sqlSelectFrom.FindStringSubmatch(text); m != nil && !sqlJoin.MatchString(text) && method == "query" {
		e := f.module.evidence("storage_query", call)
		return value{fields: map[string]value{"rows": {model: "sql:" + strings.ToLower(m[2]), read: &e}}}, true
	}
	if m := sqlInsertInto.FindStringSubmatch(text); m != nil {
		return value{model: "sql:" + strings.ToLower(m[1])}, true
	}
	return value{}, false
}

// recordSQLInsert maps INSERT columns to their values and records the writes.
func (f *flow) recordSQLInsert(call *sitter.Node, model string) {
	args := call.ChildByFieldName("arguments")
	if args == nil || args.NamedChildCount() == 0 {
		return
	}
	text, subs, ok := pgliteSQLText(f.module, args.NamedChild(0))
	if !ok {
		return
	}
	m := sqlInsertInto.FindStringSubmatch(text)
	if m == nil {
		return
	}
	columns := splitSQLList(m[2])
	items := splitSQLList(m[3])
	if len(columns) != len(items) {
		return
	}
	var params *sitter.Node
	if args.NamedChildCount() > 1 && unwrapTS(args.NamedChild(1)).Kind() == "array" {
		params = unwrapTS(args.NamedChild(1))
	}
	if f.set.storageWrites == nil {
		f.set.storageWrites = map[string][]storageWrite{}
	}
	for i, column := range columns {
		item := strings.Trim(strings.TrimSpace(items[i]), "'")
		var operand *sitter.Node
		switch {
		case strings.HasPrefix(item, "$"):
			n, err := strconv.Atoi(item[1:])
			if err == nil && params != nil && n >= 1 && uint(n) <= params.NamedChildCount() {
				operand = params.NamedChild(uint(n - 1))
			}
		case strings.HasPrefix(item, "\x00") && strings.HasSuffix(item, "\x00"):
			n, err := strconv.Atoi(strings.Trim(item, "\x00"))
			if err == nil && n < len(subs) {
				operand = subs[n]
			}
		}
		if operand == nil {
			continue
		}
		v := f.eval(operand)
		if len(v.deps) == 0 {
			continue
		}
		key := model + "." + strings.ToLower(strings.Trim(strings.TrimSpace(column), `"`))
		f.set.storageWrites[key] = append(f.set.storageWrites[key], storageWrite{f.entry.ID, v, f.module.evidence("storage_write", call)})
	}
}

func splitSQLList(s string) []string {
	var out []string
	depth, start := 0, 0
	for i, r := range s {
		switch r {
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
	}
	return append(out, s[start:])
}

// jsonRoundTrip reports JSON.parse(JSON.stringify(x)), a deep copy of x.
func jsonRoundTrip(m *sourceModule, call *sitter.Node) *sitter.Node {
	fn, args := call.ChildByFieldName("function"), call.ChildByFieldName("arguments")
	if fn == nil || args == nil || args.NamedChildCount() != 1 || fn.Utf8Text(m.src) != "JSON.parse" || shadowed(call, "JSON", m.src) || topLevelBinding(m, "JSON") {
		return nil
	}
	inner := unwrapTS(args.NamedChild(0))
	if inner == nil || inner.Kind() != "call_expression" || !jsonStringifyCall(m, inner) {
		return nil
	}
	ia := inner.ChildByFieldName("arguments")
	if ia == nil || ia.NamedChildCount() != 1 {
		return nil
	}
	return ia.NamedChild(0)
}
