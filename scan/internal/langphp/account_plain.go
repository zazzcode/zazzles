package langphp

import (
	"maps"
	"regexp"
	"slices"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/parse"
)

// Plain-PHP account evidence. A static pass over literal SQL text finds the
// tables and columns a statement writes from password_hash or a fast digest,
// and the columns a SELECT compares.

var (
	sqlInsert  = regexp.MustCompile(`(?is)\bINSERT\s+INTO\s+` + "`?" + `(\w+)` + "`?" + `\s*\(([^)]*)\)\s*VALUES\s*\(([^)]*)\)`)
	sqlUpdate  = regexp.MustCompile(`(?is)\bUPDATE\s+` + "`?" + `(\w+)` + "`?" + `\s+SET\s+(.+?)(?:\bWHERE\b|$)`)
	sqlSelect  = regexp.MustCompile(`(?is)\bSELECT\b.+?\bFROM\s+` + "`?" + `(\w+)` + "`?" + `(.*)`)
	sqlCompare = regexp.MustCompile(`(?i)\b(\w+)\s*=`)
	sqlVar     = regexp.MustCompile(`\$(\w+)`)
)

type plainDigestWrite struct {
	table, column string
	call          analysis.Evidence
	write         analysis.Evidence
}

// plainAccountSQL is the result of the static pass.
type plainAccountSQL struct {
	credentialTables  map[string]bool
	credentialColumns map[string]bool               // table.column written from a password hash or digest
	compared          map[string]analysis.Evidence  // table.column -> SELECT
	digestWrites      map[string][]plainDigestWrite // digest call file:byte -> writes in column order
	statements        map[string]string             // SQL argument file:byte -> statement text
}

// plainAssigned is a variable assigned from password_hash or a fast digest.
type plainAssigned struct {
	call    *sitter.Node
	digest  bool
	request bool
}

func plainSQLCall(m *phpModule, n *sitter.Node) *sitter.Node {
	args := phpArgs(n)
	switch n.Kind() {
	case "function_call_expression":
		switch strings.ToLower(phpText(m, phpField(n, "function"))) {
		case "mysqli_query", "mysqli_real_query", "mysqli_prepare":
			if len(args) >= 2 {
				return args[1]
			}
		}
	case "member_call_expression":
		switch strings.ToLower(phpText(m, phpField(n, "name"))) {
		case "query", "exec", "prepare":
			if len(args) >= 1 {
				return args[0]
			}
		}
	}
	return nil
}

func (s *phpSet) plainAccount() *plainAccountSQL {
	st := s.accountState()
	if st.plain != nil {
		return st.plain
	}
	out := &plainAccountSQL{credentialTables: map[string]bool{}, credentialColumns: map[string]bool{}, compared: map[string]analysis.Evidence{}, digestWrites: map[string][]plainDigestWrite{}, statements: map[string]string{}}
	st.plain = out
	for _, file := range s.files {
		m := s.modules[file]
		if m == nil || s.symfonyFile(file) {
			continue
		}
		out.readStatements(m, plainAssignments(m))
	}
	return out
}

// plainAssignments returns the variables of one file assigned from
// password_hash or a fast digest, and whether the digest input is a request
// value.
func plainAssignments(m *phpModule) map[string]plainAssigned {
	vars := map[string]plainAssigned{}
	requestVars := map[string]bool{}
	phpWalk(m.tree.RootNode(), func(n *sitter.Node) {
		if n.Kind() != "assignment_expression" {
			return
		}
		name := strings.TrimPrefix(phpText(m, phpField(n, "left")), "$")
		right := phpField(n, "right")
		if right == nil {
			return
		}
		if plainRequestText(phpText(m, right), requestVars) {
			requestVars[name] = true
		}
		if right.Kind() != "function_call_expression" {
			return
		}
		fn := strings.ToLower(strings.TrimPrefix(phpText(m, phpField(right, "function")), `\`))
		if fn == "password_hash" {
			vars[name] = plainAssigned{call: right}
			return
		}
		if algorithm, _ := digestAlgorithm(m, fn, phpArgs(right)); algorithm != "" {
			input := digestInput(fn, phpArgs(right))
			vars[name] = plainAssigned{call: right, digest: true, request: input != nil && plainRequestText(phpText(m, input), requestVars)}
		}
	})
	return vars
}

// readStatements reads the literal SQL statements of one file: the columns
// an INSERT or UPDATE writes from an assigned hash, and the columns a SELECT
// compares.
func (out *plainAccountSQL) readStatements(m *phpModule, vars map[string]plainAssigned) {
	phpWalk(m.tree.RootNode(), func(n *sitter.Node) {
		sqlNode := plainSQLCall(m, n)
		if sqlNode == nil {
			return
		}
		text := plainStatementText(m, sqlNode)
		out.statements[spanKey(parse.Span(m.file, sqlNode))] = text
		at := m.evidence("sql_statement", n)
		if g := sqlSelect.FindStringSubmatch(text); g != nil && sqlInsert.FindStringSubmatch(text) == nil && sqlUpdate.FindStringSubmatch(text) == nil {
			table := strings.ToLower(g[1])
			for _, field := range plainCompared(g[2]) {
				if _, ok := out.compared[table+"."+field]; !ok {
					out.compared[table+"."+field] = at
				}
			}
			return
		}
		table, pairs := plainWrites(text)
		for _, column := range slices.Sorted(maps.Keys(pairs)) {
			a, ok := vars[pairs[column]]
			if !ok {
				continue
			}
			out.credentialTables[table] = true
			out.credentialColumns[table+"."+column] = true
			if a.digest && a.request {
				call := m.evidence(analysis.PasswordHashKind, a.call)
				key := spanKey(call.Span)
				out.digestWrites[key] = append(out.digestWrites[key], plainDigestWrite{table: table, column: column, call: call, write: at})
			}
		}
	})
}

// plainStatementText returns the SQL text of a query-call argument. A
// variable reads the nearest preceding assignment of a string to it in the
// same function or file scope; any other right side leaves it unread.
func plainStatementText(m *phpModule, arg *sitter.Node) string {
	if arg.Kind() != "variable_name" {
		return phpText(m, arg)
	}
	name, scope := phpText(m, arg), plainScope(arg)
	var right *sitter.Node
	phpWalk(scope, func(n *sitter.Node) {
		if n.Kind() != "assignment_expression" || n.EndByte() > arg.StartByte() {
			return
		}
		if right != nil && n.StartByte() < right.StartByte() {
			return
		}
		if phpText(m, phpField(n, "left")) != name || plainScope(n).Id() != scope.Id() {
			return
		}
		right = phpField(n, "right")
	})
	for right != nil && right.Kind() == "parenthesized_expression" {
		right = right.NamedChild(0)
	}
	if right == nil {
		return phpText(m, arg)
	}
	switch right.Kind() {
	case "string", "encapsed_string", "binary_expression", "heredoc", "nowdoc":
		return phpText(m, right)
	}
	return phpText(m, arg)
}

// plainScope returns the function body or file that holds n.
func plainScope(n *sitter.Node) *sitter.Node {
	for p := n.Parent(); p != nil; p = p.Parent() {
		switch p.Kind() {
		case "function_definition", "method_declaration", "anonymous_function", "anonymous_function_creation_expression", "arrow_function":
			return p
		}
		n = p
	}
	return n
}

// plainWrites returns the table of an INSERT or UPDATE and the variable each
// column is written from.
func plainWrites(text string) (string, map[string]string) {
	pairs := map[string]string{} // column -> variable
	if g := sqlInsert.FindStringSubmatch(text); g != nil {
		cols, vals := strings.Split(g[2], ","), strings.Split(g[3], ",")
		for i := range cols {
			if i < len(vals) {
				if v := sqlVar.FindStringSubmatch(vals[i]); v != nil {
					pairs[strings.ToLower(strings.Trim(strings.TrimSpace(cols[i]), "`"))] = v[1]
				}
			}
		}
		return strings.ToLower(g[1]), pairs
	}
	if g := sqlUpdate.FindStringSubmatch(text); g != nil {
		for _, part := range strings.Split(g[2], ",") {
			if eq := strings.Index(part, "="); eq > 0 {
				if v := sqlVar.FindStringSubmatch(part[eq:]); v != nil {
					pairs[strings.ToLower(strings.Trim(strings.TrimSpace(part[:eq]), "`"))] = v[1]
				}
			}
		}
		return strings.ToLower(g[1]), pairs
	}
	return "", pairs
}

// plainCompared returns the columns a SELECT's WHERE clause compares, in
// statement order.
func plainCompared(rest string) []string {
	w := strings.Index(strings.ToUpper(rest), "WHERE")
	if w < 0 {
		return nil
	}
	var out []string
	for _, c := range sqlCompare.FindAllStringSubmatch(rest[w:], -1) {
		out = append(out, strings.ToLower(c[1]))
	}
	return out
}

// plainRequestText reports source text that reads a superglobal or a
// variable assigned from one.
func plainRequestText(text string, vars map[string]bool) bool {
	for _, g := range []string{"$_POST", "$_GET", "$_REQUEST", "$_COOKIE"} {
		if strings.Contains(text, g) {
			return true
		}
	}
	for _, v := range sqlVar.FindAllStringSubmatch(text, -1) {
		if vars[v[1]] {
			return true
		}
	}
	return false
}

func (s *phpSet) symfonyFile(file string) bool {
	for _, p := range s.symfony {
		if p.root == "" || p.root == "." || strings.HasPrefix(file, p.root+"/") || file == p.root {
			return true
		}
	}
	return false
}

// plainAccountCall handles a SQL lookup of plain PHP: the lookup of the
// recovery check and an enumeration candidate.
func (f *phpFlow) plainAccountCall(n *sitter.Node, values []phpValue) {
	if f.symfony != nil || f.report == nil {
		return
	}
	m := f.module
	sqlNode := plainSQLCall(m, n)
	if sqlNode == nil {
		return
	}
	plain := f.set.plainAccount()
	g := sqlSelect.FindStringSubmatch(plain.statements[spanKey(parse.Span(m.file, sqlNode))])
	if g == nil {
		return
	}
	table := strings.ToLower(g[1])
	if !plain.credentialTables[table] {
		return
	}
	var deps []phpDep
	for _, v := range values {
		deps = append(deps, phpInputDeps([]phpValue{v})...)
	}
	if len(deps) == 0 {
		return
	}
	f.noteAccountLookupAt(sqlNode, deps)
	credential := func(field string) bool { return plain.credentialColumns[table+"."+field] }
	f.noteEnumerationBranch(n, enumerationLookup{class: "table:" + table, method: "SELECT", fields: plainCompared(g[2]), deps: deps}, credential)
}

// plainDigest records a digest of a request value written to a SQL column
// that a login SELECT compares (sql_credential_column).
func (f *phpFlow) plainDigest(n *sitter.Node) {
	if f.symfony != nil || f.report == nil {
		return
	}
	plain := f.set.plainAccount()
	writes := plain.digestWrites[spanKey(parse.Span(f.module.file, n))]
	for _, w := range writes {
		compare, ok := plain.compared[w.table+"."+w.column]
		if !ok {
			continue
		}
		name := strings.ToLower(strings.TrimPrefix(phpText(f.module, phpField(n, "function")), `\`))
		nodes := phpArgs(n)
		algorithm, unmodeled := digestAlgorithm(f.module, name, nodes)
		d := &phpDigest{algorithm: algorithm, at: w.call, salted: phpSalted(f.module, digestInput(name, nodes)), unmodeled: unmodeled}
		facts := &analysis.PasswordHashFacts{Algorithm: algorithm, Basis: analysis.BasisSQLCredentialColumn, BasisEvidence: []analysis.Evidence{w.write, compare}, Salted: d.salted, Iterated: "no"}
		emitPasswordHash(f.report, f.entry.ID, f.invocation.ID, d, facts, f.context, f.gaps)
		return
	}
}
