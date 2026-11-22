package langphp

import (
	"regexp"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

// Plain-PHP account evidence (branch 3 D-2 plain row, D-8
// sql_credential_column). A static pass over literal SQL text finds the
// tables a statement writes from password_hash or a fast digest, and the
// columns a SELECT compares.

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
	credentialTables map[string]bool
	compared         map[string]analysis.Evidence // table.column -> SELECT
	digestWrites     map[string]plainDigestWrite  // digest call file:byte -> write
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
	out := &plainAccountSQL{credentialTables: map[string]bool{}, compared: map[string]analysis.Evidence{}, digestWrites: map[string]plainDigestWrite{}}
	st.plain = out
	for _, file := range s.files {
		m := s.modules[file]
		if m == nil || s.symfonyFile(file) {
			continue
		}
		type assigned struct {
			call    *sitter.Node
			digest  bool
			request bool
		}
		vars := map[string]assigned{}
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
			text := phpText(m, right)
			if plainRequestText(text, requestVars) {
				requestVars[name] = true
			}
			if right.Kind() != "function_call_expression" {
				return
			}
			fn := strings.ToLower(strings.TrimPrefix(phpText(m, phpField(right, "function")), `\`))
			if fn == "password_hash" {
				vars[name] = assigned{call: right}
				return
			}
			if algorithm, _ := digestAlgorithm(m, fn, phpArgs(right)); algorithm != "" {
				input := digestInput(fn, phpArgs(right))
				vars[name] = assigned{call: right, digest: true, request: input != nil && plainRequestText(phpText(m, input), requestVars)}
			}
		})
		phpWalk(m.tree.RootNode(), func(n *sitter.Node) {
			sqlNode := plainSQLCall(m, n)
			if sqlNode == nil {
				return
			}
			text := phpText(m, sqlNode)
			at := m.evidence("sql_statement", n)
			pairs := map[string]string{} // column -> variable
			table := ""
			if g := sqlInsert.FindStringSubmatch(text); g != nil {
				table = strings.ToLower(g[1])
				cols, vals := strings.Split(g[2], ","), strings.Split(g[3], ",")
				for i := range cols {
					if i < len(vals) {
						if v := sqlVar.FindStringSubmatch(vals[i]); v != nil {
							pairs[strings.ToLower(strings.Trim(strings.TrimSpace(cols[i]), "`"))] = v[1]
						}
					}
				}
			} else if g := sqlUpdate.FindStringSubmatch(text); g != nil {
				table = strings.ToLower(g[1])
				for _, part := range strings.Split(g[2], ",") {
					if eq := strings.Index(part, "="); eq > 0 {
						if v := sqlVar.FindStringSubmatch(part[eq:]); v != nil {
							pairs[strings.ToLower(strings.Trim(strings.TrimSpace(part[:eq]), "`"))] = v[1]
						}
					}
				}
			} else if g := sqlSelect.FindStringSubmatch(text); g != nil {
				table = strings.ToLower(g[1])
				if w := strings.Index(strings.ToUpper(g[2]), "WHERE"); w >= 0 {
					for _, c := range sqlCompare.FindAllStringSubmatch(g[2][w:], -1) {
						key := table + "." + strings.ToLower(c[1])
						if _, ok := out.compared[key]; !ok {
							out.compared[key] = at
						}
					}
				}
				return
			}
			for column, name := range pairs {
				a, ok := vars[name]
				if !ok {
					continue
				}
				out.credentialTables[table] = true
				if a.digest && a.request {
					call := m.evidence(analysis.PasswordHashKind, a.call)
					out.digestWrites[spanKey(call.Span)] = plainDigestWrite{table: table, column: column, call: call, write: at}
				}
			}
		})
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
	g := sqlSelect.FindStringSubmatch(phpText(m, sqlNode))
	if g == nil {
		return
	}
	table := strings.ToLower(g[1])
	if !f.set.plainAccount().credentialTables[table] {
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
	var fields []string
	if w := strings.Index(strings.ToUpper(g[2]), "WHERE"); w >= 0 {
		for _, c := range sqlCompare.FindAllStringSubmatch(g[2][w:], -1) {
			fields = append(fields, strings.ToLower(c[1]))
		}
	}
	branch, foundOnTrue := lookupBranch(m, n)
	if branch == nil {
		return
	}
	trueSide, falseSide := branchSides(m, branch)
	found, notFound := trueSide, falseSide
	if !foundOnTrue {
		found, notFound = falseSide, trueSide
	}
	if sameResponses(found, notFound) {
		return
	}
	f.emitEnumeration(n, branch, "table:"+table, "SELECT", fields, deps, found, notFound, nil)
}

// plainDigest records a digest of a request value written to a SQL column
// that a login SELECT compares (sql_credential_column).
func (f *phpFlow) plainDigest(n *sitter.Node) {
	if f.symfony != nil || f.report == nil {
		return
	}
	plain := f.set.plainAccount()
	call := f.module.evidence(analysis.PasswordHashKind, n)
	w, ok := plain.digestWrites[spanKey(call.Span)]
	if !ok {
		return
	}
	compare, ok := plain.compared[w.table+"."+w.column]
	if !ok {
		return
	}
	name := strings.ToLower(strings.TrimPrefix(phpText(f.module, phpField(n, "function")), `\`))
	nodes := phpArgs(n)
	algorithm, unmodeled := digestAlgorithm(f.module, name, nodes)
	d := &phpDigest{algorithm: algorithm, at: call, salted: phpSalted(f.module, digestInput(name, nodes)), unmodeled: unmodeled}
	facts := &analysis.PasswordHashFacts{Algorithm: algorithm, Basis: analysis.BasisSQLCredentialColumn, BasisEvidence: []analysis.Evidence{w.write, compare}, Salted: d.salted, Iterated: "no"}
	emitPasswordHash(f.report, f.entry.ID, f.invocation.ID, d, facts, f.context, f.gaps)
}
