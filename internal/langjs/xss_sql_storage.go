package langjs

import (
	"regexp"
	"sort"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/parse"
)

var (
	sqlSelect = regexp.MustCompile("(?is)^\\s*SELECT\\b.*?\\bFROM\\s+[\"'`]?(\\w+)")
	sqlInsert = regexp.MustCompile("(?is)^\\s*INSERT\\s+(?:OR\\s+\\w+\\s+)?INTO\\s+[\"'`]?(\\w+)[\"'`]?\\s*\\(([^)]*)\\)\\s*VALUES\\s*\\(([^)]*)\\)")
	sqlUpdate = regexp.MustCompile("(?is)^\\s*UPDATE\\s+[\"'`]?(\\w+)[\"'`]?\\s+SET\\s+(.*?)(?:\\bWHERE\\b|$)")
)

// sqlText returns the statement text of a literal, a template or a local name bound
// to one. A substitution stays in the text; only the table and columns are read.
func sqlText(m *sourceModule, n *sitter.Node, depth int) string {
	if n == nil || depth > 3 {
		return ""
	}
	if text, ok := stringLiteral(n, m.src); ok {
		return text
	}
	switch n.Kind() {
	case "template_string":
		return strings.Trim(n.Utf8Text(m.src), "`")
	case "identifier":
		return sqlText(m, definitionAt(m, n, n.Utf8Text(m.src)), depth+1)
	}
	return ""
}

// sqlJSDatabase reports a verified sql.js connection: the module imports sql.js and
// assigns the receiver from new <module>.Database(...).
func sqlJSDatabase(m *sourceModule, receiver string) bool {
	imported := false
	for _, imp := range m.imports {
		imported = imported || imp.module == "sql.js"
	}
	if !imported {
		return false
	}
	assigned := regexp.MustCompile(`\b` + regexp.QuoteMeta(receiver) + `\s*=\s*new\s+\w+\.Database\s*\(`)
	return assigned.Match(m.src)
}

func sqlJSCall(m *sourceModule, fn *sitter.Node) (string, bool) {
	if fn == nil || fn.Kind() != "member_expression" {
		return "", false
	}
	obj, prop := fn.ChildByFieldName("object"), fn.ChildByFieldName("property")
	if obj == nil || prop == nil || obj.Kind() != "identifier" || !sqlJSDatabase(m, obj.Utf8Text(m.src)) {
		return "", false
	}
	switch method := prop.Utf8Text(m.src); method {
	case "run", "exec", "prepare":
		return method, true
	}
	return "", false
}

// sqlJSBinding returns the import and statement call that verify a sql.js sink.
func (s *moduleSet) sqlJSBinding(use analysis.CandidateUse) []analysis.Evidence {
	m := s.modules[use.Sink.Span.File]
	if m == nil {
		return nil
	}
	call := parse.NodeAt(m.tree.RootNode(), use.Sink.Span.StartByte, use.Sink.Span.EndByte)
	if call == nil || call.Kind() != "call_expression" {
		return nil
	}
	if _, ok := sqlJSCall(m, call.ChildByFieldName("function")); !ok {
		return nil
	}
	out := []analysis.Evidence{m.evidence("sink_binding", call)}
	for _, imp := range m.imports {
		if imp.module == "sql.js" {
			out = append(out, m.evidence("sink_binding", imp.declaration))
		}
	}
	return out
}

// sqlHelper reports a local function that passes its first parameter to a verified
// statement call, directly or through one more local helper.
func (s *moduleSet) sqlHelper(m *sourceModule, call *sitter.Node, depth int) bool {
	if depth > 2 {
		return false
	}
	hm, helper := s.resolveCall(m, call)
	if hm == nil || helper == nil || !supportedCallee(helper) {
		return false
	}
	params, ok := functionParameters(helper, hm.src)
	if !ok || len(params) == 0 {
		return false
	}
	found := false
	walkCalls(helper.ChildByFieldName("body"), func(inner *sitter.Node) {
		fn, args := inner.ChildByFieldName("function"), inner.ChildByFieldName("arguments")
		if found || fn == nil || args == nil || args.NamedChildCount() == 0 || args.NamedChild(0).Utf8Text(hm.src) != params[0].name {
			return
		}
		if _, ok := sqlJSCall(hm, fn); ok {
			found = true
		} else if fn.Kind() == "identifier" {
			found = s.sqlHelper(hm, inner, depth+1)
		}
	})
	return found
}

func (f *flow) sqlRead(n, fn, args *sitter.Node) (string, *analysis.Evidence, bool) {
	if args.NamedChildCount() == 0 {
		return "", nil, false
	}
	match := sqlSelect.FindStringSubmatch(sqlText(f.module, args.NamedChild(0), 0))
	if match == nil {
		return "", nil, false
	}
	model := ""
	if _, ok := sqlJSCall(f.module, fn); ok || (fn.Kind() == "identifier" && f.set.sqlHelper(f.module, n, 0)) {
		model = "sql:" + strings.ToLower(match[1])
		f.set.rememberModel(model, []analysis.Evidence{f.module.evidence("storage_model_binding", n)})
	} else if strings.HasSuffix(fn.Utf8Text(f.module.src), "sequelize.query") {
		model = f.set.sequelizeTable(match[1])
	}
	if model == "" {
		return "", nil, false
	}
	e := f.module.evidence("storage_query", n)
	return model, &e, true
}

// sqlWrite records bound INSERT and UPDATE columns of a verified statement call.
func (f *flow) sqlWrite(n, fn, args *sitter.Node) {
	if args.NamedChildCount() < 2 {
		return
	}
	if method, ok := sqlJSCall(f.module, fn); !ok || method != "run" {
		return
	}
	bound := args.NamedChild(1)
	if bound.Kind() != "array" {
		return
	}
	text := sqlText(f.module, args.NamedChild(0), 0)
	table, columns := "", []string{}
	if match := sqlInsert.FindStringSubmatch(text); match != nil {
		table = match[1]
		names, slots := strings.Split(match[2], ","), strings.Split(match[3], ",")
		if len(names) != len(slots) {
			return
		}
		for i, slot := range slots {
			if strings.TrimSpace(slot) == "?" {
				columns = append(columns, strings.TrimSpace(names[i]))
			}
		}
	} else if match := sqlUpdate.FindStringSubmatch(text); match != nil {
		table = match[1]
		for _, assignment := range strings.Split(match[2], ",") {
			parts := strings.SplitN(assignment, "=", 2)
			if len(parts) == 2 && strings.TrimSpace(parts[1]) == "?" {
				columns = append(columns, strings.TrimSpace(parts[0]))
			}
		}
	}
	if table == "" {
		return
	}
	if f.set.storageWrites == nil {
		f.set.storageWrites = map[string][]storageWrite{}
	}
	for i, column := range columns {
		if uint(i) >= bound.NamedChildCount() {
			return
		}
		v := f.eval(bound.NamedChild(uint(i)))
		if len(v.deps) == 0 {
			continue
		}
		key := "sql:" + strings.ToLower(table) + "." + column
		f.set.storageWrites[key] = append(f.set.storageWrites[key], storageWrite{f.entry.ID, v, f.module.evidence("storage_write", n)})
	}
}

// sequelizeTable resolves a table name through Model.init's literal tableName option.
func (s *moduleSet) sequelizeTable(table string) string {
	if s.tableModels == nil {
		s.tableModels = map[string]string{}
		var files []string
		for file := range s.allowed {
			files = append(files, file)
		}
		sort.Strings(files)
		for _, file := range files {
			m, err := s.load(file)
			if err != nil || !strings.Contains(string(m.src), "tableName") {
				continue
			}
			walkCalls(m.tree.RootNode(), func(call *sitter.Node) {
				class, config := modelInit(m, call)
				if class == "" {
					return
				}
				args := call.ChildByFieldName("arguments")
				if args.NamedChildCount() < 2 {
					return
				}
				name, ok := stringLiteral(property(args.NamedChild(1), "tableName", m.src), m.src)
				if !ok || config == nil {
					return
				}
				if key := s.modelIdentity(m, class, 0); key != "" {
					s.tableModels[name] = key
				}
			})
		}
	}
	return s.tableModels[table]
}

// modelInit returns the class and attribute object of a Model.init(...) call.
func modelInit(m *sourceModule, call *sitter.Node) (string, *sitter.Node) {
	fn, args := call.ChildByFieldName("function"), call.ChildByFieldName("arguments")
	if fn == nil || args == nil || fn.Kind() != "member_expression" || args.NamedChildCount() == 0 {
		return "", nil
	}
	obj, prop := fn.ChildByFieldName("object"), fn.ChildByFieldName("property")
	if obj == nil || prop == nil || obj.Kind() != "identifier" || prop.Utf8Text(m.src) != "init" || args.NamedChild(0).Kind() != "object" {
		return "", nil
	}
	return obj.Utf8Text(m.src), args.NamedChild(0)
}

var (
	sqlWriteStatement = regexp.MustCompile(`(?is)\b(?:insert\s+(?:or\s+\w+\s+)?into|replace\s+into|update)\s+["'\x60]?(\w+)`)
	sqlCreateTable    = regexp.MustCompile(`(?is)\bcreate\s+table\s+(?:if\s+not\s+exists\s+)?["'\x60]?(\w+)`)
	sqlPlaceholder    = regexp.MustCompile(`\?|\$\d+|:\w+|@\w+`)
	staticReadCall    = regexp.MustCompile("^[\\w.$]+\\(\\s*(\"[^\"]*\"|'[^']*'|`[^`$]*`)\\s*[,)]")
)

// attachStoredWriteSets gives every record that reads a stored key its write
// census: each write statement found in scanned source for the key, whether
// its values are literals, whether the read query is static and whether the
// store is closed. The shared parse rule keeps the facts only on records whose
// stored origin stays unresolved. Nothing here changes a dependency or status.
func (s *moduleSet) attachStoredWriteSets(report *analysis.AnalysisReport) {
	tables := map[string]*sqlTableCensus{}
	for i := range report.Uses {
		u := &report.Uses[i]
		var stores []analysis.StoredWriteSet
		seen := map[string]bool{}
		for _, d := range u.Dependencies {
			// A file read is not a written store; its origin gap stands alone.
			if d.StorageKey == "" || strings.HasPrefix(d.StorageKey, "file:") || seen[d.StorageKey] {
				continue
			}
			seen[d.StorageKey] = true
			set := analysis.StoredWriteSet{Key: d.StorageKey, Writes: []analysis.StoredWrite{}, ClosedStore: "unknown", StaticRead: staticRead(d)}
			if table, ok := sqlTable(d.StorageKey); ok {
				census := tables[table]
				if census == nil {
					census = s.sqlCensus(table)
					tables[table] = census
				}
				set.Writes = append(set.Writes, census.writes...)
				set.Schema, set.ClosedStore = census.schema, census.closed
			}
			for _, w := range s.storageWrites[d.StorageKey] {
				if !containsWrite(set.Writes, w.sink) {
					set.Writes = append(set.Writes, analysis.StoredWrite{Evidence: w.sink, Literal: len(w.value.deps) == 0})
				}
			}
			stores = append(stores, set)
		}
		if len(stores) > 0 {
			u.StoredOrigin = &analysis.StoredOriginFacts{Stores: stores}
		}
	}
}

type sqlTableCensus struct {
	writes []analysis.StoredWrite
	schema *analysis.Evidence
	closed string
}

func sqlTable(key string) (string, bool) {
	if !strings.HasPrefix(key, "sql:") {
		return "", false
	}
	table, _, ok := strings.Cut(strings.TrimPrefix(key, "sql:"), ".")
	return table, ok && table != ""
}

// staticRead reports a stored dependency read by a query call whose first
// argument is one string literal with no substitution.
func staticRead(d analysis.Dependency) bool {
	for _, t := range d.Transfers {
		if t.Kind == "storage_query" {
			return staticReadCall.MatchString(strings.TrimSpace(t.Text))
		}
	}
	return false
}

func containsWrite(writes []analysis.StoredWrite, e analysis.Evidence) bool {
	for _, w := range writes {
		if w.Evidence.Span.File == e.Span.File && w.Evidence.Span.StartByte <= e.Span.StartByte && e.Span.EndByte <= w.Evidence.Span.EndByte {
			return true
		}
		if e.Span.File == w.Evidence.Span.File && e.Span.StartByte <= w.Evidence.Span.StartByte && w.Evidence.Span.EndByte <= e.Span.EndByte {
			return true
		}
	}
	return false
}

// sqlCensus finds, in every loaded module, the SQL text that writes or
// creates table. A write is literal when its text has no placeholder,
// substitution or concatenation. The store is closed when its schema is in
// source and the database is an in-memory sql.js database created there.
func (s *moduleSet) sqlCensus(table string) *sqlTableCensus {
	c := &sqlTableCensus{closed: "open"}
	var files []string
	for file := range s.modules {
		files = append(files, file)
	}
	sort.Strings(files)
	inMemory := false
	for _, file := range files {
		m := s.modules[file]
		var walk func(n *sitter.Node)
		walk = func(n *sitter.Node) {
			if n == nil {
				return
			}
			switch n.Kind() {
			case "new_expression":
				ctor, args := n.ChildByFieldName("constructor"), n.ChildByFieldName("arguments")
				if ctor != nil && strings.HasSuffix(ctor.Utf8Text(m.src), "Database") && (args == nil || args.NamedChildCount() == 0) {
					inMemory = true
				}
			case "string", "template_string":
				text, literal := sqlLiteralText(m, n)
				for _, match := range sqlCreateTable.FindAllStringSubmatch(text, -1) {
					if strings.EqualFold(match[1], table) && c.schema == nil {
						e := m.evidence("storage_schema", n)
						c.schema = &e
					}
				}
				for _, match := range sqlWriteStatement.FindAllStringSubmatch(text, -1) {
					if strings.EqualFold(match[1], table) {
						c.writes = append(c.writes, analysis.StoredWrite{Evidence: m.evidence("storage_write", n), Literal: literal && !sqlPlaceholder.MatchString(stripSQLStrings(text))})
						break
					}
				}
				return
			}
			for i := uint(0); i < n.NamedChildCount(); i++ {
				walk(n.NamedChild(i))
			}
		}
		walk(m.tree.RootNode())
	}
	if c.schema != nil {
		c.closed = "unknown"
		if inMemory {
			c.closed = "closed"
		}
	}
	return c
}

// sqlLiteralText returns the text of a string or template and whether it is
// a whole literal: no substitution and not one operand of a concatenation.
func sqlLiteralText(m *sourceModule, n *sitter.Node) (string, bool) {
	literal := n.Parent() == nil || n.Parent().Kind() != "binary_expression"
	if n.Kind() == "string" {
		text, _ := stringLiteral(n, m.src)
		return text, literal
	}
	var b strings.Builder
	for i := uint(0); i < n.NamedChildCount(); i++ {
		child := n.NamedChild(i)
		if child.Kind() == "template_substitution" {
			literal = false
			b.WriteString("${}")
			continue
		}
		b.WriteString(child.Utf8Text(m.src))
	}
	return b.String(), literal
}

// stripSQLStrings removes quoted SQL string values so a ':' or '?' inside a
// literal value is not read as a placeholder.
func stripSQLStrings(text string) string {
	return regexp.MustCompile(`'(?:[^']|'')*'`).ReplaceAllString(text, "''")
}
