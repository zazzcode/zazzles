package langphp

import (
	"regexp"
	"sort"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
	"github.com/zazzcode/zazzles/scan/internal/parse"
)

var phpSelectRe = regexp.MustCompile(`(?is)^\s*select\s+.+?\s+from\s+([a-zA-Z_][a-zA-Z0-9_]*)\b`)

var phpInsertRe = regexp.MustCompile(`(?is)^\s*insert\s+into\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(([^)]+)\)\s*values\s*\((.*)\)\s*;?\s*$`)

var phpUpdateRe = regexp.MustCompile(`(?is)^\s*update\s+([a-zA-Z_][a-zA-Z0-9_]*)\s+set\s+(.+?)\s+where\b`)

// phpSQLText extracts the constant SQL text of a value, if fully literal.
func phpSQLText(v phpValue) (string, bool) {
	if len(v.literals) == 1 && v.constant && len(v.deps) == 0 {
		return v.literals[0].text, true
	}
	return "", false
}

// sql models a direct query/exec call. connection provenance must be verified
// (a bound connection or the procedural mysqli idiom); shadowed functions were
// already excluded by the caller.
func (f *phpFlow) sql(n *sitter.Node, nodes []*sitter.Node, values []phpValue, connection phpValue, text phpValue, op string) phpValue {
	driver := connection.driver
	if driver == "" {
		driver = "mysqli" // procedural form carries its own engine
	}
	if connection.binding != "db_connection" && connection.binding != "" {
		return sliceFrom(values, 0)
	}
	queryNode, params := nodes[0], []phpValue{}
	if strings.HasPrefix(op, "mysqli_") && len(nodes) > 1 {
		// Procedural mysqli_* forms carry the connection first; the OO
		// ->query($sql, $mode) form carries the SQL first.
		queryNode, params = nodes[1], values[2:]
	}
	if op == "pdo" && len(values) > 1 {
		params = values[1:]
	}
	return f.sqlClaim(n, queryNode, params, text, driver, op, connection.evidence, nil, nil)
}

// sqlClaim records the sql_query_candidate and returns the result value. The
// returned statement/result value carries the SQL text (sqlText) so a later
// execute() re-records construction-time taint, and the SELECT table/columns
// for storage linking when the text is constant.
func (f *phpFlow) sqlClaim(n *sitter.Node, queryNode *sitter.Node, params []phpValue, text phpValue, driver, op string, connectionEvidence, bindingControls, preparedText []analysis.Evidence) phpValue {
	m := f.module
	all := phpSlot(text, "sql_text")
	for _, v := range params {
		all = phpCombine(all, phpSlot(v, "sql_parameters"))
	}
	textCopy := text
	result := phpValue{binding: "db_result", driver: driver, evidence: append([]analysis.Evidence{}, connectionEvidence...), sqlText: &textCopy, bindingControls: bindingControls}
	if queryNode != nil && op != "execute" {
		result.sqlTextEvidence = []analysis.Evidence{m.evidence("query_text", queryNode)}
	}

	f.notePlainSQL(n, text)
	if constant, ok := phpSQLText(text); ok {
		if match := phpSelectRe.FindStringSubmatch(constant); len(match) > 0 {
			result.table = strings.ToLower(match[1])
			result.columns = selectColumns(match[0])
			result.evidence = append(result.evidence, m.evidence("storage_query", n))
		}
	} else if match := phpSelectRe.FindStringSubmatch(phpUnquote(text.template)); len(match) > 0 && !strings.ContainsAny(match[1], "${") {
		// An interpolated SELECT (`... FROM task WHERE id = $id`) still reads
		// a literal table: rows stay stored values instead of vanishing.
		result.table = strings.ToLower(match[1])
		result.columns = selectColumns(match[0])
		result.evidence = append(result.evidence, m.evidence("storage_query", n))
	}
	// Inline interpolated writes expose the value's raw template for
	// storage-key attribution.
	f.storageWrite(n, text, queryNode, m)
	if len(all.deps) == 0 && !text.built {
		return result
	}
	u := f.addUse("sql_query_candidate", n, all)
	binding := append([]analysis.Evidence{}, connectionEvidence...)
	binding = append(binding, m.evidence("sink_binding", phpCallee(n)))
	u.Context = append(u.Context, binding...)
	u.Context = append(u.Context, bindingControls...)
	u.APIModel = analysispacks.PHPSQLContract(driver)
	if text.built {
		u.Gaps = append(u.Gaps, f.gap("query_text_interpolated", "PHP string interpolation constructs executable SQL text", n))
	}
	for _, d := range all.deps {
		kind := "input_validation_absent"
		if d.protection == "numeric" {
			kind = "validation_type_only"
		}
		u.Gaps = append(u.Gaps, f.gap(kind, "No complete business-policy enforcement established for "+d.container+"."+d.key, n))
	}
	c := &analysis.Completeness{ClaimKind: "injection", Required: []string{"input_source", "sink_binding", "invoked_callable", "control_flow"}, Evidence: map[string][]analysis.Evidence{"sink_binding": binding, "invoked_callable": {f.entryEvidence()}, "control_flow": append([]analysis.Evidence{m.evidence("operation", n)}, f.context...)}, Blockers: []analysis.Gap{}, Coverage: append([]analysis.Gap{}, u.Gaps...), Scope: "Bounded PHP source-to-operation flow; SQL text and bound parameters have separate roles."}
	for _, d := range all.deps {
		if d.dep.Source.Kind == "input_source" || d.dep.Source.Kind == "storage_source" {
			c.Evidence["input_source"] = append(c.Evidence["input_source"], d.dep.Source)
		}
	}
	if queryNode != nil {
		c.Evidence["query_text"] = []analysis.Evidence{m.evidence("query_text", queryNode)}
	}
	if op == "execute" && len(preparedText) > 0 {
		// execute() runs the prepared statement: its text is the query text.
		c.Evidence["query_text"] = append([]analysis.Evidence{}, preparedText...)
		u.Context = append(u.Context, preparedText...)
	}
	for _, g := range append(append([]analysis.Gap{}, f.gaps...), append(text.gaps, all.gaps...)...) {
		switch g.Kind {
		case "php_parameter_unresolved", "php_value_unresolved", "php_call_unresolved", "php_loop_unresolved", "php_expression_unresolved", "php_global_unresolved", "work_limit", "dependency_limit", "transfer_limit":
			c.Blockers = append(c.Blockers, g)
		}
	}
	if text.built && len(text.deps) == 0 {
		c.Blockers = append(c.Blockers, f.gap("query_structure_unresolved", "Dynamic SQL structure/key restrictions are not resolved", n))
	}
	fields := []string{}
	for _, d := range all.deps {
		if d.key != "" {
			fields = parse.AppendUniqueString(fields, d.key)
		}
	}
	entryPath := ""
	if f.entry.HTTP != nil {
		entryPath = f.entry.HTTP.Path
	}
	u.Check = &analysis.Check{ID: "automatic-php-query", Path: entryPath, Kind: "sql_query", Fields: fields, Validation: "Assess only requirements established by supplied server code and source-backed form-field policy. A browser form can declare a requirement but does not enforce it on direct HTTP requests. Missing business requirements remain uncertain.", Protection: "Request values must remain data and must not change SQL syntax. Bound values and dynamic identifiers are separate slots."}
	// Bound parameters are data whoever wrote them; only constructed SQL text
	// needs a request-linked writer before a stored value can inject.
	var constructed []phpDep
	for _, d := range all.deps {
		if d.dep.SinkSlot == "sql_text" {
			constructed = append(constructed, d)
		}
	}
	if stored := phpStoredOnlyBlockers(constructed, u.Sink.Span); len(stored) > 0 {
		c.Blockers = append(c.Blockers, stored...)
		f.set.storedOnly[u.ID] = phpStoredKeys(constructed)
	}
	c.ModelFacts = append(c.ModelFacts, phpSQLFacts(text)...)
	u.Completeness = c
	return result
}

// entryEvidence records invoked_callable evidence on the entry module, whose
// tree stays valid while f.module points at a helper's module.
func (f *phpFlow) entryEvidence() analysis.Evidence {
	if f.entryModule == nil {
		return analysis.Evidence{}
	}
	return f.entryModule.evidence("invoked_callable", f.entryModuleRoot)
}

// sqlPrepare models prepare(): the statement keeps SQL text provenance; the
// claim records the construction at prepare time and binding controls at
// bind/execute time.
func (f *phpFlow) sqlPrepare(n *sitter.Node, nodes []*sitter.Node, values []phpValue, connection phpValue, text phpValue, driver, _ string) phpValue {
	queryNode := nodes[0]
	if len(nodes) > 1 && connection.binding == "db_connection" && driver == "mysqli" {
		queryNode = nodes[1]
	}
	stmt := f.sqlClaim(n, queryNode, nil, text, driver, "prepare", connection.evidence, nil, nil)
	stmt.binding = "db_statement"
	// The prepare call, with the variable it is assigned to, is what makes the
	// query text this statement's text; an execute() claim carries it so the
	// judge sees the literal, the bindings and the execution as one statement.
	prepared := n
	if p := n.Parent(); p != nil && p.Kind() == "assignment_expression" {
		prepared = p
	}
	stmt.sqlTextEvidence = append([]analysis.Evidence{f.module.evidence("statement_preparation", prepared)}, stmt.sqlTextEvidence...)
	return stmt
}

// sqlExecPrepared re-records the execution when the prepared text carried
// request-derived construction.
func (f *phpFlow) sqlExecPrepared(n *sitter.Node, stmt phpValue) phpValue {
	text := phpValue{}
	if stmt.sqlText != nil {
		text = *stmt.sqlText
	}
	requestDerived := text.built
	for _, p := range stmt.sqlParams {
		if len(p.deps) > 0 {
			requestDerived = true
		}
	}
	if !requestDerived {
		return stmt
	}
	out := f.sqlClaim(n, n, stmt.sqlParams, text, stmt.driver, "execute", stmt.evidence, stmt.bindingControls, stmt.sqlTextEvidence)
	out.binding = "db_statement"
	out.sqlTextEvidence = stmt.sqlTextEvidence
	return out
}

// sqlFetch models fetch*: the returned row carries table/column storage keys.
func (f *phpFlow) sqlFetch(n *sitter.Node, result phpValue) phpValue {
	v := result
	v.binding = "db_row"
	v.driver = result.driver
	v.evidence = append(v.evidence, f.module.evidence("storage_read", n))
	v.literals = nil
	v.constant = false
	v.sqlText = nil
	v.sqlTextEvidence = nil
	v.fields = nil
	return v
}

// storageWrite indexes INSERT column writes for stored XSS linking. The raw
// statement template supplies the table/columns; values are attributed by
// interpolation position only when the counts match exactly — no invented
// origins when they do not.
func (f *phpFlow) storageWrite(n *sitter.Node, text phpValue, queryNode *sitter.Node, m *phpModule) {
	sqlTemplate := text.template
	if sqlTemplate == "" && queryNode != nil && (queryNode.Kind() == "string" || queryNode.Kind() == "encapsed_string") {
		sqlTemplate = phpText(m, queryNode)
	}
	seen := map[string]bool{}
	for _, w := range append([]phpSQLWrite{{template: sqlTemplate, deps: text.deps}}, text.sqlWrites...) {
		if seen[w.template] {
			continue
		}
		seen[w.template] = true
		columns := phpWriteColumns(phpUnquote(w.template), w.deps)
		for _, storage := range sortedStorageKeys(columns) {
			v := phpTransfer(phpValue{deps: []phpDep{columns[storage]}}, f.module.evidence("storage_write", n))
			f.set.writes[storage] = append(f.set.writes[storage], phpWrite{value: v, entry: f.invocation.EntryID, evidence: f.module.evidence("storage_write", n)})
		}
	}
}

func sortedStorageKeys(m map[string]phpDep) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

var phpInterpolationRe = regexp.MustCompile(`\{?\$[A-Za-z_]`)

// phpWriteColumns attributes interpolated dependencies to the storage keys of
// an INSERT column list or UPDATE SET list. Attribution is exact-count-or-skip:
// every interpolation must map to exactly one column, otherwise no origin is
// invented and the reads stay unresolved.
func phpWriteColumns(template string, deps []phpDep) map[string]phpDep {
	if len(deps) == 0 {
		return nil
	}
	column := func(table, key string) string {
		return "php-sql:" + table + "." + strings.ToLower(strings.Trim(strings.TrimSpace(key), "`\"'[]"))
	}
	out := map[string]phpDep{}
	if match := phpInsertRe.FindStringSubmatch(template); match != nil {
		table := strings.ToLower(match[1])
		fields := strings.Split(match[2], ",")
		if len(deps) != len(fields) {
			return nil
		}
		for i, key := range fields {
			out[column(table, key)] = deps[i]
		}
		return out
	}
	match := phpUpdateRe.FindStringSubmatch(template)
	if match == nil || len(phpInterpolationRe.FindAllString(template, -1)) != len(deps) {
		return nil
	}
	table, next := strings.ToLower(match[1]), 0
	for _, assignment := range strings.Split(match[2], ",") {
		key, value, ok := strings.Cut(assignment, "=")
		if !ok {
			return nil
		}
		switch len(phpInterpolationRe.FindAllString(value, -1)) {
		case 0:
		case 1:
			out[column(table, key)] = deps[next]
			next++
		default:
			return nil
		}
	}
	return out
}

// phpUnquote strips one pair of matching outer quotes from a source template.
func phpUnquote(t string) string {
	if len(t) >= 2 {
		if q := t[0]; (q == '"' || q == '\'') && t[len(t)-1] == q {
			return t[1 : len(t)-1]
		}
	}
	return t
}

// selectColumns extracts the column list of a SELECT header (bounded).
func selectColumns(header string) []string {
	s := strings.TrimSpace(header)
	s = strings.TrimPrefix(strings.ToLower(s), "select")
	idx := strings.Index(strings.ToLower(s), " from ")
	if idx < 0 {
		return nil
	}
	list := s[:idx]
	parts := strings.Split(list, ",")
	var out []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" || strings.ContainsAny(p, "*()'") {
			return nil
		}
		if as := strings.Split(p, " "); len(as) > 1 {
			p = as[len(as)-1]
		}
		out = append(out, strings.ToLower(strings.Trim(p, "`\"'[]")))
	}
	return out
}

// linkStorage links stored XSS reads to their writes once every entry was
// analyzed: SQL keys (php-sql:) to INSERT/UPDATE writes and session keys
// (php-session:) to $_SESSION writes from any entry. Each stored path starts
// from its own render protection. A record whose stored origin stays
// unresolved but which also carries a direct raw request path remains a
// reflected claim: the raw witness is scoped to its own path and the
// unresolved stored siblings stay visible instead of vetoing it.
func (s *phpSet) linkStorage(out *analysis.AnalysisReport) {
	projects := s.storageProjectIndex(out)
	kept := out.Uses[:0]
	defer func() { out.Uses = kept }()
	for i := range out.Uses {
		u := &out.Uses[i]
		if u.XSS == nil {
			kept = append(kept, *u)
			continue
		}
		own, ownContext := map[int]string{}, map[int]string{}
		for _, p := range u.XSS.Paths {
			own[p.Dependency] = p.Protection
			ownContext[p.Dependency] = p.OutputContext
		}
		var deps []analysis.Dependency
		var paths []analysis.XSSPath
		var related []string
		resolved, stored, directRaw := true, false, false
		// The record's storage key names its first raw stored path, else its
		// first stored read, independent of dependency order otherwise.
		firstKey, rawKey := "", ""
		context := ""
		add := func(d analysis.Dependency, entry, protection string) {
			deps = append(deps, d)
			paths = append(paths, analysis.XSSPath{Dependency: len(deps) - 1, Entry: entry, Protection: protection, OutputContext: context})
		}
		for j, d := range u.Dependencies {
			read := own[j]
			// A stored path lands where its read lands (judge evidence quality O).
			context = ownContext[j]
			pathContext := u.XSS.OutputContext
			if context != "" {
				pathContext = context
			}
			if d.StorageKey == "" {
				directRaw = directRaw || read == "raw"
				add(d, "", read)
				continue
			}
			session := strings.HasPrefix(d.StorageKey, "php-session:")
			if session && d.Source.Kind != "storage_source" {
				// A write source source() linked at read time; the complete
				// session writer set is linked below.
				continue
			}
			stored = true
			if firstKey == "" {
				firstKey = d.StorageKey
			}
			writes := s.scopedStorageWrites(d.StorageKey, u.EntryID, projects)
			if len(writes) == 0 && strings.HasPrefix(d.StorageKey, "php-session:flash.") && s.flashStoreClosed() {
				// No addFlash call writes this type and nothing else in the
				// project reaches the flash bag, so the read carries no value.
				continue
			}
			if len(writes) == 0 {
				resolved = false
				add(d, "", read)
				continue
			}
			for _, w := range writes {
				related = parse.AppendUniqueString(related, w.entry)
				for _, source := range w.value.deps {
					nd := source.dep
					nd.StorageKey = d.StorageKey
					nd.Transfers = append(append([]analysis.Evidence{}, nd.Transfers...), d.Transfers...)
					protection := phpStoredPathProtection(read, source.protection, pathContext)
					if protection == "raw" && rawKey == "" {
						rawKey = d.StorageKey
					}
					add(nd, w.entry, protection)
				}
			}
		}
		if !stored {
			kept = append(kept, *u)
			continue
		}
		if len(deps) == 0 {
			// Every writer of every stored value is server-generated: the
			// render has no request-derived content, like any render whose
			// value carries no dependency.
			continue
		}
		if len(deps) > 64 {
			deps = deps[:64]
			paths = paths[:64]
			u.Gaps = append(u.Gaps, analysis.Gap{Kind: "dependency_limit", Detail: "Stored origin expansion exceeds 64 paths", At: u.Sink.Span})
			u.XSS.Protection = "unknown"
			resolved = false
		}
		u.Dependencies = deps
		u.XSS.Paths = paths
		u.XSS.OutputContext = recordContext(paths, u.XSS.OutputContext)
		u.XSS.StorageKey = firstKey
		if rawKey != "" {
			u.XSS.StorageKey = rawKey
		}
		u.XSS.OriginResolved = resolved
		u.XSS.RelatedEntries = related
		// The type names the witness: a raw linked stored path makes a stored
		// claim; otherwise a direct raw request path keeps it reflected, with
		// resolved or unresolved stored siblings visible in its paths.
		u.XSS.Type = "stored"
		if rawKey == "" && directRaw {
			u.XSS.Type = "reflected"
		}
		raw, unknown := false, false
		for _, p := range paths {
			raw = raw || p.Protection == "raw"
			unknown = unknown || p.Protection == "unknown"
		}
		initialProtection := u.XSS.Protection
		switch {
		case raw:
			u.XSS.Protection = "raw"
		case unknown:
			u.XSS.Protection = "unknown"
		case len(paths) > 0 && resolved:
			u.XSS.Protection = "encoded"
		}
		if u.XSS.Protection != initialProtection {
			switch u.XSS.Protection {
			case "unknown":
				u.XSS.ProtectionReason = "Protection for a linked source path in its render context remains unresolved."
			case "encoded":
				u.XSS.ProtectionReason = "Every linked source path carries protection for its render context."
			}
		}
		if !resolved {
			u.XSS.ProtectionReason += " Stored field origin is unresolved."
		}
		kept = append(kept, *u)
	}
}

// phpStoredPathProtection combines a stored read's own render protection with
// the protection its writer applied before storage.
func phpStoredPathProtection(read, written, context string) string {
	switch {
	case read != "raw":
		return read
	case written == "url_encoded" || written == "encoded":
		return phpRenderProtection(written, context)
	case written == "unknown" || written == phpUnwritten || written == phpShellDenylist:
		return "unknown"
	case written == "numeric" || written == "non_content":
		return "encoded"
	}
	return "raw"
}

// attachChecks mirrors the Python check attachment for PHP entries.
func (s *phpSet) attachChecks(out *analysis.AnalysisReport, checks []analysis.Check) {
	selected := []analysis.CandidateUse{}
	for _, old := range out.Uses {
		attached := false
		for _, check := range checks {
			if check.Kind != "sql_query" || old.Kind != "sql_query_candidate" || !parse.CheckContextMatches(out, check, old) {
				continue
			}
			fieldMatch := false
			for _, d := range old.Dependencies {
				for _, field := range check.Fields {
					fieldMatch = fieldMatch || d.Source.Text == field || strings.HasPrefix(d.Source.Text, field+":")
					for _, transfer := range d.Transfers {
						fieldMatch = fieldMatch || (transfer.Kind == "field_projection" && transfer.Text == field)
					}
				}
			}
			if !fieldMatch {
				continue
			}
			for _, entry := range out.Entries {
				if entry.ID == old.EntryID && check.NormalizedSelector().Matches(entry) {
					use := old
					c := check
					use.Check = &c
					use.ID += "/" + check.ID
					selected = append(selected, use)
					attached = true
				}
			}
		}
		if !attached {
			selected = append(selected, old)
		}
	}
	out.Uses = selected
}
