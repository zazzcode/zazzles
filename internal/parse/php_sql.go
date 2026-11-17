package parse

import (
	"regexp"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
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
	if op != "pdo" && len(nodes) > 1 {
		// Procedural mysqli_* forms carry the connection first.
		queryNode, params = nodes[1], values[2:]
	}
	if op == "pdo" && len(values) > 1 {
		params = values[1:]
	}
	return f.sqlClaim(n, queryNode, params, text, driver, op, connection.evidence, nil)
}

// sqlClaim records the sql_query_candidate and returns the result value. The
// returned statement/result value carries the SQL text (sqlText) so a later
// execute() re-records construction-time taint, and the SELECT table/columns
// for storage linking when the text is constant.
func (f *phpFlow) sqlClaim(n *sitter.Node, queryNode *sitter.Node, params []phpValue, text phpValue, driver, op string, connectionEvidence, bindingControls []analysis.Evidence) phpValue {
	m := f.module
	all := phpSlot(text, "sql_text")
	for _, v := range params {
		all = phpCombine(all, phpSlot(v, "sql_parameters"))
	}
	textCopy := text
	result := phpValue{binding: "db_result", driver: driver, evidence: append([]analysis.Evidence{}, connectionEvidence...), sqlText: &textCopy, bindingControls: bindingControls}

	if constant, ok := phpSQLText(text); ok {
		if match := phpSelectRe.FindStringSubmatch(constant); len(match) > 0 {
			result.table = strings.ToLower(match[1])
			result.columns = selectColumns(match[0])
			result.evidence = append(result.evidence, m.evidence("storage_query", n))
		}
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
			fields = appendUniqueString(fields, d.key)
		}
	}
	entryPath := ""
	if f.entry.HTTP != nil {
		entryPath = f.entry.HTTP.Path
	}
	u.Check = &analysis.Check{ID: "automatic-php-query", Path: entryPath, Kind: "sql_query", Fields: fields, Validation: "Assess only requirements established by supplied server code and source-backed form-field policy. A browser form can declare a requirement but does not enforce it on direct HTTP requests. Missing business requirements remain uncertain.", Protection: "Request values must remain data and must not change SQL syntax. Bound values and dynamic identifiers are separate slots."}
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
	stmt := f.sqlClaim(n, queryNode, nil, text, driver, "prepare", connection.evidence, nil)
	stmt.binding = "db_statement"
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
	out := f.sqlClaim(n, n, stmt.sqlParams, text, stmt.driver, "execute", stmt.evidence, stmt.bindingControls)
	out.binding = "db_statement"
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
	if len(sqlTemplate) >= 2 {
		if q := sqlTemplate[0]; (q == '"' || q == '\'') && sqlTemplate[len(sqlTemplate)-1] == q {
			sqlTemplate = sqlTemplate[1 : len(sqlTemplate)-1]
		}
	}
	match := phpInsertRe.FindStringSubmatch(sqlTemplate)
	if match == nil || len(text.deps) == 0 {
		return
	}
	table := strings.ToLower(match[1])
	fields := strings.Split(match[2], ",")
	if len(text.deps) != len(fields) {
		return
	}
	for i, key := range fields {
		d := text.deps[i]
		storage := "php-sql:" + table + "." + strings.ToLower(strings.Trim(strings.TrimSpace(key), "`\"'[]"))
		v := phpValue{deps: []phpDep{d}}
		v = phpTransfer(v, f.module.evidence("storage_write", n))
		f.set.writes[storage] = append(f.set.writes[storage], phpWrite{value: v, entry: f.invocation.EntryID, evidence: f.module.evidence("storage_write", n)})
	}
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

// linkStorage links stored XSS storage keys to their writes (php-sql:).
func (s *phpSet) linkStorage(out *analysis.AnalysisReport) {
	for i := range out.Uses {
		u := &out.Uses[i]
		if u.XSS == nil {
			continue
		}
		var deps []analysis.Dependency
		var paths []analysis.XSSPath
		var related []string
		resolved := true
		stored := false
		for _, d := range u.Dependencies {
			if d.StorageKey == "" {
				deps = append(deps, d)
				continue
			}
			stored = true
			u.XSS.StorageKey = d.StorageKey
			writes := s.writes[d.StorageKey]
			if len(writes) == 0 {
				resolved = false
				deps = append(deps, d)
				continue
			}
			for _, w := range writes {
				related = appendUniqueString(related, w.entry)
				for _, source := range w.value.deps {
					nd := source.dep
					nd.StorageKey = d.StorageKey
					nd.Transfers = append(append([]analysis.Evidence{}, nd.Transfers...), d.Transfers...)
					deps = append(deps, nd)
					p := u.XSS.Protection
					if source.protection == "unknown" {
						p = "unknown"
					} else if p == "raw" && (source.protection == "encoded" || source.protection == "numeric" || source.protection == "non_content") {
						p = "encoded"
					}
					paths = append(paths, analysis.XSSPath{Dependency: len(deps) - 1, Entry: w.entry, Protection: p})
				}
			}
		}
		if stored {
			if len(deps) > 64 {
				deps = deps[:64]
				u.Gaps = append(u.Gaps, analysis.Gap{Kind: "dependency_limit", Detail: "Stored origin expansion exceeds 64 paths", At: u.Sink.Span})
				u.XSS.Protection = "unknown"
				resolved = false
			}
			u.Dependencies = deps
			u.XSS.Type = "stored"
			u.XSS.OriginResolved = resolved
			u.XSS.RelatedEntries = related
			if len(paths) > len(deps) {
				paths = paths[:len(deps)]
			}
			u.XSS.Paths = paths
			raw, unknown := false, false
			for _, p := range paths {
				raw = raw || p.Protection == "raw"
				unknown = unknown || p.Protection == "unknown"
			}
			if !raw && unknown {
				u.XSS.Protection = "unknown"
			}
			if len(paths) > 0 && !raw && !unknown && resolved {
				u.XSS.Protection = "encoded"
			}
			if !resolved {
				u.XSS.ProtectionReason += " Stored field origin is unresolved."
			}
		}
	}
}

// attachChecks mirrors the Python check attachment for PHP entries.
func (s *phpSet) attachChecks(out *analysis.AnalysisReport, checks []analysis.Check) {
	selected := []analysis.CandidateUse{}
	for _, old := range out.Uses {
		attached := false
		for _, check := range checks {
			if check.Kind != "sql_query" || old.Kind != "sql_query_candidate" || !checkContextMatches(out, check, old) {
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

func phpSlot(v phpValue, slot string) phpValue {
	v.deps = append([]phpDep{}, v.deps...)
	for i := range v.deps {
		v.deps[i].dep.SinkSlot = slot
	}
	return v
}
