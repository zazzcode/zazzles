package report

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

var jinjaSafeFilter = regexp.MustCompile(`\|\s*safe\b`)
var jqueryListAppend = regexp.MustCompile(`^\s*([A-Za-z_$][A-Za-z0-9_$]*)\.append\(\s*['"]<li>['"]\s*\+\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*\+\s*['"]</li>['"]\s*\)\s*$`)
var simplePythonInterpolation = regexp.MustCompile(`\{([A-Za-z_][A-Za-z0-9_.]*)\}`)
var pythonPercentOperand = regexp.MustCompile(`^\s*%\s*([A-Za-z_][A-Za-z0-9_.]*)\s*\)?\s*$`)

func sqliteGuidance(u analysis.CandidateUse, at string) Guidance {
	g := Guidance{Title: "Bind this sqlite3 statement's values", ExampleStatus: "source-derived candidate; not executed or verified as an application patch", Actions: []string{"At " + at + ", keep the sqlite3 execute SQL operand static and place each request-derived value in its separate parameter operand. Supplying parameters does not protect interpolation already present in the SQL text.", "Use ? placeholders for values. Column/table names cannot be bound as values: retain an explicit allow-list and reject unlisted identifiers before constructing those SQL fragments."}}
	texts := []string{u.Sink.Text}
	for _, d := range u.Dependencies {
		for _, e := range d.Transfers {
			if e.Kind == "assignment" || e.Kind == "string_interpolation" {
				texts = append(texts, e.Text)
			}
		}
	}
	for _, text := range texts {
		sql, params, ok := pythonSQLValueCandidate(text)
		if !ok {
			continue
		}
		callee := "cursor.execute"
		if i := strings.Index(u.Sink.Text, "("); i > 0 {
			callee = strings.TrimSpace(u.Sink.Text[:i])
		}
		tuple := strings.Join(params, ", ")
		if len(params) == 1 {
			tuple += ","
		}
		g.Example = callee + "(" + strconv.Quote(sql) + ", (" + tuple + "))"
		g.Actions = append(g.Actions, "Replace the interpolated SQL construction shown in the evidence with the value-binding candidate below. Verify the resulting data types and preserve wildcard behavior in bound LIKE values.")
		break
	}
	if g.Example == "" {
		g.Actions = append(g.Actions, "The current evidence does not support an automatic statement rewrite. Inspect the exact SQL-construction assignments and identifier allow-lists before changing this call; do not apply a Sequelize or another driver's example.")
	}
	g.Actions = append(g.Actions, "Add a regression test that passes a quote-bearing value and checks the statement text remains unchanged while the complete original value is present only in the bound parameters.")
	return g
}
func pythonSQLValueCandidate(text string) (string, []string, bool) {
	// This suggests a narrow repair; it never establishes a security verdict.
	for i := 0; i < len(text)-2; i++ {
		formatted := text[i] == 'f' && (text[i+1] == '\'' || text[i+1] == '"')
		quoteAt := i
		if formatted {
			quoteAt++
		} else if text[i] != '\'' && text[i] != '"' {
			continue
		}
		quote := text[quoteAt]
		end := quoteAt + 1
		for end < len(text) {
			if text[end] == '\\' {
				end += 2
				continue
			}
			if text[end] == quote {
				break
			}
			end++
		}
		if end >= len(text) {
			continue
		}
		sql := text[quoteAt+1 : end]
		upper := strings.ToUpper(strings.TrimSpace(sql))
		if !strings.HasPrefix(upper, "SELECT ") && !strings.HasPrefix(upper, "UPDATE ") && !strings.HasPrefix(upper, "INSERT ") && !strings.HasPrefix(upper, "DELETE ") {
			continue
		}
		var params []string
		if formatted {
			matches := simplePythonInterpolation.FindAllStringSubmatch(sql, -1)
			if len(matches) == 0 || strings.Contains(sql, "{{") {
				return "", nil, false
			}
			for _, m := range matches {
				sql = strings.Replace(sql, m[0], "__ZAZZ_PARAM__", 1)
				params = append(params, m[1])
			}
			if strings.ContainsAny(sql, "{}") {
				return "", nil, false
			}
		} else {
			m := pythonPercentOperand.FindStringSubmatch(text[end+1:])
			if len(m) == 0 || strings.Count(sql, "%s") != 1 {
				return "", nil, false
			}
			sql = strings.Replace(sql, "%s", "__ZAZZ_PARAM__", 1)
			params = []string{m[1]}
		}
		return bindSQLCandidate(sql, params)
	}
	return "", nil, false
}
func bindSQLCandidate(sql string, params []string) (string, []string, bool) {
	var out strings.Builder
	bound := []string{}
	index := 0
	for i := 0; i < len(sql); {
		if sql[i] == '\'' {
			end := i + 1
			for end < len(sql) {
				if sql[end] == '\'' {
					if end+1 < len(sql) && sql[end+1] == '\'' {
						end += 2
						continue
					}
					break
				}
				end++
			}
			if end == len(sql) {
				return "", nil, false
			}
			literal := sql[i+1 : end]
			count := strings.Count(literal, "__ZAZZ_PARAM__")
			if count == 0 {
				out.WriteString(sql[i : end+1])
			} else {
				parts := strings.Split(literal, "__ZAZZ_PARAM__")
				expr := []string{}
				for j, part := range parts {
					if part != "" {
						expr = append(expr, strconv.Quote(part))
					}
					if j < count {
						if index >= len(params) {
							return "", nil, false
						}
						param := params[index]
						index++
						if count > 1 || parts[0] != "" || parts[len(parts)-1] != "" {
							param = "str(" + param + ")"
						}
						expr = append(expr, param)
					}
				}
				out.WriteByte('?')
				bound = append(bound, strings.Join(expr, " + "))
			}
			i = end + 1
			continue
		}
		if strings.HasPrefix(sql[i:], "__ZAZZ_PARAM__") {
			if index >= len(params) {
				return "", nil, false
			}
			prefix := strings.TrimSpace(strings.ToUpper(out.String()))
			if prefix == "" || !strings.ContainsAny(prefix[len(prefix)-1:], "=(,<>") {
				return "", nil, false
			}
			out.WriteByte('?')
			bound = append(bound, params[index])
			index++
			i += len("__ZAZZ_PARAM__")
			continue
		}
		out.WriteByte(sql[i])
		i++
	}
	return out.String(), bound, index == len(params) && len(bound) > 0
}
