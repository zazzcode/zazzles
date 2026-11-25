package langphp

import (
	"regexp"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

var (
	phpPlainStatement   = regexp.MustCompile(`(?is)^\s*(?:select|insert|update|delete|replace)\b`)
	phpDynamicStatement = regexp.MustCompile(`(?i)\b(?:exec|execute|call|prepare)\b`)
	phpSQLLiteral       = regexp.MustCompile("'[^']*'|\"[^\"]*\"|`[^`]*`")
	phpInnerParens      = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*)?\s*\(([^()]*)\)`)
	phpPlaceholder      = regexp.MustCompile(`:[A-Za-z_]|\?`)
	phpPreparedName     = regexp.MustCompile(`^\$(\w+)\s*=\s*[^=]`)
)

// phpPlaceholderLists are the words before a parenthesis that are not functions.
var phpPlaceholderLists = map[string]bool{"values": true, "in": true, "and": true, "or": true, "where": true}

// phpBindCalls are the statement methods that leave the SQL text as it is.
var phpBindCalls = map[string]bool{"bindparam": true, "bindvalue": true, "setfetchmode": true}

// boundFacts states that a statement whose SQL text is a literal written in its own
// prepare call receives request values only as bound parameters. It is withheld when
// anything could replace the statement, or the statement can run a value as code.
func (f *phpFlow) boundFacts(n *sitter.Node, text phpValue, params []phpValue, op string, prepared []analysis.Evidence) []string {
	constant, ok := phpSQLText(text)
	if op != "execute" || !ok || text.built || text.wrapped || len(text.gaps) > 0 {
		return nil
	}
	call, literal := phpOnlyPreparation(prepared)
	if call == nil || literal == nil || call.Span.File != f.module.file {
		return nil
	}
	source := strings.TrimSpace(literal.Text)
	if len(source) < 2 || source[0] != '\'' && source[0] != '"' || constant != source && constant != source[1:len(source)-1] || !phpDataStatement(source[1:len(source)-1]) {
		return nil
	}
	name := phpPreparedName.FindStringSubmatch(call.Text)
	if name == nil || source[0] == '"' && strings.Contains(source, "$") || !phpStraightLine(f.module, n, uint(call.Span.StartByte), name[1]) {
		return nil
	}
	for _, p := range params {
		if len(p.deps) > 0 {
			return []string{"constant_sql_bound_values: " + strings.Join(strings.Fields(constant), " ")}
		}
	}
	return nil
}

// phpDataStatement reports one statement that cannot run a bound value as code: no
// comment, escape or second statement, and no placeholder inside a function call.
func phpDataStatement(sql string) bool {
	if !phpPlainStatement.MatchString(sql) || strings.Contains(sql, "\\") {
		return false
	}
	sql = strings.TrimRight(phpSQLLiteral.ReplaceAllString(sql, " "), "; \t\r\n")
	if phpDynamicStatement.MatchString(sql) || strings.ContainsAny(sql, "'\"`;#") || strings.Contains(sql, "--") || strings.Contains(sql, "/*") {
		return false
	}
	for m := phpInnerParens.FindStringSubmatchIndex(sql); m != nil; m = phpInnerParens.FindStringSubmatchIndex(sql) {
		inner := " "
		if phpPlaceholder.MatchString(sql[m[4]:m[5]]) {
			if m[2] >= 0 && !phpPlaceholderLists[strings.ToLower(sql[m[2]:m[3]])] {
				return false
			}
			inner = " ? "
		}
		sql = sql[:m[0]] + inner + sql[m[1]:]
	}
	return !strings.ContainsAny(sql, "()")
}

// phpOnlyPreparation returns the one prepare call of a statement and its SQL operand.
func phpOnlyPreparation(prepared []analysis.Evidence) (call, literal *analysis.Evidence) {
	for i := range prepared {
		switch prepared[i].Kind {
		case "statement_preparation":
			if call != nil {
				return nil, nil
			}
			call = &prepared[i]
		case "query_text":
			if literal != nil {
				return nil, nil
			}
			literal = &prepared[i]
		}
	}
	return call, literal
}

// phpStraightLine reports that the assignment at start and the execution n are
// statements of one block with only bind calls on the same variable between them.
func phpStraightLine(m *phpModule, n *sitter.Node, start uint, name string) bool {
	assign := m.tree.RootNode().DescendantForByteRange(start, start+1)
	for assign != nil && assign.Kind() != "expression_statement" {
		assign = assign.Parent()
	}
	if assign == nil || assign.Parent() == nil || assign.NamedChildCount() != 1 ||
		assign.NamedChild(0).Kind() != "assignment_expression" || assign.NamedChild(0).StartByte() != start {
		return false
	}
	switch assign.Parent().Kind() {
	case "program", "compound_statement", "case_statement", "default_statement":
	default:
		return false
	}
	run := phpRunStatement(n, assign.Parent())
	if run == nil {
		return false
	}
	for s := assign.NextNamedSibling(); s != nil; s = s.NextNamedSibling() {
		switch {
		case s.Id() == run.Id():
			return true
		case s.Kind() == "comment":
		case s.Kind() != "expression_statement" || s.NamedChildCount() != 1 || !phpBindOnly(m, s.NamedChild(0), name):
			return false
		}
	}
	return false
}

// phpRunStatement returns the statement of block that runs the execution n before
// anything else, or nil.
func phpRunStatement(n, block *sitter.Node) *sitter.Node {
	run := n
	for p := run.Parent(); p != nil; p = run.Parent() {
		if p.Id() == block.Id() {
			return run
		}
		switch p.Kind() {
		case "expression_statement", "parenthesized_expression", "unary_op_expression", "return_statement":
		case "assignment_expression":
			if l := p.ChildByFieldName("left"); l == nil || l.Kind() != "variable_name" {
				return nil
			}
		case "if_statement":
			if c := p.ChildByFieldName("condition"); c == nil || c.Id() != run.Id() {
				return nil
			}
		default:
			return nil
		}
		run = p
	}
	return nil
}

// phpBindOnly reports a bind call on the named statement whose arguments run nothing.
func phpBindOnly(m *phpModule, c *sitter.Node, name string) bool {
	if c.Kind() != "member_call_expression" {
		return false
	}
	o, k, args := c.ChildByFieldName("object"), c.ChildByFieldName("name"), c.ChildByFieldName("arguments")
	return o != nil && k != nil && args != nil && phpVarName(m, o) == name && k.Kind() == "name" &&
		phpBindCalls[strings.ToLower(k.Utf8Text(m.src))] && phpPlainArguments(args)
}

// phpPlainArguments reports arguments made of variables, literals, array elements and
// class constants only.
func phpPlainArguments(n *sitter.Node) bool {
	switch n.Kind() {
	case "arguments", "argument", "variable_name", "name", "string", "string_content", "encapsed_string", "escape_sequence",
		"integer", "float", "boolean", "null", "subscript_expression", "class_constant_access_expression", "qualified_name", "comment":
	default:
		return false
	}
	for i := uint(0); i < n.NamedChildCount(); i++ {
		if !phpPlainArguments(n.NamedChild(i)) {
			return false
		}
	}
	return true
}

// declaredClass reports a class name that the program itself declares, once or more.
func (f *phpFlow) declaredClass(at *sitter.Node, name string) bool {
	index := f.set.classIndex()
	return len(index.byName[strings.ToLower(index.qualify(f.module, name, at.StartByte()))]) > 0
}
