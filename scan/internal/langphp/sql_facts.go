package langphp

import (
	"regexp"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
)

// phpPlainCalls are built-ins that write no variable and return a new value.
var phpPlainCalls = map[string]bool{
	"mysqli_real_escape_string": true, "md5": true, "sha1": true, "stripslashes": true, "trim": true,
	"isset": true, "empty": true, "is_object": true, "trigger_error": true,
}

// phpRequestArrays are the superglobals whose elements a plain expression reads.
var phpRequestArrays = map[string]bool{"_GET": true, "_POST": true, "_REQUEST": true, "_COOKIE": true}

// phpSQLFactHazard matches source text of a program for which no operand fact is
// stated: code the engine can run between two plain statements, a built-in that
// is redefined, and SQL or server settings that change how a literal is read
// without the client's knowledge.
var phpSQLFactHazard = regexp.MustCompile(`(?i)\b(?:set_error_handler|register_tick_function|pcntl_\w+|extr_refs|php_errormsg|__destruct|__tostring|offsetget|offsetexists|(?:runkit7?|uopz)_\w+)\b` +
	`|\bset\b[^;]{0,60}(?:names|char)|sql_mode|no_backslash_escapes|character_set_|collation_connection|init_connect|init_command`)

// phpLocalName is a variable whose references can be looked up in source text.
var phpLocalName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// phpPlainWrite is one plain assignment statement.
type phpPlainWrite struct {
	name  string
	value *sitter.Node
}

// phpSQLPart is constant SQL text, or the node of an operand.
type phpSQLPart struct {
	text    string
	operand *sitter.Node
}

// sqlOperandFacts states facts about the operands of constructed SQL text. They
// are read from one source pattern and from nothing the flow concluded: a native
// mysqli_query whose text is written in the same run of plain assignments as its
// operands, each operand being the native escape on the query's own connection
// or a hexadecimal hash, inside one single-quoted literal of a plain statement.
// Anything else states none: an unknown is not a fact, and a fact decides nothing.
func (f *phpFlow) sqlOperandFacts(n *sitter.Node) []string {
	m := f.module
	if m.tree.RootNode().HasError() || !f.nativeCall(n, "mysqli_query") || f.set.sqlFactHazard() {
		return nil
	}
	args := phpPlainArguments(n)
	if len(args) != 2 {
		return nil
	}
	connection, text := phpConnectionName(m, args[0]), args[1]
	if connection == "" {
		return nil
	}
	writes, names := f.plainWritesBefore(n), map[string]bool{}
	if name := phpVarName(m, text); name != "" {
		last := len(writes) - 1
		if last < 0 || writes[last].name != name {
			return nil
		}
		text, writes = writes[last].value, writes[:last]
		names[name] = true
	}
	parts, ok := phpSQLParts(m, text)
	if !ok {
		return nil
	}
	var sql strings.Builder
	var facts []string
	operands, first := map[string]bool{}, len(writes)
	for _, p := range parts {
		sql.WriteString(p.text)
		if p.operand == nil {
			continue
		}
		sql.WriteByte(phpOperandMark)
		value := p.operand
		if name := phpVarName(m, value); name != "" {
			at := len(writes) - 1
			for at >= 0 && writes[at].name != name {
				at--
			}
			if at < 0 {
				return nil
			}
			value, operands[name], names[name], first = writes[at].value, true, true, min(first, at)
		}
		if !f.plainExpression(value) {
			return nil
		}
		kind, call, ok := f.operandValue(value, connection)
		if !ok || call == nil {
			return nil
		}
		name, source := strings.TrimSpace(phpText(m, p.operand)), " from "+m.evidence("operation", call).Text+" at "+m.file
		if kind == "hash" {
			facts = append(facts, "hash_hex_result: "+name+source)
		} else {
			facts = append(facts, "escaped_in_quoted_literal: "+name+source+"; quoted literal")
		}
	}
	// From the first operand on, only operands are written, so a variable that
	// shares a value with another still ends on an operand's value.
	for _, w := range writes[first:] {
		if !operands[w.name] {
			return nil
		}
	}
	if names[strings.Trim(connection, "$[]")] || f.set.referencedName(names) || !phpQuotedOperands(sql.String()) {
		return nil
	}
	return facts
}

// operandValue returns the kind and the call of a plain value that is the escape on the
// connection or a hash. Every alternative of a conditional is the same kind of call,
// or the empty string, which has no call.
func (f *phpFlow) operandValue(n *sitter.Node, connection string) (string, *sitter.Node, bool) {
	n = phpUnparenthesized(n)
	switch n.Kind() {
	case "string", "encapsed_string":
		text := phpText(f.module, n)
		return "", nil, text == `""` || text == `''`
	case "conditional_expression":
		kind, call, ok := f.operandValue(phpField(n, "body"), connection)
		other, otherCall, also := f.operandValue(phpField(n, "alternative"), connection)
		if call == nil {
			return other, otherCall, ok && also
		}
		return kind, call, ok && also && (otherCall == nil || kind == other)
	case "function_call_expression":
		args := phpPlainArguments(n)
		switch {
		case len(args) == 2 && f.nativeCall(n, "mysqli_real_escape_string"):
			return "escape", n, phpConnectionName(f.module, args[0]) == connection
		case len(args) == 1 && (f.nativeCall(n, "md5") || f.nativeCall(n, "sha1")):
			return "hash", n, true
		}
	}
	return "", nil, false
}

// nativeCall reports a direct call of the PHP built-in: an unqualified name in a
// file without namespace or imports, which no scanned file declares.
func (f *phpFlow) nativeCall(n *sitter.Node, name string) bool {
	return phpText(f.module, phpField(n, "function")) == name && f.phpBuiltinEffectName(name) && !f.set.builtinEffects["module:"+f.module.file]
}

// phpPlainArguments returns positional arguments, or none when the call has any
// other kind.
func phpPlainArguments(n *sitter.Node) []*sitter.Node {
	list := phpField(n, "arguments")
	var out []*sitter.Node
	for i := uint(0); i < list.NamedChildCount(); i++ {
		a := list.NamedChild(i)
		if a.ChildCount() != 1 {
			return nil
		}
		out = append(out, a.Child(0))
	}
	return out
}

// phpConnectionName names a connection held in a variable or in $GLOBALS under a
// literal key.
func phpConnectionName(m *phpModule, n *sitter.Node) string {
	if name := phpVarName(m, n); name != "" {
		return "$" + name
	}
	if object, key := phpLiteralElement(m, n); object == "GLOBALS" {
		return "$[" + key + "]"
	}
	return ""
}

// phpLiteralElement returns the variable and the literal key of an array element.
func phpLiteralElement(m *phpModule, n *sitter.Node) (string, string) {
	if n.Kind() != "subscript_expression" {
		return "", ""
	}
	parts, ok := phpSQLParts(m, n.NamedChild(1))
	if !ok || len(parts) != 1 || parts[0].operand != nil {
		return "", ""
	}
	return phpVarName(m, n.NamedChild(0)), parts[0].text
}

func phpUnparenthesized(n *sitter.Node) *sitter.Node {
	for n != nil && n.Kind() == "parenthesized_expression" {
		n = n.NamedChild(0)
	}
	return n
}

// plainExpression reports an expression that writes nothing and runs no code of
// the program.
func (f *phpFlow) plainExpression(n *sitter.Node) bool {
	n = phpUnparenthesized(n)
	if n == nil {
		return false
	}
	switch n.Kind() {
	case "string", "name", "variable_name":
		return true
	case "encapsed_string":
		for i := uint(0); i < n.NamedChildCount(); i++ {
			if k := n.NamedChild(i).Kind(); k != "string_content" && k != "escape_sequence" && k != "variable_name" {
				return false
			}
		}
		return true
	case "subscript_expression":
		object, _ := phpLiteralElement(f.module, n)
		return object == "GLOBALS" || phpRequestArrays[object]
	case "unary_op_expression":
		return phpOperator(f.module, n) == "!" && f.plainExpression(phpField(n, "argument"))
	case "binary_expression":
		switch phpOperator(f.module, n) {
		case ".", "&&":
			return f.plainExpression(phpField(n, "left")) && f.plainExpression(phpField(n, "right"))
		}
	case "conditional_expression":
		return f.plainExpression(phpField(n, "condition")) && f.plainExpression(phpField(n, "body")) && f.plainExpression(phpField(n, "alternative"))
	case "function_call_expression":
		args := phpPlainArguments(n)
		if name := phpText(f.module, phpField(n, "function")); len(args) == 0 || !phpPlainCalls[name] || !f.nativeCall(n, name) {
			return false
		}
		for _, a := range args {
			if !f.plainExpression(a) {
				return false
			}
		}
		return true
	}
	return false
}

// plainWritesBefore returns the unbroken run of plain assignments before the
// statement of the same block that evaluates n before anything else.
func (f *phpFlow) plainWritesBefore(n *sitter.Node) []phpPlainWrite {
	statement := phpFirstEvaluated(n)
	if statement == nil {
		return nil
	}
	var out []phpPlainWrite
	for s := statement.PrevNamedSibling(); s != nil; s = s.PrevNamedSibling() {
		if s.Kind() == "comment" {
			continue
		}
		w, ok := f.plainWrite(s)
		if !ok {
			break
		}
		out = append([]phpPlainWrite{w}, out...)
	}
	return out
}

func (f *phpFlow) plainWrite(s *sitter.Node) (phpPlainWrite, bool) {
	if s.Kind() != "expression_statement" || s.NamedChild(0).Kind() != "assignment_expression" {
		return phpPlainWrite{}, false
	}
	a := s.NamedChild(0)
	w := phpPlainWrite{name: phpVarName(f.module, phpField(a, "left")), value: phpField(a, "right")}
	return w, phpLocalName.MatchString(w.name) && f.plainExpression(w.value)
}

// phpFirstEvaluated returns the statement whose first evaluated call is n.
func phpFirstEvaluated(n *sitter.Node) *sitter.Node {
	for p := n.Parent(); p != nil; n, p = p, p.Parent() {
		switch p.Kind() {
		case "expression_statement", "return_statement", "if_statement":
			return p
		case "parenthesized_expression", "error_suppression_expression", "unary_op_expression":
		case "assignment_expression":
			if phpField(p, "left").Kind() != "variable_name" {
				return nil
			}
		case "binary_expression":
			if phpField(p, "left").Id() != n.Id() {
				return nil
			}
		default:
			return nil
		}
	}
	return nil
}

// phpSQLParts splits text written with literals, interpolated variables and
// concatenation, as it stands in the source. An escape sequence and every other
// node fail, and phpQuotedOperands refuses a backslash.
func phpSQLParts(m *phpModule, n *sitter.Node) ([]phpSQLPart, bool) {
	n = phpUnparenthesized(n)
	if n == nil {
		return nil, false
	}
	source := phpText(m, n)
	switch n.Kind() {
	case "variable_name", "function_call_expression":
		return []phpSQLPart{{operand: n}}, true
	case "string":
		if source[0] != '\'' {
			return nil, false
		}
		return []phpSQLPart{{text: source[1 : len(source)-1]}}, true
	case "encapsed_string":
		var parts []phpSQLPart
		for i, at := uint(0), n.StartByte(); i < n.ChildCount(); i++ {
			c := n.Child(i)
			if c.StartByte() != at {
				return nil, false
			}
			at = c.EndByte()
			switch {
			case c.Kind() == "string_content":
				parts = append(parts, phpSQLPart{text: phpText(m, c)})
			case c.Kind() == "variable_name":
				parts = append(parts, phpSQLPart{operand: c})
			case c.IsNamed():
				return nil, false
			}
		}
		return parts, true
	case "binary_expression":
		if phpOperator(m, n) != "." {
			return nil, false
		}
		left, ok := phpSQLParts(m, phpField(n, "left"))
		right, also := phpSQLParts(m, phpField(n, "right"))
		return append(left, right...), ok && also
	}
	return nil, false
}

// sqlFactHazard reports a program in which the plain pattern proves nothing.
func (s *phpSet) sqlFactHazard() bool {
	if s.sqlHazard == nil {
		found := false
		for _, file := range s.files {
			m := s.modules[file]
			found = found || m == nil || phpSQLFactHazard.Match(m.src)
		}
		s.sqlHazard = &found
	}
	return *s.sqlHazard
}

// referencedName reports a variable that any scanned file takes by reference
// under one of these names.
func (s *phpSet) referencedName(names map[string]bool) bool {
	for name := range names {
		quoted := regexp.QuoteMeta(name)
		reference := regexp.MustCompile(`(?:^|[^&])&\s*\$` + quoted + `\b|\$` + quoted + `\s*=\s*&`)
		for _, file := range s.files {
			if reference.Match(s.modules[file].src) {
				return true
			}
		}
	}
	return false
}
