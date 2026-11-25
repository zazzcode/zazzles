package langjs

import (
	"regexp"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/parse"
)

// maxPackageHops bounds the declarations followed from a callee to its import.
const maxPackageHops = 6

// maxPackageImports bounds the other package imports offered beside the binding.
const maxPackageImports = 4

// sqlStatementStart matches a SQL statement's verb and the clause word that
// must follow it, so prose that begins with a verb is not SQL.
var sqlStatementStart = regexp.MustCompile(`(?is)^[\s(]*(` +
	`select\s.*?\sfrom\s|select\s+[\w*]+\s*\(|insert\s+(ignore\s+|or\s+\w+\s+)?into\s|update\s.+?\sset\s|delete\s+from\s|` +
	`merge\s+into\s|replace\s+into\s|with\s+(recursive\s+)?\w+\s*(\([^)]*\)\s*)?as\s*\(|` +
	`(create|alter|drop|truncate)\s+(table|index|view|schema|database|user|role|temporary|unique)\b)`)

// sqlStatementText reports constant text that begins a SQL statement.
func sqlStatementText(text string) bool { return sqlStatementStart.MatchString(text + " ") }

// constantParts returns an expression's constant text in order; every dynamic
// part is one space-delimited placeholder. It follows single-assignment locals.
func constantParts(m *sourceModule, n *sitter.Node, depth int) string {
	n = unwrapTS(n)
	if n == nil || depth > maxPackageHops {
		return " ? "
	}
	switch n.Kind() {
	case "string":
		return strings.Trim(n.Utf8Text(m.src), "'\"")
	case "template_string":
		var b strings.Builder
		for i := uint(0); i < n.ChildCount(); i++ {
			switch c := n.Child(i); c.Kind() {
			case "string_fragment", "escape_sequence":
				b.WriteString(c.Utf8Text(m.src))
			case "template_substitution":
				if c.NamedChildCount() > 0 {
					b.WriteString(constantParts(m, c.NamedChild(0), depth+1))
				}
			}
		}
		return b.String()
	case "binary_expression":
		if op := n.ChildByFieldName("operator"); op != nil && op.Utf8Text(m.src) == "+" {
			return constantParts(m, n.ChildByFieldName("left"), depth+1) + constantParts(m, n.ChildByFieldName("right"), depth+1)
		}
	case "call_expression":
		// ['SELECT ...', part].join(' ') reads in element order.
		fn := n.ChildByFieldName("function")
		if fn != nil && fn.Kind() == "member_expression" {
			obj, prop := unwrapTS(fn.ChildByFieldName("object")), fn.ChildByFieldName("property")
			if obj != nil && prop != nil && obj.Kind() == "array" && prop.Utf8Text(m.src) == "join" {
				var parts []string
				for i := uint(0); i < obj.NamedChildCount(); i++ {
					parts = append(parts, constantParts(m, obj.NamedChild(i), depth+1))
				}
				return strings.Join(parts, " ")
			}
		}
	case "identifier":
		if v := packageDeclaration(m, n, n.Utf8Text(m.src)); v != nil && !bindingReassigned(m, n.Utf8Text(m.src)) {
			return constantParts(m, v, depth+1)
		}
	}
	return " ? "
}

// packageDeclaration returns the initializer of the nearest declaration of name
// that encloses at, nil when a parameter or no declaration binds it.
func packageDeclaration(m *sourceModule, at *sitter.Node, name string) *sitter.Node {
	for p := at.Parent(); p != nil; p = p.Parent() {
		if isFunction(p) && bindsParameter(m, p, name) {
			return nil
		}
		if p.Kind() != "statement_block" && p.Kind() != "program" {
			continue
		}
		for i := uint(0); i < p.NamedChildCount(); i++ {
			d := p.NamedChild(i)
			if d.Kind() == "export_statement" {
				d = d.ChildByFieldName("declaration")
			}
			if d == nil || d.Kind() != "lexical_declaration" && d.Kind() != "variable_declaration" {
				continue
			}
			for j := uint(0); j < d.NamedChildCount(); j++ {
				id := d.NamedChild(j).ChildByFieldName("name")
				if id != nil && id.Kind() == "identifier" && id.Utf8Text(m.src) == name {
					return d.NamedChild(j).ChildByFieldName("value")
				}
			}
		}
	}
	return nil
}

// bindsParameter reports a function parameter that binds name.
func bindsParameter(m *sourceModule, fn *sitter.Node, name string) bool {
	if p := fn.ChildByFieldName("parameter"); p != nil {
		return p.Utf8Text(m.src) == name
	}
	params := fn.ChildByFieldName("parameters")
	if params == nil {
		return false
	}
	found := false
	var walk func(*sitter.Node)
	walk = func(n *sitter.Node) {
		if k := n.Kind(); (k == "identifier" || k == "shorthand_property_identifier_pattern") && n.Utf8Text(m.src) == name {
			found = true
		}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			walk(n.NamedChild(i))
		}
	}
	walk(params)
	return found
}

// packageRoot follows an expression to a package import: through members, calls,
// construction, await, single-assignment declarations, one imported module, and
// a parameter of a callback given to a call on the package.
func (s *moduleSet) packageRoot(m *sourceModule, n *sitter.Node, depth int) []analysis.Evidence {
	n = unwrapTS(n)
	if n == nil || depth > maxPackageHops {
		return nil
	}
	switch n.Kind() {
	case "member_expression":
		return s.packageRoot(m, n.ChildByFieldName("object"), depth)
	case "call_expression":
		if args := n.ChildByFieldName("arguments"); args != nil && args.Kind() == "template_string" {
			return nil
		}
		return s.packageRoot(m, n.ChildByFieldName("function"), depth)
	case "new_expression":
		return s.packageRoot(m, n.ChildByFieldName("constructor"), depth)
	case "await_expression":
		if n.NamedChildCount() == 1 {
			return s.packageRoot(m, n.NamedChild(0), depth)
		}
	case "identifier":
		return s.packageName(m, n, n.Utf8Text(m.src), depth)
	}
	return nil
}

func (s *moduleSet) packageName(m *sourceModule, at *sitter.Node, name string, depth int) []analysis.Evidence {
	if bindingReassigned(m, name) {
		return nil
	}
	for p := at.Parent(); p != nil; p = p.Parent() {
		if !isFunction(p) || !bindsParameter(m, p, name) {
			continue
		}
		// Only a callback handed to a package call receives a package value.
		args := p.Parent()
		if args == nil || args.Kind() != "arguments" || args.Parent() == nil {
			return nil
		}
		b := s.packageRoot(m, args.Parent().ChildByFieldName("function"), depth+1)
		if len(b) == 0 {
			return nil
		}
		return append(b, m.evidence("sink_binding", args.Parent()))
	}
	if v := packageDeclaration(m, at, name); v != nil {
		if b := s.packageRoot(m, v, depth+1); len(b) > 0 {
			return append(b, m.evidence("sink_binding", v.Parent()))
		}
		return nil
	}
	imp, ok := m.imports[name]
	if !ok || imp.declaration == nil {
		return nil
	}
	target := s.importModule(m, imp.module)
	if target == nil {
		if strings.HasPrefix(imp.module, ".") || strings.HasPrefix(imp.module, "/") || len(s.aliasBases(m.file, imp.module)) > 0 {
			return nil
		}
		return []analysis.Evidence{m.evidence("sink_binding", imp.declaration)}
	}
	if imp.name == "*" || bindingReassigned(target, imp.name) {
		return nil
	}
	v := topVariable(target, imp.name)
	if imp.name == "default" {
		v = defaultExport(target)
	} else if !exportedName(target, imp.name) {
		return nil
	}
	if v == nil {
		return nil
	}
	if b := s.packageRoot(target, v, depth+1); len(b) > 0 {
		return append(b, m.evidence("sink_binding", imp.declaration))
	}
	return nil
}

// packageSQLText returns the argument of a package call that carries a SQL
// statement built from request data, with the value of that text, or -1. The
// callee's name plays no part.
func (f *flow) packageSQLText(call *sitter.Node, values []value) (int, value) {
	fn, args := call.ChildByFieldName("function"), call.ChildByFieldName("arguments")
	if fn == nil || args == nil || args.Kind() != "arguments" {
		return -1, value{}
	}
	index, text := f.requestSQLArgument(args, values)
	if index < 0 || len(f.set.packageRoot(f.module, fn, 0)) == 0 {
		return -1, value{}
	}
	return index, text
}

// packageSQLCallback reports a callback given to a package call whose body holds
// a string that begins a SQL statement.
func (f *flow) packageSQLCallback(n *sitter.Node) bool {
	args := n.Parent()
	if f.client != nil || f.set == nil || args == nil || args.Kind() != "arguments" || args.Parent() == nil {
		return false
	}
	found := false
	var walk func(*sitter.Node)
	walk = func(c *sitter.Node) {
		if k := c.Kind(); k == "template_string" || k == "string" {
			found = found || sqlStatementText(constantParts(f.module, c, 0))
		}
		for i := uint(0); i < c.NamedChildCount() && !found; i++ {
			walk(c.NamedChild(i))
		}
	}
	walk(n)
	return found && len(f.set.packageRoot(f.module, args.Parent().ChildByFieldName("function"), 0)) > 0
}

func (f *flow) requestSQLArgument(args *sitter.Node, values []value) (int, value) {
	for i, v := range values {
		if uint(i) >= args.NamedChildCount() {
			break
		}
		arg := unwrapTS(args.NamedChild(uint(i)))
		if arg != nil && arg.Kind() == "object" {
			for _, field := range v.fields {
				if f.requestSQL(field) {
					return i, field
				}
			}
			continue
		}
		if f.requestSQL(v) {
			return i, v
		}
	}
	return -1, value{}
}

// requestSQL reports a value with a request dependency that passed through a
// construction whose constant text begins a SQL statement.
func (f *flow) requestSQL(v value) bool {
	for _, d := range v.deps {
		if d.Source.Kind != "input_source" {
			continue
		}
		for _, t := range d.Transfers {
			m := f.set.modules[t.Span.File]
			if m == nil {
				continue
			}
			n := parse.NodeAt(m.tree.RootNode(), t.Span.StartByte, t.Span.EndByte)
			if n == nil {
				continue
			}
			switch unwrapTS(n).Kind() {
			case "template_string", "binary_expression", "call_expression":
				if sqlStatementText(constantParts(m, n, 0)) {
					return true
				}
			}
		}
	}
	return false
}

// packageSQLBinding returns the import-to-call binding of a SQL use on a package
// without a contract, with the module's other package imports as context.
func (s *moduleSet) packageSQLBinding(use analysis.CandidateUse) []analysis.Evidence {
	m := s.modules[use.Sink.Span.File]
	if m == nil {
		return nil
	}
	call := parse.NodeAt(m.tree.RootNode(), use.Sink.Span.StartByte, use.Sink.Span.EndByte)
	if call == nil || call.Kind() != "call_expression" {
		return nil
	}
	f := &flow{set: s, module: m}
	text := false
	for _, d := range use.Dependencies {
		text = text || d.SinkSlot == "sql_text" && f.requestSQL(value{deps: []analysis.Dependency{d}})
	}
	if !text {
		return nil
	}
	b := s.packageRoot(m, call.ChildByFieldName("function"), 0)
	if len(b) == 0 {
		return nil
	}
	return append(b, m.evidence("sink_binding", call))
}
