package langphp

import (
	"fmt"
	"strconv"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/parse"
)

type phpBoundCallable struct {
	module *phpModule
	fn     *sitter.Node
	// object receives a verified class receiver for method calls.
	object *phpValue
	// class is the declaring class of a method, for self::, parent:: and
	// static:: calls inside it.
	class *phpClassDecl
}

type phpFlow struct {
	set        *phpSet
	module     *phpModule
	entry      analysis.EntryPoint
	invocation analysis.InvocationContext
	report     *analysis.AnalysisReport
	env        map[string]phpValue
	// globals tracks $GLOBALS['name'] assignments (the DVWA mysqli idiom).
	globals map[string]phpValue
	// helperExits is shared by branch clones of the current helper invocation.
	helperExits *phpSuperglobalExits
	context     []analysis.Evidence
	gaps        []analysis.Gap
	depth       int
	work        *int
	stack       map[string]bool
	include     int
	returns     phpValue
	// entryModule/entryModuleRoot anchor the invoked_callable evidence of the
	// entry file even while helper expansion switches f.module.
	entryModule     *phpModule
	entryModuleRoot *sitter.Node
	// constants holds define() values executed in this flow; PHP constants
	// are global, so helpers share them and the first definition wins.
	constants map[string]string
	// condition carries selecting-branch evidence tagged onto literal sets.
	condition []analysis.Evidence
	// dirty records the variables this flow wrote since its clone origin, so
	// branch merges join only changed values instead of the whole environment.
	dirty map[string]bool
	// class is the class whose method this flow expands, if any.
	class    *phpClassDecl
	symfony  *symfonyProject
	services map[string]phpValue
}

func (f *phpFlow) gap(kind, detail string, n *sitter.Node) analysis.Gap {
	return analysis.Gap{Kind: kind, Detail: detail, At: parse.Span(f.module.file, n)}
}

func (f *phpFlow) addUse(kind string, n *sitter.Node, v phpValue) *analysis.CandidateUse {
	deps := []analysis.Dependency{}
	for _, d := range v.deps {
		deps = append(deps, d.dep)
	}
	u := analysis.CandidateUse{ID: fmt.Sprintf("use:%s:%s:%d:%s", f.invocation.ID, f.module.file, n.StartByte(), kind), EntryID: f.invocation.EntryID, InvocationContextID: f.invocation.ID, Kind: kind, Sink: f.module.evidence(kind, n), Dependencies: deps, Context: phpDedupeEvidence(f.context), Gaps: append(append([]analysis.Gap{}, f.gaps...), v.gaps...), Assessment: analysis.Assessment{Status: "not_run"}}
	f.report.Uses = append(f.report.Uses, u)
	return &f.report.Uses[len(f.report.Uses)-1]
}

func (f *phpFlow) evalChildren(n *sitter.Node) phpValue {
	var v phpValue
	for i := uint(0); i < n.ChildCount(); i++ {
		if c := n.Child(i); c != nil && c.IsNamed() {
			v = phpCombine(v, f.eval(c))
		}
	}
	return v
}

func (f *phpFlow) eval(n *sitter.Node) phpValue {
	if n == nil {
		return phpValue{}
	}
	m := f.module
	switch n.Kind() {
	case "variable_name":
		name := phpVarName(m, n)
		if v, ok := f.env[name]; ok {
			return phpTransfer(v, m.evidence("value_reference", n))
		}
		if container, origin, ok := superscriptOrigin(name); ok && phpRequestContainer(container) {
			// A whole request superglobal (`reset($_GET)`, `foreach ($_POST
			// ...)`) carries every request value, keyed by no single field.
			return f.source(n, container, origin, "")
		}
		return phpValue{unknown: true, gaps: []analysis.Gap{f.gap("php_value_unresolved", "Variable is not resolved: $"+name, n)}}
	case "name":
		text := phpText(m, n)
		if c, ok := f.constant(text); ok {
			return phpValue{literals: []phpLiteral{{text: c}}, constant: true, evidence: []analysis.Evidence{m.evidence("constant_binding", n)}}
		}
		return phpValue{}
	case "integer", "float", "true", "false", "null":
		return phpValue{literals: []phpLiteral{{text: phpText(m, n)}}, constant: true}
	case "string":
		if text, ok := phpStringLiteral(m, n); ok {
			return phpValue{literals: []phpLiteral{{text: text}}, constant: true, template: text, evidence: []analysis.Evidence{m.evidence("literal", n)}}
		}
		v := f.evalChildren(n)
		v.built = true
		return phpTransfer(v, m.evidence("string_interpolation", n))
	case "encapsed_string":
		v := phpValue{}
		candidates := []phpLiteral{{}}
		allLiteral, interpolated := true, false
		for i := uint(0); i < n.ChildCount(); i++ {
			c := n.Child(i)
			if c == nil {
				continue
			}
			if c.Kind() == "string_content" {
				text := c.Utf8Text(m.src)
				for j := range candidates {
					candidates[j].text += text
				}
				continue
			}
			if !c.IsNamed() {
				continue
			}
			interpolated = true
			part := f.eval(c)
			if len(part.deps) > 0 || len(part.literals) == 0 {
				allLiteral = false
				part.literals = nil
				part.constant = false
				v = phpCombine(v, part)
				continue
			}
			// Interpolation of a finite literal set expands alternatives.
			var expanded []phpLiteral
			for _, base := range candidates {
				for _, lit := range part.literals {
					next := phpLiteral{text: base.text + lit.text}
					next.condition = append(append([]analysis.Evidence{}, base.condition...), lit.condition...)
					expanded = append(expanded, next)
				}
			}
			candidates = expanded
			if len(candidates) > 16 {
				candidates = candidates[:16]
				allLiteral = false
			}
		}
		if allLiteral && len(v.deps) == 0 {
			v.literals = candidates
			v.constant = len(candidates) == 1
		}
		v.template = phpText(m, n)
		if !interpolated {
			// A double-quoted string without interpolation is a literal.
			v.evidence = []analysis.Evidence{m.evidence("literal", n)}
			return v
		}
		v.built = true
		if t := phpUnquote(v.template); phpInsertRe.MatchString(t) || phpUpdateRe.MatchString(t) {
			v.sqlWrites = []phpSQLWrite{{template: v.template, deps: v.deps}}
		}
		return phpTransfer(v, m.evidence("string_interpolation", n))
	case "binary_expression":
		return f.binaryExpression(n)
	case "parenthesized_expression":
		return f.evalChildren(n)
	case "assignment_expression", "augmented_assignment_expression", "reference_assignment_expression":
		// `$a =& $b` is modeled as a copy: later writes through either alias
		// do not reach the other.
		return f.assign(n)
	case "subscript_expression":
		return f.subscript(n)
	case "function_call_expression", "member_call_expression", "scoped_call_expression":
		return f.call(n)
	case "object_creation_expression":
		return f.objectCreation(n)
	case "cast_expression":
		return f.castValue(n, f.evalChildren(n))
	case "unary_op_expression", "error_suppression_expression", "clone_expression":
		return f.evalChildren(n)
	case "conditional_expression":
		if n.NamedChildCount() == 3 {
			f.eval(n.NamedChild(0))
			v := phpJoin(f.eval(n.NamedChild(1)), f.eval(n.NamedChild(2)))
			return phpTransfer(v, m.evidence("conditional_value", n))
		}
		return phpValue{gaps: []analysis.Gap{f.gap("php_expression_unresolved", "unsupported conditional shape", n)}}
	case "array_creation_expression":
		v := phpValue{fields: map[string]phpValue{}}
		var elements []string
		allStrings := true
		for i := uint(0); i < n.NamedChildCount(); i++ {
			pair := n.NamedChild(i)
			if pair.Kind() != "array_element_initializer" {
				continue
			}
			var key string
			var valueNode *sitter.Node
			if pair.NamedChildCount() == 1 {
				// Positional element: the sole child is the value.
				valueNode = pair.NamedChild(0)
			} else {
				for j := uint(0); j < pair.NamedChildCount(); j++ {
					c := pair.NamedChild(j)
					text, literal := phpStringLiteral(m, c)
					if f.symfony != nil && j == 0 && phpCurlURLKey(m, c) {
						text, literal = phpCurlURLField, true
					}
					if literal && key == "" && valueNode == nil {
						key = text
					} else {
						valueNode = c
					}
				}
			}
			if valueNode == nil {
				continue
			}
			if text, ok := phpStringLiteral(m, valueNode); ok {
				elements = append(elements, text)
			} else {
				allStrings = false
			}
			value := f.eval(valueNode)
			v = phpCombine(v, value)
			if key != "" {
				v.fields[key] = value
			}
		}
		if allStrings && len(elements) > 0 {
			v.arrayLiterals = elements
		}
		return v
	case "shell_execution_expression":
		v := f.evalChildren(n)
		f.commandUse(n, "shell_exec", []string{"shell_command"}, []phpValue{v}, []*sitter.Node{n})
		return phpValue{unknown: true, evidence: []analysis.Evidence{m.evidence("command_output", n)}}
	case "include_expression", "include_once_expression", "require_expression", "require_once_expression":
		return f.includeExpression(n)
	case "member_access_expression", "nullsafe_member_access_expression":
		if v, ok := f.propertyRead(n); ok {
			return v
		}
		return f.evalChildren(n)
	case "scoped_property_access_expression":
		return f.evalChildren(n)
	default:
		return f.evalChildren(n)
	}
}

func (f *phpFlow) castValue(n *sitter.Node, v phpValue) phpValue {
	switch castKind(f.module, n) {
	case "int", "integer", "float", "double":
		at := f.module.evidence("numeric_conversion", n)
		return phpTransfer(phpNumeric(v, analysis.CommandValueNumber, at), at)
	case "string":
		return phpTransfer(v, f.module.evidence("string_conversion", n))
	}
	return phpTransfer(v, f.module.evidence("type_cast", n))
}

func castKind(m *phpModule, n *sitter.Node) string {
	for i := uint(0); i < n.ChildCount(); i++ {
		c := n.Child(i)
		if c == nil {
			continue
		}
		if !c.IsNamed() {
			text := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(c.Utf8Text(m.src)), ")"))
			return strings.TrimPrefix(text, "(")
		}
		if c.Kind() == "cast_type" {
			return strings.ToLower(strings.Trim(strings.TrimSpace(c.Utf8Text(m.src)), "() "))
		}
	}
	return ""
}

func (f *phpFlow) binaryExpression(n *sitter.Node) phpValue {
	left, right := phpField(n, "left"), phpField(n, "right")
	if left == nil || right == nil {
		return f.evalChildren(n)
	}
	op := ""
	for i := uint(0); i < n.ChildCount(); i++ {
		if c := n.Child(i); c != nil && !c.IsNamed() {
			op = strings.TrimSpace(c.Utf8Text(f.module.src))
		}
	}
	a, b := f.eval(left), f.eval(right)
	return f.binaryValues(n, op, a, b)
}

func (f *phpFlow) binaryValues(n *sitter.Node, op string, a, b phpValue) phpValue {
	m := f.module
	switch op {
	case ".":
		v := phpCombine(a, b)
		v.built = true
		v.prefix = phpPrefixOf(a)
		if phpConstantText(a) {
			v.prefix += phpPrefixOf(b)
		}
		if a.template != "" && b.template != "" {
			v.template = a.template + b.template
		}
		return phpConcatTransfer(v, m.evidence("string_construction", n))
	case "==", "===", "!=", "!==", "<", ">", "<=", ">=", "<=>":
		return phpTransfer(phpProtect(phpCombine(a, b), "non_content"), m.evidence("comparison", n))
	case "&&", "||", "and", "or", "xor":
		return phpTransfer(phpProtect(phpCombine(a, b), "non_content"), m.evidence("boolean", n))
	}
	return phpTransfer(phpCombine(a, b), m.evidence("expression", n))
}

func (f *phpFlow) assign(n *sitter.Node) phpValue {
	left, right := phpField(n, "left"), phpField(n, "right")
	v := f.eval(right)
	if n.Kind() == "augmented_assignment_expression" {
		base := f.eval(left)
		prefix := phpPrefixOf(base)
		if phpConstantText(base) {
			prefix += phpPrefixOf(v)
		}
		v = phpCombine(base, v)
		v.built, v.prefix = true, prefix
	}
	return f.assignValue(n, left, v)
}
func (f *phpFlow) assignValue(n, left *sitter.Node, v phpValue) phpValue {
	m := f.module
	v = phpTransfer(v, m.evidence("assignment", n))
	if len(f.condition) > 0 && len(v.literals) > 0 {
		lits := append([]phpLiteral{}, v.literals...)
		for i := range lits {
			lits[i].condition = append(append([]analysis.Evidence{}, f.condition...), lits[i].condition...)
		}
		v.literals = lits
	}
	if left == nil {
		return v
	}
	switch left.Kind() {
	case "member_access_expression":
		f.propertyWrite(left, v)
	case "variable_name":
		name := phpVarName(m, left)
		f.markDirty(name)
		f.env[name] = v
		f.replaceSuperglobalElements(name, v, left)
	case "subscript_expression":
		obj, index := phpSubscriptParts(left)
		key, _ := phpStringLiteral(m, index)
		// $GLOBALS['name'] = ... tracks the DVWA mysqli connection idiom.
		if obj != nil && obj.Kind() == "variable_name" && phpVarName(m, obj) == "GLOBALS" {
			if key != "" {
				if f.globals == nil {
					f.globals = map[string]phpValue{}
				}
				f.markDirty(phpGlobalsKeyPrefix + key)
				f.globals[key] = v
			}
			return v
		}
		if obj != nil && obj.Kind() == "variable_name" && phpVarName(m, obj) == "_SESSION" {
			if key != "" {
				v = phpTransfer(v, m.evidence("storage_write", left))
				f.set.sessionWrites["php-session:"+key] = append(f.set.sessionWrites["php-session:"+key], phpWrite{value: v, entry: f.invocation.EntryID, evidence: m.evidence("storage_write", left)})
			}
			return v
		}
		if obj != nil && f.writeSuperglobalElement(phpVarName(m, obj), index, v) {
			return v
		}
		if obj != nil {
			name := phpVarName(m, obj)
			if base, ok := f.env[name]; ok {
				f.markDirty(name)
				updated := base
				if key != "" {
					if updated.fields == nil {
						updated.fields = map[string]phpValue{}
					}
					updated.fields[key] = v
				}
				updated = phpCombine(updated, v)
				f.env[name] = updated
			}
		}
	}
	return v
}

// phpSubscriptParts returns the positional children of a subscript: the
// container expression and the index, which carry no field names in this
// grammar.
func phpSubscriptParts(n *sitter.Node) (obj, index *sitter.Node) {
	for i := uint(0); i < n.NamedChildCount(); i++ {
		c := n.NamedChild(i)
		if obj == nil {
			obj = c
		} else if index == nil {
			index = c
		}
	}
	return obj, index
}

func (f *phpFlow) subscript(n *sitter.Node) phpValue {
	m := f.module
	obj, index := phpSubscriptParts(n)
	key, literal := phpStringLiteral(m, index)
	if !literal && index != nil && index.Kind() == "integer" {
		key = phpText(m, index)
	}
	if obj == nil {
		return f.evalChildren(n)
	}
	if obj.Kind() == "variable_name" {
		name := phpVarName(m, obj)
		if container, origin, ok := superscriptOrigin(name); ok {
			if container == "SERVER" {
				if phpServerDetermined(key) {
					// The server, not the request, chooses this value.
					return phpValue{evidence: []analysis.Evidence{m.evidence("server_value", n)}}
				}
				origin = serverKeyOrigin(key)
			}
			if sg, tracked := phpSuperglobalKey(name, key); tracked {
				if state, ok := f.globals[sg]; ok {
					return f.superglobalRead(n, state, container, origin, key)
				}
			}
			return f.source(n, container, origin, key)
		}
		if name == "GLOBALS" {
			if v, ok := f.globals[key]; ok {
				return phpTransfer(v, m.evidence("value_reference", n))
			}
			return phpValue{unknown: true, gaps: []analysis.Gap{f.gap("php_value_unresolved", "Global variable is not resolved: $"+key, n)}}
		}
		if base, ok := f.env[name]; ok {
			return f.projectValue(base, key, n)
		}
	}
	v := f.eval(obj)
	return f.projectValue(v, key, n)
}

// projectValue projects a field of a tracked value (arrays, DB rows).
func (f *phpFlow) projectValue(v phpValue, key string, n *sitter.Node) phpValue {
	if v.binding == "symfony_body_array" {
		return f.symfonyBagInput(n, "body", key)
	}
	if v.binding == "symfony_bag" && v.driver == "query" {
		return f.symfonyBagInput(n, "query", key)
	}
	if v.regex != nil {
		if group, err := strconv.Atoi(key); err == nil && group >= 1 {
			return f.regexCapture(v, group, n)
		}
	}
	if field, ok := v.fields[key]; ok {
		return phpTransfer(field, f.module.evidence("field_projection", n))
	}
	if v.binding == "db_row" && v.table != "" {
		column := key
		if pos, err := strconv.Atoi(column); err == nil && pos >= 0 && pos < len(v.columns) {
			// Numeric row access (fetch_row) resolves through the SELECT
			// header position; an unresolvable position keeps the raw key
			// and fails storage matching honestly.
			column = v.columns[pos]
		}
		e := f.module.evidence("storage_source", n)
		return phpValue{deps: []phpDep{{dep: analysis.Dependency{Source: e, StorageKey: "php-sql:" + v.table + "." + column, Transfers: append([]analysis.Evidence{}, v.evidence...)}, protection: "raw"}}}
	}
	v = phpTransfer(v, f.module.evidence("field_projection", n))
	v.deps = append([]phpDep{}, v.deps...)
	for i := range v.deps {
		if v.deps[i].key == "" {
			v.deps[i].key = key
			v.deps[i].dep.Transfers = append(v.deps[i].dep.Transfers, analysis.Evidence{Kind: "field_projection", Text: key, Span: parse.Span(f.module.file, n), SHA256: f.module.hash})
		}
	}
	return v
}

// render records a terminal echo/print as the PHP HTML rendering sink.
func (f *phpFlow) render(n *sitter.Node, v phpValue) {
	if len(v.deps) == 0 {
		return
	}
	m := f.module
	markup := m.inlineHTMLBefore(n.StartByte())
	f.recordXSS(m.evidence("html_output", n), v, parse.HTMLOutputContext(markup), f.pathContexts(n, v, markup))
	if markup != "" {
		// The judge sees the markup around an echo embedded in a page, so the
		// output context (`value="<?php echo $x ?>"`) is source-backed.
		file := analysis.Evidence{Kind: "file", Text: string(m.src), Span: parse.Span(m.file, m.tree.RootNode()), SHA256: m.hash}
		u := &f.report.Uses[len(f.report.Uses)-1]
		u.Context = append(u.Context, parse.RenderMarkup(file, int(n.StartByte()), int(n.EndByte())))
	}
}
