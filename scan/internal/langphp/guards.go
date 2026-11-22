package langphp

import (
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

// branchProtection returns variable protections that hold on the true branch
// of the condition (yes) and on the false branch (no). Only predicates whose
// truth is implied by the branch contribute: `!` flips the branch, `&&`
// implies both operands only when true, `||` implies both negations only when
// false; any other operator implies nothing. A negated predicate such as
// `!in_array($v, [...])` therefore lands in no, which conditional() applies
// only when the rejecting branch terminates.
func (f *phpFlow) branchProtection(n *sitter.Node) (yes, no map[string]string) {
	yes, no = map[string]string{}, map[string]string{}
	f.impliedProtections(n, true, yes)
	f.impliedProtections(n, false, no)
	return yes, no
}

// impliedProtections records into out the protections implied when the
// condition c evaluates to truth.
func (f *phpFlow) impliedProtections(c *sitter.Node, truth bool, out map[string]string) {
	if c == nil {
		return
	}
	m := f.module
	switch c.Kind() {
	case "parenthesized_expression":
		if c.NamedChildCount() == 1 {
			f.impliedProtections(c.NamedChild(0), truth, out)
		}
	case "unary_op_expression":
		if strings.HasPrefix(strings.TrimSpace(phpText(m, c)), "!") && c.NamedChildCount() == 1 {
			f.impliedProtections(c.NamedChild(0), !truth, out)
		}
	case "binary_expression":
		switch strings.ToLower(phpOperator(m, c)) {
		case "&&", "and":
			if truth {
				f.impliedProtections(phpField(c, "left"), true, out)
				f.impliedProtections(phpField(c, "right"), true, out)
			}
		case "||", "or":
			if !truth {
				f.impliedProtections(phpField(c, "left"), false, out)
				f.impliedProtections(phpField(c, "right"), false, out)
			}
		}
	case "function_call_expression":
		if !truth {
			return
		}
		name := phpText(m, phpCallee(c))
		if _, shadow := m.funcs[name]; shadow {
			return
		}
		args := phpArgs(c)
		switch name {
		case "is_numeric", "ctype_digit":
			if len(args) != 1 {
				return
			}
			protection := "numeric"
			if name == "ctype_digit" {
				protection = phpDigitsGuard
			}
			if v := phpVarName(m, args[0]); v != "" {
				out[v] = protection
			} else if key := phpElementKey(m, args[0]); key != "" {
				out[key] = protection
			}
		case "in_array":
			if len(args) != 2 {
				return
			}
			v := phpVarName(m, args[0])
			if v == "" {
				v = phpElementKey(m, args[0])
			}
			if v == "" {
				return
			}
			options := phpArrayLiteralStrings(m, args[1])
			if options == nil {
				if av, ok := f.env[phpVarName(m, args[1])]; ok {
					options = phpFiniteStrings(av)
				}
			}
			if len(options) > 0 {
				out[v] = "component"
			}
		}
	}
}

// applyProtections applies the protections the branch condition at implies.
func (f *phpFlow) applyProtections(p map[string]string, at analysis.Evidence) *phpFlow {
	for name, protection := range p {
		if base, index, element := strings.Cut(name, phpElementSeparator); element {
			f.protectElement(base, index, protection, at)
			continue
		}
		if v, ok := f.env[name]; ok {
			f.env[name] = phpGuarded(v, protection, at)
			// Branch merges join only dirty variables; a protection-only
			// change must survive the join like an assignment would.
			f.markDirty(name)
		}
	}
	return f
}

// phpFiniteStrings returns a value's unconditional finite string candidate
// set, or nil when the value is anything else (deps, unknown, dynamic
// elements).
func phpFiniteStrings(v phpValue) []string {
	if len(v.deps) > 0 || v.unknown || len(v.arrayLiterals) == 0 {
		return nil
	}
	return append([]string{}, v.arrayLiterals...)
}

// phpArrayLiteralStrings extracts the string elements of a plain array
// literal; nil for any non-literal shape. The first string of a keyed element
// is the key, mirroring array evaluation.
func phpArrayLiteralStrings(m *phpModule, n *sitter.Node) []string {
	if n == nil || n.Kind() != "array_creation_expression" {
		return nil
	}
	var out []string
	for i := uint(0); i < n.NamedChildCount(); i++ {
		pair := n.NamedChild(i)
		if pair.Kind() != "array_element_initializer" {
			return nil
		}
		var valueNode *sitter.Node
		for j := uint(0); j < pair.NamedChildCount(); j++ {
			c := pair.NamedChild(j)
			if valueNode == nil && pair.NamedChildCount() > 1 {
				if _, ok := phpStringLiteral(m, c); ok {
					continue // keyed element: first string is the key
				}
			}
			valueNode = c
		}
		text, ok := phpStringLiteral(m, valueNode)
		if !ok {
			return nil
		}
		out = append(out, text)
	}
	return out
}

// phpElementSeparator joins a variable and a literal index into one guard key.
const phpElementSeparator = "\x00"

// phpElementKey returns the guard key of `$name[literal]`, or "".
func phpElementKey(m *phpModule, n *sitter.Node) string {
	if n == nil || n.Kind() != "subscript_expression" {
		return ""
	}
	obj, index := phpSubscriptParts(n)
	name := phpVarName(m, obj)
	if name == "" || index == nil {
		return ""
	}
	key, ok := phpStringLiteral(m, index)
	if !ok && index.Kind() == "integer" {
		key, ok = phpText(m, index), true
	}
	if !ok {
		return ""
	}
	return name + phpElementSeparator + key
}

// protectElement records a guard on one literal-index element (for example
// `is_numeric($octet[0])`): later reads of that element see the protection;
// sibling elements and the whole array keep their own protection. The fields
// map is copied because branch clones share it with their parent.
func (f *phpFlow) protectElement(name, index, protection string, at analysis.Evidence) {
	v, ok := f.env[name]
	if !ok {
		return
	}
	element, ok := v.fields[index]
	if !ok {
		element = v
		element.fields = nil
	}
	fields := make(map[string]phpValue, len(v.fields)+1)
	for k, field := range v.fields {
		fields[k] = field
	}
	fields[index] = phpGuarded(element, protection, at)
	v.fields = fields
	f.env[name] = v
	f.markDirty(name)
}

// applySymfonyFilters records the selected validation branch on the tested
// value so a later write or another branch cannot inherit that evidence.
func (f *phpFlow) applySymfonyFilters(condition *sitter.Node, truth bool) {
	if f.symfony == nil || condition == nil {
		return
	}
	f.symfonyImpliedFilters(condition, truth, func(variable, name string, module *phpModule, node *sitter.Node) {
		value, exists := f.env[variable]
		if !exists {
			return
		}
		e := module.evidence("php_filter_"+name, node)
		value = phpTransfer(value, e)
		for i := range value.deps {
			if value.deps[i].protection == "raw" {
				value.deps[i].protection = e.Kind
			}
		}
		f.env[variable] = value
		f.markDirty(variable)
	})
}

func phpFilterEvidence(dep phpDep) (analysis.Evidence, bool) {
	for i := len(dep.dep.Transfers) - 1; i >= 0; i-- {
		e := dep.dep.Transfers[i]
		if strings.HasPrefix(e.Kind, "php_filter_") {
			return e, true
		}
	}
	return analysis.Evidence{}, false
}

func (f *phpFlow) symfonyImpliedFilters(n *sitter.Node, truth bool, record func(string, string, *phpModule, *sitter.Node)) {
	if n == nil {
		return
	}
	m := f.module
	switch n.Kind() {
	case "parenthesized_expression":
		f.symfonyImpliedFilters(firstNamedChild(n), truth, record)
		return
	case "unary_op_expression":
		if phpOperator(m, n) == "!" {
			f.symfonyImpliedFilters(firstNamedChild(n), !truth, record)
		}
		return
	case "binary_expression":
		switch strings.ToLower(phpOperator(m, n)) {
		case "&&", "and":
			if truth {
				f.symfonyImpliedFilters(phpField(n, "left"), truth, record)
				f.symfonyImpliedFilters(phpField(n, "right"), truth, record)
			}
			return
		case "||", "or":
			if !truth {
				f.symfonyImpliedFilters(phpField(n, "left"), truth, record)
				f.symfonyImpliedFilters(phpField(n, "right"), truth, record)
			}
			return
		}
	case "member_call_expression":
		variable, filter, helper, returned := f.symfonyFilterHelper(n)
		if truth && variable != "" {
			record(variable, filter, helper, returned)
		}
		return
	}
	if variable, filter := f.phpFilterPredicate(m, n, truth); variable != "" {
		record(variable, filter, m, n)
	}
}

func (f *phpFlow) phpFilterPredicate(m *phpModule, n *sitter.Node, truth bool) (variable, filter string) {
	if n == nil {
		return "", ""
	}
	if n.Kind() == "parenthesized_expression" {
		return f.phpFilterPredicate(m, firstNamedChild(n), truth)
	}
	if n.Kind() == "unary_op_expression" && phpOperator(m, n) == "!" {
		return f.phpFilterPredicate(m, firstNamedChild(n), !truth)
	}
	if n.Kind() == "binary_expression" {
		op := phpOperator(m, n)
		left, right := phpField(n, "left"), phpField(n, "right")
		if phpText(m, left) == "false" {
			left, right = right, left
		}
		if phpText(m, right) != "false" || (op != "!==" && op != "===") {
			return "", ""
		}
		return f.phpFilterPredicate(m, left, truth == (op == "!=="))
	}
	if !truth || n.Kind() != "function_call_expression" {
		return "", ""
	}
	callee := phpText(m, phpCallee(n))
	if callee != "filter_var" && callee != `\filter_var` {
		return "", ""
	}
	if !f.set.phpDeserializationBuiltin(m, phpCallee(n)) {
		return "", ""
	}
	args := phpArgs(n)
	if len(args) != 2 {
		return "", ""
	}
	filter = strings.TrimPrefix(phpText(m, args[1]), `\`)
	switch filter {
	case "FILTER_VALIDATE_URL", "FILTER_VALIDATE_EMAIL", "FILTER_VALIDATE_INT", "FILTER_VALIDATE_IP", "FILTER_VALIDATE_BOOLEAN", "FILTER_VALIDATE_DOMAIN":
		return phpVarName(m, args[0]), strings.ToLower(filter)
	}
	return "", ""
}

func (f *phpFlow) symfonyFilterHelper(n *sitter.Node) (variable, filter string, module *phpModule, returned *sitter.Node) {
	m := f.module
	receiver := phpVarName(m, phpField(n, "object"))
	decl := f.env[receiver].classDecl
	if receiver == "this" && decl == nil {
		decl = f.class
	}
	if decl == nil {
		return "", "", nil, nil
	}
	_, helper, module, _ := f.set.classIndex().method(decl, phpText(m, phpField(n, "name")))
	body := phpField(helper, "body")
	if body == nil || body.NamedChildCount() != 1 || body.NamedChild(0).Kind() != "return_statement" {
		return "", "", nil, nil
	}
	returned = body.NamedChild(0)
	param, filter := f.phpFilterPredicate(module, firstNamedChild(returned), true)
	if param == "" {
		return "", "", nil, nil
	}
	params, args := phpField(helper, "parameters"), phpArgs(n)
	for i := uint(0); params != nil && i < params.NamedChildCount() && i < uint(len(args)); i++ {
		if phpVarName(module, phpField(params.NamedChild(i), "name")) == param {
			return phpVarName(m, args[i]), filter, module, returned
		}
	}
	return "", "", nil, nil
}
