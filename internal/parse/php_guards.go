package parse

import (
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
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
			if v := phpVarName(m, args[0]); v != "" {
				out[v] = "numeric"
			}
		case "in_array":
			if len(args) != 2 {
				return
			}
			v := phpVarName(m, args[0])
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

func (f *phpFlow) applyProtections(p map[string]string) *phpFlow {
	for name, protection := range p {
		if v, ok := f.env[name]; ok {
			f.env[name] = phpProtect(v, protection)
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
