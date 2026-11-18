package parse

import (
	"fmt"
	sitter "github.com/tree-sitter/go-tree-sitter"
)

func (s *phpSet) callableSummary(m *phpModule, fn *sitter.Node) *closedCallable {
	if s.summaries == nil {
		s.summaries = map[string]*closedCallable{}
	}
	return s.buildSummary(m, fn, 0)
}
func (s *phpSet) buildSummary(m *phpModule, fn *sitter.Node, depth int) *closedCallable {
	key := fmt.Sprintf("%s:%d", m.file, fn.StartByte())
	if c := s.summaries[key]; c != nil {
		return c
	}
	c := &closedCallable{}
	s.summaries[key] = c
	defer c.finish()
	if depth >= 64 {
		c.reject("summary_limit", m.file, fn)
		return c
	}
	params := phpField(fn, "parameters")
	for i := uint(0); params != nil && i < params.NamedChildCount(); i++ {
		p := params.NamedChild(i)
		if p.Kind() != "simple_parameter" || phpField(p, "default_value") != nil || phpField(p, "reference_modifier") != nil || i >= 64 {
			c.reject("unsupported_parameters", m.file, p)
			continue
		}
		for j := uint(0); j < p.NamedChildCount(); j++ {
			if p.NamedChild(j).Kind() == "reference_modifier" {
				c.reject("unsupported_parameters", m.file, p)
			}
		}
		c.params = append(c.params, phpVarName(m, phpField(p, "name")))
	}
	var scan func(*sitter.Node)
	scan = func(n *sitter.Node) {
		if n == nil {
			return
		}
		switch n.Kind() {
		case "variable_name":
			c.read(phpVarName(m, n), m.file, n)
			return
		case "function_call_expression":
			name := phpText(m, phpCallee(n))
			target := s.legacyResolution(m, name).Target
			if target == nil {
				c.reject("unmodeled_call", m.file, n)
			} else {
				d := s.buildSummary(target.module, target.fn, depth+1)
				c.callees = append(c.callees, spanOf(target.module.file, target.fn))
				if !d.closed() {
					c.reject("callee_not_closed", m.file, n)
				}
			}
			scan(phpField(n, "arguments"))
			return
		case "compound_statement", "return_statement", "expression_statement", "arguments", "argument", "binary_expression", "unary_op_expression", "parenthesized_expression", "conditional_expression", "array_creation_expression", "array_element_initializer", "string", "encapsed_string", "string_content", "integer", "float", "boolean", "null", "comment":
		default:
			c.reject("unsupported_syntax", m.file, n)
			return
		}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			scan(n.NamedChild(i))
		}
	}
	if fn.Kind() != "function_definition" {
		c.reject("unsupported_callable", m.file, fn)
		return c
	}
	scan(phpField(fn, "body"))
	return c
}
func (s *phpSet) resolveFunction(m *phpModule, name string) *phpBoundCallable {
	if fn := m.funcs[name]; fn != nil {
		return &phpBoundCallable{module: m, fn: fn}
	}
	return (&phpFlow{module: m, set: s}).uniqueFunction(name)
}
func (f *phpFlow) closedSummaryCall(call *sitter.Node, target *phpBoundCallable, args []phpValue) bool {
	if target.object != nil {
		return false
	}
	c := f.set.callableSummary(target.module, target.fn)
	if !c.closed() || len(args) != len(c.params) {
		return false
	}
	nodes := phpField(call, "arguments")
	if nodes == nil || int(nodes.NamedChildCount()) != len(args) {
		return false
	}
	for i, a := range args {
		if !inertPHP(a) {
			return false
		}
		n := nodes.NamedChild(uint(i))
		if n.Kind() != "argument" || n.NamedChildCount() != 1 {
			return false
		}
	}
	return true
}

var phpSummaryShadow func(*phpFlow, *sitter.Node, *phpBoundCallable, []phpValue, phpValue, int)
