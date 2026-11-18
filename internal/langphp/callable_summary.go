package langphp

import (
	"fmt"
	sitter "github.com/tree-sitter/go-tree-sitter"

	"github.com/zazzcode/zazzles/internal/parse"
)

func (s *phpSet) callableSummary(m *phpModule, fn *sitter.Node) *parse.ClosedCallable {
	if s.summaries == nil {
		s.summaries = map[string]*parse.ClosedCallable{}
	}
	return s.buildSummary(m, fn, 0)
}
func (s *phpSet) buildSummary(m *phpModule, fn *sitter.Node, depth int) *parse.ClosedCallable {
	key := fmt.Sprintf("%s:%d", m.file, fn.StartByte())
	if c := s.summaries[key]; c != nil {
		return c
	}
	c := &parse.ClosedCallable{}
	s.summaries[key] = c
	defer c.Finish()
	if depth >= 64 {
		c.Reject("summary_limit", m.file, fn)
		return c
	}
	params := phpField(fn, "parameters")
	for i := uint(0); params != nil && i < params.NamedChildCount(); i++ {
		p := params.NamedChild(i)
		if p.Kind() != "simple_parameter" || phpField(p, "default_value") != nil || phpField(p, "reference_modifier") != nil || i >= 64 {
			c.Reject("unsupported_parameters", m.file, p)
			continue
		}
		for j := uint(0); j < p.NamedChildCount(); j++ {
			if p.NamedChild(j).Kind() == "reference_modifier" {
				c.Reject("unsupported_parameters", m.file, p)
			}
		}
		c.Params = append(c.Params, phpVarName(m, phpField(p, "name")))
	}
	var scan func(*sitter.Node)
	scan = func(n *sitter.Node) {
		if n == nil {
			return
		}
		switch n.Kind() {
		case "variable_name":
			c.Read(phpVarName(m, n), m.file, n)
			return
		case "function_call_expression":
			name := phpText(m, phpCallee(n))
			target := s.legacyResolution(m, name).Target
			if target == nil {
				c.Reject("unmodeled_call", m.file, n)
			} else {
				d := s.buildSummary(target.module, target.fn, depth+1)
				c.Callees = append(c.Callees, parse.Span(target.module.file, target.fn))
				if !d.Closed() {
					c.Reject("callee_not_closed", m.file, n)
				}
			}
			scan(phpField(n, "arguments"))
			return
		case "compound_statement", "return_statement", "expression_statement", "arguments", "argument", "binary_expression", "unary_op_expression", "parenthesized_expression", "conditional_expression", "array_creation_expression", "array_element_initializer", "string", "encapsed_string", "string_content", "integer", "float", "boolean", "null", "comment":
		default:
			c.Reject("unsupported_syntax", m.file, n)
			return
		}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			scan(n.NamedChild(i))
		}
	}
	if fn.Kind() != "function_definition" {
		c.Reject("unsupported_callable", m.file, fn)
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
	if !c.Closed() || len(args) != len(c.Params) {
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
