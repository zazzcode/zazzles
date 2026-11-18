package langpy

import (
	"fmt"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/parse"
)

func (s *pythonSet) callableSummary(m *pythonModule, fn *sitter.Node) *parse.ClosedCallable {
	if s.summaries == nil {
		s.summaries = map[string]*parse.ClosedCallable{}
	}
	return s.buildSummary(m, fn, 0)
}
func (s *pythonSet) buildSummary(m *pythonModule, fn *sitter.Node, depth int) *parse.ClosedCallable {
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
	params := fn.ChildByFieldName("parameters")
	for i := uint(0); params != nil && i < params.NamedChildCount(); i++ {
		p := params.NamedChild(i)
		if p.Kind() != "identifier" || i >= 64 {
			c.Reject("unsupported_parameters", m.file, p)
			continue
		}
		c.Params = append(c.Params, pyText(m, p))
	}
	var scan func(*sitter.Node)
	scan = func(n *sitter.Node) {
		if n == nil {
			return
		}
		switch n.Kind() {
		case "identifier":
			c.Read(pyText(m, n), m.file, n)
			return
		case "call":
			callee := n.ChildByFieldName("function")
			name := pyText(m, callee)
			// Only immutable declarations are eligible. A parameter, local, import
			// alias or dynamic receiver must not acquire the same-named helper body.
			for _, p := range c.Params {
				if p == strings.Split(name, ".")[0] {
					c.Reject("unmodeled_call", m.file, n)
					return
				}
			}
			target, k := s.resolve(m, name, 0)
			if target == nil || target.funcs[k] == nil || s.staticInvalid[m.file+":"+strings.Split(name, ".")[0]] || s.staticInvalid[target.file+":"+k] {
				c.Reject("unmodeled_call", m.file, n)
			} else {
				d := s.buildSummary(target, target.funcs[k], depth+1)
				c.Callees = append(c.Callees, parse.Span(target.file, target.funcs[k]))
				if !d.Closed() {
					c.Reject("callee_not_closed", m.file, n)
				}
			}
			scan(n.ChildByFieldName("arguments"))
			return
		case "block", "return_statement", "expression_statement", "argument_list", "binary_operator", "unary_operator", "boolean_operator", "comparison_operator", "parenthesized_expression", "conditional_expression", "list", "tuple", "string", "string_start", "string_end", "string_content", "integer", "float", "true", "false", "none", "pass_statement", "comment":
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
	if parent := fn.Parent(); parent != nil && parent.Kind() == "decorated_definition" {
		c.Reject("unmodeled_decorator", m.file, parent)
	}
	scan(fn.ChildByFieldName("body"))
	return c
}
func (f *pythonFlow) closedSummaryCall(call *sitter.Node, target *pythonBoundCallable, args []pythonValue) bool {
	if len(target.closure) > 0 {
		return false
	}
	c := f.set.callableSummary(target.module, target.fn)
	if !c.Closed() || len(args) != len(c.Params) {
		return false
	}
	nodes := call.ChildByFieldName("arguments")
	if nodes == nil || int(nodes.NamedChildCount()) != len(args) {
		return false
	}
	for i, a := range args {
		if !inertPython(a) || nodes.NamedChild(uint(i)).Kind() == "keyword_argument" || nodes.NamedChild(uint(i)).Kind() == "list_splat" || nodes.NamedChild(uint(i)).Kind() == "dictionary_splat" {
			return false
		}
	}
	return true
}

// Nil outside shadow tests; it observes successful expansions without changing
// the flow's result or summary applicability.
var pythonSummaryShadow func(*pythonFlow, *sitter.Node, *pythonBoundCallable, []pythonValue, pythonValue, int)

func inertPython(v pythonValue) bool {
	return len(v.deps) == 0 && len(v.gaps) == 0 && v.fields == nil && v.binding == "" && v.table == "" && v.driver == "" && v.templateEscape == "" && !v.unknown && !v.built && !v.rendered && v.callable == nil && v.methods == nil && v.thread == nil
}
