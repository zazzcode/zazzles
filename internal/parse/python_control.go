package parse

import (
	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
)

func (f *pythonFlow) block(n *sitter.Node) bool {
	if n == nil {
		return false
	}
	for i := uint(0); i < n.NamedChildCount(); i++ {
		if f.stmt(n.NamedChild(i)) {
			return true
		}
	}
	return false
}
func (f *pythonFlow) stmt(n *sitter.Node) bool {
	switch n.Kind() {
	case "expression_statement":
		for i := uint(0); i < n.NamedChildCount(); i++ {
			expr := n.NamedChild(i)
			v := f.eval(expr)
			f.markGuard(expr, v)
		}
	case "return_statement":
		if n.NamedChildCount() > 0 {
			expr := n.NamedChild(0)
			v := f.eval(expr)
			f.returns = pyCombine(f.returns, v)
			if f.depth == 0 && !v.rendered && f.returnsHTML() {

				if len(v.deps) > 0 && v.binding != "json" && v.binding != "non_html" {
					f.recordXSS(f.module.evidence("html_return", expr), v, "html_text", nil)
				}
			}
		}
		return true
	case "raise_statement":
		f.evalChildren(n)
		return true
	case "if_statement":
		return f.conditional(n)
	case "elif_clause":
		// Treat an elif chain as an explicit bounded alternative, preserving its condition.
		c := f.clone()
		c.context = append(c.context, f.module.evidence("branch_precondition", n))
		c.block(n.ChildByFieldName("consequence"))
		f.merge(c, f.clone())
	case "with_statement":
		return f.withBlock(n)
	case "try_statement":
		return f.tryBlock(n)
	case "for_statement", "while_statement":
		b := f.clone()
		b.gaps = append(b.gaps, f.gap("python_loop_unresolved", "loop execution and mutation are not fully modeled", n))
		b.block(n.ChildByFieldName("body"))
		f.merge(f.clone(), b)
	case "import_statement", "import_from_statement":
		// Local imports are resolved with lexical shadowing checks at their use sites.
		temp := *f.module
		temp.imports = map[string]pythonImport{}
		temp.declarations(n, false)
		for k, v := range temp.imports {
			f.imports[k] = v
		}
	case "function_definition":
		closure := map[string]pythonValue{}
		for k, v := range f.env {
			closure[k] = pyTransfer(v, f.module.evidence("closure_capture", n))
		}
		f.env[pyText(f.module, n.ChildByFieldName("name"))] = pythonValue{callable: &pythonBoundCallable{module: f.module, fn: n, closure: closure}}
		return false
	case "decorated_definition":
		if fn := n.ChildByFieldName("definition"); fn != nil && fn.Kind() == "function_definition" {
			gap := f.gap("python_callback_unresolved", "Decorated local callback requires its wrapper contract", n)
			f.env[pyText(f.module, fn.ChildByFieldName("name"))] = pythonValue{unknown: true, gaps: []analysis.Gap{gap}}
			f.gaps = append(f.gaps, gap)
		}
		return false
	case "class_definition":
		return false
	default:
		f.evalChildren(n)
	}
	return false
}
func (f *pythonFlow) conditional(n *sitter.Node) bool {
	test := n.ChildByFieldName("condition")
	f.eval(test)

	if outcome, known := f.constantCondition(test); known {
		if outcome {
			f.context = append(f.context, f.module.evidence("branch_precondition", test))
			return f.block(n.ChildByFieldName("consequence"))
		}
		f.context = append(f.context, f.module.evidence("branch_false_precondition", test))
		alternative := n.ChildByFieldName("alternative")
		if alternative == nil {
			return false
		}
		if alternative.Kind() == "elif_clause" {
			return f.conditional(alternative)
		}
		return f.block(pyBody(alternative))
	}
	yes := f.clone()
	yes.context = append(yes.context, f.module.evidence("branch_precondition", test))
	yt := yes.block(n.ChildByFieldName("consequence"))
	branches := []*pythonFlow{}
	if !yt {
		branches = append(branches, yes)
	} else {
		f.returns = pyCombine(f.returns, pyTransfer(yes.returns, f.module.evidence("branch_precondition", test)))
	}
	alternative := n.ChildByFieldName("alternative")
	no := f.clone()
	no.context = append(no.context, f.module.evidence("branch_false_precondition", test))
	nt := false
	if alternative != nil {
		no.context = append(no.context, f.module.evidence("branch_alternative", alternative))
		if alternative.Kind() == "elif_clause" {
			nt = no.stmt(alternative)
		} else {
			nt = no.block(alternative.ChildByFieldName("body"))
		}
	}
	if !nt {
		branches = append(branches, no)
	} else {
		f.returns = pyCombine(f.returns, pyTransfer(no.returns, f.module.evidence("branch_false_precondition", test)))
	}
	if len(branches) > 0 {
		f.merge(branches...)
		if len(branches) == 1 {
			f.context = branches[0].context
		}
	}
	return yt && nt
}

func (f *pythonFlow) withBlock(n *sitter.Node) bool {
	for i := uint(0); i < n.NamedChildCount(); i++ {
		c := n.NamedChild(i)
		if c.Kind() == "with_clause" {
			for j := uint(0); j < c.NamedChildCount(); j++ {
				item := c.NamedChild(j)
				v := item.ChildByFieldName("value")
				if v == nil && item.NamedChildCount() > 0 {
					v = item.NamedChild(0)
				}
				if v != nil && v.Kind() == "as_pattern" {
					value := f.eval(v.NamedChild(0))
					alias := v.ChildByFieldName("alias")
					if alias != nil {
						f.env[pyText(f.module, alias)] = value
					}
				} else {
					f.eval(v)
				}
			}
		}
	}
	return f.block(n.ChildByFieldName("body"))
}

func (f *pythonFlow) tryBlock(n *sitter.Node) bool {
	// Except handlers see possible prefixes of the try body, not only its final state.
	base := f.clone()
	body := f.clone()
	var branches []*pythonFlow
	var final *sitter.Node
	for i := uint(0); i < n.NamedChildCount(); i++ {
		if c := n.NamedChild(i); c.Kind() == "finally_clause" {
			final = c
			gap := f.gap("python_finally_unresolved", "finally may override earlier returns or mutate their values", c)
			f.gaps = append(f.gaps, gap)
			base.gaps = append(base.gaps, gap)
			body.gaps = append(body.gaps, gap)
		}
	}
	body.context = append(body.context, f.module.evidence("try_precondition", n.ChildByFieldName("body")))
	prefixes := []*pythonFlow{base.clone()}
	terminated := false
	tryBody := n.ChildByFieldName("body")
	if tryBody != nil {
		for i := uint(0); i < tryBody.NamedChildCount(); i++ {
			terminated = body.stmt(tryBody.NamedChild(i))
			prefixes = append(prefixes, body.clone())
			if terminated {
				break
			}
		}
	}
	base.merge(prefixes...)
	if !terminated {
		for i := uint(0); i < n.NamedChildCount(); i++ {
			if c := n.NamedChild(i); c.Kind() == "else_clause" {
				terminated = body.block(pyBody(c))
			}
		}
	}
	if terminated {
		f.returns = pyCombine(f.returns, body.returns)
	} else {
		branches = append(branches, body)
	}
	for i := uint(0); i < n.NamedChildCount(); i++ {
		c := n.NamedChild(i)
		if c.Kind() != "except_clause" {
			continue
		}
		branch := base.clone()
		branch.context = append(branch.context, f.module.evidence("exception_precondition", c))
		if branch.block(pyBody(c)) {
			f.returns = pyCombine(f.returns, branch.returns)
		} else {
			branches = append(branches, branch)
		}
	}
	if len(branches) > 0 {
		f.merge(branches...)
	}
	if final != nil && f.block(pyBody(final)) {
		return true
	}
	return len(branches) == 0
}

func (f *pythonFlow) methodCondition(n *sitter.Node) (bool, bool) {
	if n == nil || n.Kind() != "comparison_operator" || n.NamedChildCount() != 2 {
		return false, false
	}
	a, b := n.NamedChild(0), n.NamedChild(1)
	literal, ok := pyLiteral(f.module, b)
	if !ok {
		a, b = b, a
		literal, ok = pyLiteral(f.module, b)
	}
	if !ok || f.qualified(pyText(f.module, a)) != "flask.request.method" {
		return false, false
	}
	op := pyText(f.module, n.ChildByFieldName("operators"))
	switch op {
	case "==":
		return f.route.route.Method == literal, true
	case "!=":
		return f.route.route.Method != literal, true
	}
	return false, false
}
