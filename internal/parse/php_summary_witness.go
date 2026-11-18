package parse

import (
	"fmt"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
)

// A witness recipe contains only callable-local operations and source nodes.
// It never contains a caller value, candidate ID, protection verdict or flow.
const phpWitnessMaxCost = 1024

type phpWitnessParam struct {
	name string
	node *sitter.Node
}
type phpWitnessExpr struct {
	kind       string
	node       *sitter.Node
	name       string
	args       []*phpWitnessExpr
	callee     *phpWitnessProgram
	parameters uint64
}
type phpWitnessStep struct {
	kind string
	expr *phpWitnessExpr
}
type phpWitnessSink struct {
	at         analysis.Span
	family     string
	argument   int
	parameters uint64
}
type phpWitnessProgram struct {
	returns uint64
	sinks   []phpWitnessSink
	module  *phpModule
	fn      *sitter.Node
	params  []phpWitnessParam
	steps   []phpWitnessStep
	reason  string
	done    bool
	cost    int
}

func (p *phpWitnessProgram) supported() bool { return p != nil && p.done && p.reason == "" }
func (s *phpSet) phpWitness(m *phpModule, fn *sitter.Node) *phpWitnessProgram {
	if s.witnessPrograms == nil {
		s.witnessPrograms = map[string]*phpWitnessProgram{}
	}
	return s.buildPHPWitness(m, fn, 0)
}
func (s *phpSet) buildPHPWitness(m *phpModule, fn *sitter.Node, depth int) *phpWitnessProgram {
	key := fmt.Sprintf("%s:%d", m.file, fn.StartByte())
	if p := s.witnessPrograms[key]; p != nil {
		return p
	}
	p := &phpWitnessProgram{module: m, fn: fn, cost: 1}
	s.witnessPrograms[key] = p
	defer func() { p.done = true }()
	reject := func(reason string) *phpWitnessProgram { p.reason = reason; return p }
	if depth >= 64 {
		return reject("summary_limit")
	}
	if fn.Kind() != "function_definition" || fn.HasError() {
		return reject("unsupported_callable")
	}
	for i := uint(0); i < fn.NamedChildCount(); i++ {
		if fn.NamedChild(i).Kind() == "reference_modifier" {
			return reject("unsupported_callable")
		}
	}
	s.indexBuiltinEffects()
	if s.builtinEffects["module:"+m.file] {
		return reject("unsupported_namespace")
	}
	params := phpField(fn, "parameters")
	locals := map[string]uint64{}
	for i := uint(0); params != nil && i < params.NamedChildCount(); i++ {
		node := params.NamedChild(i)
		name := phpVarName(m, phpField(node, "name"))
		if i >= 64 || node.Kind() != "simple_parameter" || name == "" || phpWitnessStateName(name) || phpField(node, "default_value") != nil {
			return reject("unsupported_parameters")
		}
		for j := uint(0); j < node.NamedChildCount(); j++ {
			if node.NamedChild(j).Kind() == "reference_modifier" {
				return reject("unsupported_parameters")
			}
		}
		if _, exists := locals[name]; exists {
			return reject("unsupported_parameters")
		}
		p.params = append(p.params, phpWitnessParam{name, node})
		locals[name] = 1 << i
		p.cost++
	}
	c := phpWitnessCompiler{set: s, program: p, locals: locals, depth: depth}
	body := phpField(fn, "body")
	for i := uint(0); body != nil && i < body.NamedChildCount(); i++ {
		node := body.NamedChild(i)
		switch node.Kind() {
		case "comment":
			continue
		case "expression_statement", "echo_statement", "return_statement":
			if node.Kind() == "return_statement" && node.NamedChildCount() == 0 {
				p.steps = append(p.steps, phpWitnessStep{kind: "return"})
				return p
			}
			for j := uint(0); j < node.NamedChildCount(); j++ {
				expr := c.expression(node.NamedChild(j))
				kind := "expression"
				if node.Kind() == "echo_statement" {
					kind = "echo"
				}
				if node.Kind() == "return_statement" {
					kind = "return"
				}
				p.steps = append(p.steps, phpWitnessStep{kind, expr})
				if expr != nil && kind == "return" {
					p.returns |= expr.parameters
				}
				if expr != nil && kind == "echo" {
					p.sinks = append(p.sinks, phpWitnessSink{at: spanOf(m.file, expr.node), family: "xss", parameters: expr.parameters})
				}
			}
			if node.Kind() == "return_statement" {
				return p
			}
		default:
			p.reason = "unsupported_statement"
			return p
		}
		if p.reason != "" {
			return p
		}
	}
	return p
}

type phpWitnessCompiler struct {
	set     *phpSet
	program *phpWitnessProgram
	locals  map[string]uint64
	depth   int
}

func (c *phpWitnessCompiler) fail(reason string) *phpWitnessExpr {
	if c.program.reason == "" {
		c.program.reason = reason
	}
	return nil
}
func (c *phpWitnessCompiler) expression(n *sitter.Node) *phpWitnessExpr {
	p, m := c.program, c.program.module
	if n == nil {
		return c.fail("unsupported_expression")
	}
	p.cost++
	if p.cost > phpWitnessMaxCost {
		return c.fail("summary_limit")
	}
	e := &phpWitnessExpr{kind: n.Kind(), node: n}
	switch n.Kind() {
	case "variable_name":
		e.name = phpVarName(m, n)
		var bound bool
		e.parameters, bound = c.locals[e.name]
		if !bound {
			return c.fail("ambient_read")
		}
	case "string", "encapsed_string":
		if _, ok := phpStringLiteral(m, n); !ok {
			return c.fail("unsupported_interpolation")
		}
	case "integer", "float", "true", "false", "null":
	case "parenthesized_expression", "cast_expression":
		for i := uint(0); i < n.NamedChildCount(); i++ {
			child := n.NamedChild(i)
			if child.Kind() == "cast_type" {
				continue
			}
			e.args = append(e.args, c.expression(child))
		}
		if len(e.args) != 1 {
			return c.fail("unsupported_expression")
		}
	case "binary_expression":
		e.name = phpOperator(m, n)
		e.args = []*phpWitnessExpr{c.expression(phpField(n, "left")), c.expression(phpField(n, "right"))}
	case "assignment_expression":
		left := phpField(n, "left")
		e.name = phpVarName(m, left)
		if e.name == "" || phpWitnessStateName(e.name) {
			return c.fail("heap_write")
		}
		e.args = []*phpWitnessExpr{c.expression(phpField(n, "right"))}
		if e.args[0] != nil {
			c.locals[e.name] = e.args[0].parameters
		}
	case "function_call_expression":
		callee := phpCallee(n)
		if callee == nil || callee.Kind() != "name" {
			return c.fail("dynamic_callee")
		}
		e.name = phpText(m, callee)
		for _, node := range phpArgs(n) {
			e.args = append(e.args, c.expression(node))
		}
		args := phpField(n, "arguments")
		for i := uint(0); args != nil && i < args.NamedChildCount(); i++ {
			arg := args.NamedChild(i)
			if arg.Kind() != "argument" || arg.NamedChildCount() != 1 {
				return c.fail("unsupported_binding")
			}
		}
		target := c.set.resolveFunction(m, e.name)
		builtin, min, max := phpWitnessBuiltin(e.name)
		if target != nil {
			if builtin {
				return c.fail("shadowed_builtin")
			}
			e.callee = c.set.buildPHPWitness(target.module, target.fn, c.depth+1)
			if !e.callee.done {
				return c.fail("summary_cycle")
			}
			if !e.callee.supported() {
				return c.fail("callee_not_supported")
			}
			if len(e.args) != len(e.callee.params) {
				return c.fail("unsupported_binding")
			}
			p.cost += e.callee.cost
			if p.cost > phpWitnessMaxCost {
				return c.fail("summary_limit")
			}
		} else {
			f := &phpFlow{set: c.set, module: m}
			if !builtin || !f.phpBuiltinEffectName(e.name) {
				return c.fail("unmodeled_call")
			}
			if len(e.args) < min || len(e.args) > max {
				return c.fail("unsupported_binding")
			}
		}
	default:
		return c.fail("unsupported_expression")
	}
	if e.kind != "variable_name" {
		for _, arg := range e.args {
			if arg != nil {
				e.parameters |= arg.parameters
			}
		}
	}
	if e.callee != nil {
		e.parameters = phpMapWitnessParams(e.callee.returns, e.args)
		for _, sink := range e.callee.sinks {
			p.sinks = append(p.sinks, phpWitnessSink{at: sink.at, family: sink.family, argument: sink.argument, parameters: phpMapWitnessParams(sink.parameters, e.args)})
		}
	} else if e.kind == "function_call_expression" {
		if family := phpWitnessSinkFamily(e.name); family != "" {
			arg := 0
			if family == "sql" {
				arg = 1
			}
			p.sinks = append(p.sinks, phpWitnessSink{at: spanOf(m.file, n), family: family, argument: arg, parameters: e.args[arg].parameters})
		}
	}
	return e
}

func phpMapWitnessParams(bits uint64, args []*phpWitnessExpr) uint64 {
	var out uint64
	for i, arg := range args {
		if bits&(1<<uint(i)) != 0 && arg != nil {
			out |= arg.parameters
		}
	}
	return out
}
func phpWitnessSinkFamily(name string) string {
	switch name {
	case "system", "exec", "shell_exec", "passthru":
		return "command"
	case "mysqli_query", "mysqli_real_query", "mysqli_multi_query", "mysqli_prepare":
		return "sql"
	case "file_get_contents", "readfile", "file", "unlink", "file_put_contents":
		return "path"
	case "eval":
		return "code"
	case "print":
		return "xss"
	}
	return ""
}

// The allowed call set includes only native modeled operations. APIs with
// implicit by-reference output arguments are bounded to their unary form.
func phpWitnessBuiltin(name string) (bool, int, int) {
	switch name {
	case "system", "exec", "shell_exec", "passthru", "htmlspecialchars", "htmlentities",
		"urlencode", "rawurlencode", "strip_tags", "intval", "floatval", "doubleval",
		"escapeshellarg", "escapeshellcmd", "basename", "realpath", "md5", "sha1", "strlen",
		"strtoupper", "strtolower", "trim", "ltrim", "rtrim", "ucfirst", "ucwords", "strrev",
		"nl2br", "stripslashes", "base64_encode", "base64_decode", "addslashes",
		"print", "eval", "file_get_contents", "readfile", "file", "unlink":
		return true, 1, 1
	case "mysqli_query", "mysqli_real_query", "mysqli_multi_query", "mysqli_prepare", "mysqli_real_escape_string":
		return true, 2, 2
	case "json_decode":
		return true, 1, 4
	case "strrpos":
		return true, 2, 3
	case "file_put_contents":
		return true, 2, 2
	}
	return false, 0, 0
}
func phpWitnessPlainArguments(call *sitter.Node, count int) bool {
	args := phpField(call, "arguments")
	if args == nil {
		return count == 0
	}
	if int(args.NamedChildCount()) != count {
		return false
	}
	for i := uint(0); i < args.NamedChildCount(); i++ {
		node := args.NamedChild(i)
		if node.Kind() != "argument" || node.NamedChildCount() != 1 {
			return false
		}
	}
	return true
}
func (f *phpFlow) applyPHPWitness(call *sitter.Node, target *phpBoundCallable, args []phpValue) (phpValue, bool) {
	if target == nil || target.object != nil {
		return phpValue{}, false
	}
	p := f.set.phpWitness(target.module, target.fn)
	if !p.supported() || len(args) != len(p.params) || !phpWitnessPlainArguments(call, len(args)) {
		return phpValue{}, false
	}
	return f.instantiatePHPWitness(call, p, args), true
}
func (f *phpFlow) instantiatePHPWitness(call *sitter.Node, p *phpWitnessProgram, args []phpValue) phpValue {
	m := p.module
	f.context = append(f.context, m.evidence("helper_definition", p.fn), f.module.evidence("call_binding", call))
	h := f.clone()
	h.module = m
	h.depth++
	h.env = map[string]phpValue{}
	h.globals = map[string]phpValue{}
	for i, param := range p.params {
		h.env[param.name] = phpTransfer(args[i], m.evidence("argument_to_parameter", param.node))
	}
	terminated := false
	for _, step := range p.steps {
		v := h.phpWitnessValue(step.expr)
		switch step.kind {
		case "echo":
			h.render(step.expr.node, v)
		case "return":
			terminated = true
			h.returns = phpCombine(h.returns, v)
		}
	}
	if !terminated {
		h.returns.gaps = append(h.returns.gaps, h.gaps...)
	}
	f.gaps = phpMergeGaps(f.gaps, h.gaps)
	f.context = phpMergeEvidence(f.context, h.context)
	return phpTransfer(h.returns, f.module.evidence("helper_return", call))
}
func (f *phpFlow) phpWitnessValue(e *phpWitnessExpr) phpValue {
	if e == nil {
		return phpValue{}
	}
	switch e.kind {
	case "variable_name", "string", "encapsed_string", "integer", "float", "true", "false", "null":
		return f.eval(e.node)
	case "parenthesized_expression":
		return f.phpWitnessValue(e.args[0])
	case "cast_expression":
		return f.castValue(e.node, f.phpWitnessValue(e.args[0]))
	case "binary_expression":
		return f.binaryValues(e.node, e.name, f.phpWitnessValue(e.args[0]), f.phpWitnessValue(e.args[1]))
	case "assignment_expression":
		return f.assignValue(e.node, phpField(e.node, "left"), f.phpWitnessValue(e.args[0]))
	case "function_call_expression":
		values := make([]phpValue, len(e.args))
		var all phpValue
		for i, arg := range e.args {
			values[i] = f.phpWitnessValue(arg)
			all = phpCombine(all, values[i])
		}
		if e.callee != nil {
			return f.instantiatePHPWitness(e.node, e.callee, values)
		}
		return f.callValues(e.node, phpArgs(e.node), values, all)
	}
	panic("unvalidated PHP witness expression: " + strings.TrimSpace(e.kind))
}

func phpWitnessStateName(name string) bool {
	_, _, superglobal := superscriptOrigin(name)
	return superglobal || name == "GLOBALS" || name == "this"
}
