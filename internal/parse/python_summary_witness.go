package parse

import (
	"fmt"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
)

const pythonWitnessInstructionLimit = 4096

// A witness recipe keeps original syntax spans but lowers body traversal and
// lexical binding once. Parameter masks describe each operation's input facts;
// application uses the native expression and sink models for actual values.
type pythonWitnessExpr struct {
	node      *sitter.Node
	children  []*pythonWitnessExpr
	reads     uint64
	effectful bool
}
type pythonWitnessOp struct {
	expr     *pythonWitnessExpr
	name     string
	returned bool
}
type pythonWitnessPlan struct {
	module            *pythonModule
	fn                *sitter.Node
	params            []string
	ops               []pythonWitnessOp
	instructions      int
	reason            string
	building          bool
	requiresSelection bool
	effectful         bool
}
type pythonWitnessCompiler struct {
	set     *pythonSet
	plan    *pythonWitnessPlan
	names   map[string]uint64
	defined map[string]bool
}

func (s *pythonSet) witnessPlan(m *pythonModule, fn *sitter.Node) *pythonWitnessPlan {
	if s.witnessPlans == nil {
		s.witnessPlans = map[string]*pythonWitnessPlan{}
	}
	return s.compileWitnessPlan(m, fn, 0)
}
func (s *pythonSet) compileWitnessPlan(m *pythonModule, fn *sitter.Node, depth int) *pythonWitnessPlan {
	key := fmt.Sprintf("%s:%d", m.file, fn.StartByte())
	if p := s.witnessPlans[key]; p != nil {
		return p
	}
	p := &pythonWitnessPlan{module: m, fn: fn, building: true}
	s.witnessPlans[key] = p
	defer func() { p.building = false }()
	reject := func(reason string) *pythonWitnessPlan { p.reason = reason; return p }
	if depth >= 64 {
		return reject("summary_limit")
	}
	if fn.HasError() || fn.Kind() != "function_definition" || fn.Parent() != nil && fn.Parent().Kind() == "decorated_definition" {
		return reject("unsupported_callable")
	}
	for i := uint(0); i < fn.ChildCount(); i++ {
		if fn.Child(i).Kind() == "async" {
			return reject("unsupported_async")
		}
	}
	c := &pythonWitnessCompiler{set: s, plan: p, names: map[string]uint64{}, defined: map[string]bool{}}
	params := fn.ChildByFieldName("parameters")
	for i := uint(0); params != nil && i < params.NamedChildCount(); i++ {
		n := params.NamedChild(i)
		if i >= 64 || n.Kind() != "identifier" {
			return reject("unsupported_parameters")
		}
		name := pyText(m, n)
		if c.defined[name] {
			return reject("unsupported_parameters")
		}
		p.params = append(p.params, name)
		c.names[name] = 1 << i
		c.defined[name] = true
	}
	body := fn.ChildByFieldName("body")
	if body == nil {
		return reject("unsupported_body")
	}
	for i := uint(0); i < body.NamedChildCount(); i++ {
		n := body.NamedChild(i)
		op := pythonWitnessOp{}
		switch n.Kind() {
		case "comment", "pass_statement":
			continue
		case "return_statement":
			op.returned = true
			if n.NamedChildCount() > 0 {
				op.expr = c.expression(n.NamedChild(0), depth)
			}
		case "expression_statement":
			if n.NamedChildCount() != 1 {
				return reject("unsupported_statement")
			}
			expr := n.NamedChild(0)
			if expr.Kind() == "assignment" {
				left := expr.ChildByFieldName("left")
				if left == nil || left.Kind() != "identifier" {
					return reject("heap_write")
				}
				if expr.ChildByFieldName("type") != nil {
					return reject("unsupported_binding")
				}
				op.name = pyText(m, left)
				op.expr = c.expression(expr.ChildByFieldName("right"), depth)
				if op.expr != nil {
					op.expr = &pythonWitnessExpr{node: expr, children: []*pythonWitnessExpr{op.expr}, reads: op.expr.reads, effectful: op.expr.effectful}
					p.instructions++
					c.names[op.name] = op.expr.reads
					c.defined[op.name] = true
				}
			} else {
				op.expr = c.expression(expr, depth)
			}
		default:
			return reject("unsupported_control_flow")
		}
		if p.reason != "" {
			return p
		}
		if op.expr != nil {
			p.effectful = p.effectful || op.expr.effectful
		}
		p.ops = append(p.ops, op)
		if p.instructions > pythonWitnessInstructionLimit {
			return reject("summary_limit")
		}
		if op.returned {
			break
		}
	}
	return p
}
func (c *pythonWitnessCompiler) expression(n *sitter.Node, depth int) *pythonWitnessExpr {
	if n == nil {
		return nil
	}
	p, m := c.plan, c.plan.module
	fail := func(reason string) *pythonWitnessExpr { p.reason = reason; return nil }
	if p.instructions >= pythonWitnessInstructionLimit {
		return fail("summary_limit")
	}
	e := &pythonWitnessExpr{node: n}
	p.instructions++
	add := func(n *sitter.Node) bool {
		child := c.expression(n, depth)
		if n != nil && child == nil {
			return false
		}
		if child != nil {
			e.children = append(e.children, child)
			e.reads |= child.reads
			e.effectful = e.effectful || child.effectful
		}
		return true
	}
	switch n.Kind() {
	case "identifier":
		name := pyText(m, n)
		if c.defined[name] {
			e.reads = c.names[name]
			return e
		}
		if _, ok := pyStaticString(m, m.vars[name]); ok {
			idx := m.bindingIndex()
			if c.set.staticInvalid[m.file+":"+name] || m.unsafeWitnessBindings() || idx.writes[name] != 1 || idx.aliased[name] {
				return fail("mutable_module_binding")
			}
			return e
		}
		if m.imports[name].node != nil && !c.set.staticInvalid[m.file+":"+name] {
			return e
		}
		return fail("ambient_binding")
	case "integer", "float", "true", "false", "none", "string_start", "string_end", "string_content":
		return e
	case "call":
		fn := n.ChildByFieldName("function")
		name := pyText(m, fn)
		root := strings.Split(name, ".")[0]
		target, key := c.set.resolve(m, name, 0)
		if target != nil && target.funcs[key] != nil && !c.defined[root] && c.set.stableWitnessReference(m, name) && !c.set.staticInvalid[target.file+":"+key] {
			d := c.set.compileWitnessPlan(target, target.funcs[key], depth+1)
			if d.building || d.reason != "" {
				return fail("callee_not_supported")
			}
			args := n.ChildByFieldName("arguments")
			if args == nil && len(d.params) != 0 || args != nil && int(args.NamedChildCount()) != len(d.params) {
				return fail("unsupported_arguments")
			}
			p.instructions += d.instructions
			p.requiresSelection = p.requiresSelection || d.requiresSelection
			e.effectful = d.effectful
		} else if !c.nativeCall(n) {
			return fail("unmodeled_call")
		}

		args := n.ChildByFieldName("arguments")
		for i := uint(0); args != nil && i < args.NamedChildCount(); i++ {
			a := args.NamedChild(i)
			if a.Kind() == "keyword_argument" {
				return fail("unsupported_arguments")
			}
			if strings.Contains(a.Kind(), "splat") {
				return fail("unsupported_arguments")
			}
			if !add(a) {
				return nil
			}
		}
		if fn != nil && fn.Kind() == "attribute" {
			if !add(fn.ChildByFieldName("object")) {
				return nil
			}
		}
		if c.set.qualified(m, name) == "importlib.import_module" {
			p.requiresSelection = true
		}
		if target == nil || target.funcs[key] == nil {
			q := c.set.qualified(m, name)
			switch name {
			case "print", "eval", "exec", "open":
				e.effectful = true
			}
			if strings.HasPrefix(q, "os.") || strings.HasPrefix(q, "subprocess.") || strings.HasPrefix(q, "logging.") {
				e.effectful = true
			}
		}

		return e
	case "attribute":
		if !add(n.ChildByFieldName("object")) {
			return nil
		}
		return e
	case "subscript":
		if !add(n.ChildByFieldName("value")) || !add(n.ChildByFieldName("subscript")) {
			return nil
		}
		return e
	case "string", "interpolation", "binary_operator", "boolean_operator", "comparison_operator", "unary_operator", "not_operator", "parenthesized_expression", "list", "tuple", "expression_list":
		for i := uint(0); i < n.NamedChildCount(); i++ {
			if !add(n.NamedChild(i)) {
				return nil
			}
		}
		return e
	default:
		return fail("unsupported_expression")
	}
}
func (c *pythonWitnessCompiler) nativeCall(n *sitter.Node) bool {
	m := c.plan.module
	fn := n.ChildByFieldName("function")
	name := pyText(m, fn)
	root := strings.Split(name, ".")[0]
	if c.defined[root] {
		return false
	}
	if !c.set.stableWitnessReference(m, name) {
		return false
	}
	if fn != nil && fn.Kind() == "identifier" {
		if c.defined[name] || m.vars[name] != nil || m.funcs[name] != nil {
			return false
		}
		if m.imports[name].node == nil {
			switch name {
			case "str", "int", "float", "bool", "len", "print", "eval", "exec", "open":
				return true
			}
		}
	}
	q := c.set.qualified(m, name)

	switch q {
	case "os.system", "os.popen", "os.execl", "os.execle", "os.execlp", "os.execv", "os.execve", "os.execvp", "os.execvpe",
		"subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.check_output", "subprocess.Popen", "subprocess.getoutput", "subprocess.getstatusoutput",
		"shlex.quote", "html.escape", "markupsafe.escape", "urllib.parse.quote", "urllib.parse.quote_plus", "urllib.parse.unquote", "urllib.parse.unquote_plus", "urllib.parse.urlencode",
		"importlib.import_module":
		return true
	}
	if strings.HasPrefix(q, "logging.") {
		return true
	}
	if fn != nil && fn.Kind() == "attribute" {
		if _, literal := pyLiteral(m, fn.ChildByFieldName("object")); !literal {
			return false
		}
		switch pyText(m, fn.ChildByFieldName("attribute")) {
		case "format", "join", "strip", "lower", "upper", "split", "replace":
			return true
		}
	}
	return false
}
func (f *pythonFlow) witnessExpression(e *pythonWitnessExpr) pythonValue {
	if e == nil {
		return pythonValue{}
	}
	for _, child := range e.children {
		if child.effectful {
			continue
		}
		v := f.witnessExpression(child)
		f.witnessValues[child.node.Id()] = v
	}
	// The node itself must execute through the native model once, even if a
	// previous operation referenced the same immutable syntax node.
	delete(f.witnessValues, e.node.Id())
	return f.eval(e.node)
}
func (f *pythonFlow) applyWitness(call *sitter.Node, target *pythonBoundCallable, args []pythonValue) (pythonValue, bool) {
	if len(target.closure) > 0 {
		return pythonValue{}, false
	}
	p := f.set.witnessPlan(target.module, target.fn)
	if p.building || p.reason != "" || len(args) != len(p.params) || p.instructions > pythonWitnessInstructionLimit {
		return pythonValue{}, false
	}
	if p.requiresSelection && !f.provenImportPlan(call, target, args, p) {
		return pythonValue{}, false
	}
	nodes := call.ChildByFieldName("arguments")
	if nodes == nil || int(nodes.NamedChildCount()) != len(args) {
		return pythonValue{}, false
	}
	for i := uint(0); i < nodes.NamedChildCount(); i++ {
		a := nodes.NamedChild(i)
		if a.Kind() == "keyword_argument" || strings.Contains(a.Kind(), "splat") {
			return pythonValue{}, false
		}
	}
	// The entire DAG, including callees and instruction count, has been checked
	// before creating a frame or letting native models emit any uses.
	return f.helperFrame(call, target, args, p), true
}
