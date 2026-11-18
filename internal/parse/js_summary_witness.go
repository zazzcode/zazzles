package parse

import (
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
)

const jsWitnessInstructionLimit = 2048

// jsWitnessPlan is an immutable instruction DAG. Syntax is compiled once;
// operations and sink facts are instantiated by the ordinary flow models.
type jsWitnessPlan struct {
	module         *sourceModule
	fn             *sitter.Node
	params         []boundParam
	statements     []*sitter.Node
	exprs          map[uintptr]*jsWitnessExpr
	calls          map[uintptr]*jsWitnessPlan
	reasons        []summaryReason
	cost           int
	reads, returns uint64
	sinks          []jsWitnessSink
	transforms     []analysis.Span
	done           bool
	nested         bool
}

type jsWitnessSink struct {
	At         analysis.Span
	Parameters uint64
}
type jsWitnessExpr struct {
	node       *sitter.Node
	children   []*jsWitnessExpr
	parameters uint64
}

func (p *jsWitnessPlan) supported() bool { return p != nil && p.done && len(p.reasons) == 0 }
func (p *jsWitnessPlan) reject(kind string, n *sitter.Node) {
	p.reasons = append(p.reasons, summaryReason{Kind: kind, At: spanOf(p.module.file, n)})
}

func (s *moduleSet) jsWitnessPlan(m *sourceModule, fn *sitter.Node) *jsWitnessPlan {
	if s.witnessPlans == nil {
		s.witnessPlans = map[string]*jsWitnessPlan{}
	}
	old := s.summaryNoLoad
	s.summaryNoLoad = true
	defer func() { s.summaryNoLoad = old }()
	return s.buildJSWitnessPlan(m, fn, 0)
}

func (s *moduleSet) buildJSWitnessPlan(m *sourceModule, fn *sitter.Node, depth int) *jsWitnessPlan {
	key := summaryKey(m, fn)
	if p := s.witnessPlans[key]; p != nil {
		return p
	}
	p := &jsWitnessPlan{module: m, fn: fn, exprs: map[uintptr]*jsWitnessExpr{}, calls: map[uintptr]*jsWitnessPlan{}}
	s.witnessPlans[key] = p
	defer func() { p.done = true }()
	if fn.HasError() {
		p.reject("unsupported_callable", fn)
		return p
	}
	for i := uint(0); i < fn.ChildCount(); i++ {
		if child := fn.Child(i); child != nil && child.Kind() == "async" {
			p.reject("unsupported_async", fn)
			return p
		}
	}
	if depth >= 64 {
		p.reject("summary_limit", fn)
		return p
	}
	for parent := fn.Parent(); parent != nil; parent = parent.Parent() {
		if supportedCallee(parent) || parent.Kind() == "method_definition" {
			p.nested = true
			break
		}
	}
	params, ok := functionParameters(fn, m.src)
	if !ok || len(params) > 64 {
		p.reject("unsupported_parameters", fn)
		return p
	}
	p.params = params
	locals := map[string]bool{}
	bindings := map[string]uint64{}
	for i, param := range params {
		if param.optional {
			p.reject("unsupported_parameters", param.node)
		}
		locals[param.name] = true
		bindings[param.name] = 1 << uint(i)
	}
	c := jsWitnessCompiler{set: s, plan: p, locals: locals, bindings: bindings, depth: depth}
	body := fn.ChildByFieldName("body")
	if body == nil {
		p.reject("unsupported_callable", fn)
		return p
	}
	if body.Kind() != "statement_block" {
		if c.expression(body) != nil {
			p.statements = append(p.statements, body)
			p.returns = p.exprs[body.Id()].parameters
		}
		return p
	}
	for i := uint(0); i < body.NamedChildCount(); i++ {
		stmt := body.NamedChild(i)
		p.cost++
		switch stmt.Kind() {
		case "comment", "empty_statement", "function_declaration":
		case "lexical_declaration", "variable_declaration":
			for j := uint(0); j < stmt.NamedChildCount(); j++ {
				d := stmt.NamedChild(j)
				if d.Kind() == "comment" {
					continue
				}
				name := d.ChildByFieldName("name")
				if d.Kind() != "variable_declarator" || name == nil || name.Kind() != "identifier" {
					p.reject("unsupported_binding", d)
					continue
				}
				expr := c.expression(d.ChildByFieldName("value"))
				if expr != nil {
					c.bindings[name.Utf8Text(m.src)] = expr.parameters
				}
				c.locals[name.Utf8Text(m.src)] = true
			}
		case "return_statement", "expression_statement":
			for j := uint(0); j < stmt.NamedChildCount(); j++ {
				expr := c.expression(stmt.NamedChild(j))
				if stmt.Kind() == "return_statement" && expr != nil {
					p.returns |= expr.parameters
				}
			}
		default:
			p.reject("unsupported_control_flow", stmt)
		}
		p.statements = append(p.statements, stmt)
		if p.cost > jsWitnessInstructionLimit {
			p.reject("summary_limit", stmt)
			break
		}
		if stmt.Kind() == "return_statement" {
			break
		}
	}
	return p
}

type jsWitnessCompiler struct {
	set      *moduleSet
	plan     *jsWitnessPlan
	locals   map[string]bool
	bindings map[string]uint64
	depth    int
}

func (c *jsWitnessCompiler) expression(n *sitter.Node) *jsWitnessExpr {
	if n == nil {
		return nil
	}
	p, m := c.plan, c.plan.module
	if e := p.exprs[n.Id()]; e != nil {
		return e
	}
	e := &jsWitnessExpr{node: n}
	p.exprs[n.Id()] = e
	p.cost++
	if p.cost > jsWitnessInstructionLimit {
		p.reject("summary_limit", n)
		return e
	}
	child := func(n *sitter.Node) {
		if x := c.expression(n); x != nil {
			e.children = append(e.children, x)
		}
	}
	switch n.Kind() {
	case "identifier", "shorthand_property_identifier":
		name := n.Utf8Text(m.src)
		e.parameters = c.bindings[name]
		p.reads |= e.parameters
		if !c.locals[name] && (p.nested || moduleBindingClass(c.set, m, n, name) != "constant") {
			p.reject("ambient_binding", n)
		}
	case "number", "string", "true", "false", "null", "undefined", "property_identifier", "type_identifier", "comment", "string_fragment", "escape_sequence", "regex", "regex_pattern", "regex_flags":
	case "call_expression":
		fn, args := n.ChildByFieldName("function"), n.ChildByFieldName("arguments")
		if fn == nil || callHasSpread(n) {
			p.reject("unsupported_binding", n)
			break
		}
		if fn.Kind() == "member_expression" && !jsWitnessStaticReceiver(fn.ChildByFieldName("object")) {
			p.reject("dynamic_receiver", n)
			break
		}
		root := summaryCalleeRoot(fn, m.src)
		if c.locals[root] || !jsWitnessStableName(m, root) {
			p.reject("dynamic_callee", n)
			break
		}
		if hm, helper := c.set.resolveCall(m, n); helper != nil && supportedCallee(helper) {
			if name := jsWitnessDeclarationName(helper, hm.src); name != "" && !jsWitnessStableName(hm, name) {
				p.reject("dynamic_callee", n)
				break
			}
			target := c.set.buildJSWitnessPlan(hm, helper, c.depth+1)
			p.calls[n.Id()] = target
			if !target.supported() || len(callArgumentsJS(n)) != len(target.params) {
				p.reject("callee_not_supported", n)
			} else {
				p.cost += target.cost
				if p.cost > jsWitnessInstructionLimit {
					p.reject("summary_limit", n)
				}
			}
		} else if !c.nativeCall(n, fn) {
			p.reject("unmodeled_call", n)
		}
		for i := uint(0); args != nil && i < args.NamedChildCount(); i++ {
			child(args.NamedChild(i))
		}
	case "assignment_expression", "augmented_assignment_expression":
		left := n.ChildByFieldName("left")
		if left == nil || left.Kind() != "identifier" || !c.locals[left.Utf8Text(m.src)] {
			p.reject("heap_or_ambient_write", n)
		}
		child(n.ChildByFieldName("right"))
	case "member_expression":
		child(n.ChildByFieldName("object"))
	case "subscript_expression":
		child(n.ChildByFieldName("object"))
		child(n.ChildByFieldName("index"))
	case "pair":
		key := n.ChildByFieldName("key")
		if key == nil || (key.Kind() != "property_identifier" && key.Kind() != "string" && key.Kind() != "number") {
			p.reject("unsupported_binding", n)
		}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			child(n.NamedChild(i))
		}
	case "array", "object", "binary_expression", "unary_expression", "parenthesized_expression", "template_string", "template_substitution", "as_expression", "satisfies_expression", "non_null_expression", "type_annotation", "predefined_type":
		if n.Kind() == "unary_expression" {
			if op := n.ChildByFieldName("operator"); op != nil && op.Utf8Text(m.src) == "delete" {
				p.reject("heap_or_ambient_write", n)
			}
		}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			child(n.NamedChild(i))
		}
	default:
		p.reject("unsupported_expression", n)
	}
	for _, ch := range e.children {
		e.parameters |= ch.parameters
	}
	if n.Kind() == "call_expression" {
		if target := p.calls[n.Id()]; target != nil && target.supported() {
			e.parameters = 0
			for i, arg := range e.children {
				if target.returns&(1<<uint(i)) != 0 {
					e.parameters |= arg.parameters
				}
			}
			for _, sink := range target.sinks {
				mapped := uint64(0)
				for i, arg := range e.children {
					if sink.Parameters&(1<<uint(i)) != 0 {
						mapped |= arg.parameters
					}
				}
				p.sinks = append(p.sinks, jsWitnessSink{sink.At, mapped})
			}
		} else if c.nativeSink(n, n.ChildByFieldName("function")) {
			p.sinks = append(p.sinks, jsWitnessSink{spanOf(m.file, n), e.parameters})
		} else {
			p.transforms = append(p.transforms, spanOf(m.file, n))
		}
	}
	if n.Kind() == "assignment_expression" || n.Kind() == "augmented_assignment_expression" {
		if left := n.ChildByFieldName("left"); left != nil && left.Kind() == "identifier" {
			if n.Kind() == "augmented_assignment_expression" {
				e.parameters |= c.bindings[left.Utf8Text(m.src)]
			}
			c.bindings[left.Utf8Text(m.src)] = e.parameters
		}
	}
	return e
}

func (c *jsWitnessCompiler) nativeSink(call, fn *sitter.Node) bool {
	if fn == nil {
		return false
	}
	f := &flow{set: c.set, module: c.plan.module}
	if c.sqlCall(call, fn) {
		return true
	}
	if _, _, ok := f.nodeCommandBinding(call, fn); ok {
		return true
	}
	if _, ok := f.logSink(call, fn); ok {
		return true
	}
	if _, ok := fsMember(c.plan.module, call, fn); ok {
		return true
	}
	return fn.Kind() == "identifier" && fn.Utf8Text(c.plan.module.src) == "eval"
}

func (c *jsWitnessCompiler) nativeCall(call, fn *sitter.Node) bool {
	m := c.plan.module
	f := &flow{set: c.set, module: m}
	if c.sqlCall(call, fn) {
		return true
	}
	if _, _, ok := f.nodeCommandBinding(call, fn); ok {
		return true
	}
	if _, ok := f.logSink(call, fn); ok {
		return true
	}
	if _, ok := fsMember(m, call, fn); ok {
		// Template file reads would extend the scan's loaded source snapshot.
		for _, arg := range callArgumentsJS(call) {
			if text, ok := stringLiteral(arg, m.src); ok && (strings.HasSuffix(text, ".ejs") || strings.HasSuffix(text, ".pug") || strings.HasSuffix(text, ".hbs") || strings.HasSuffix(text, ".handlebars")) {
				return false
			}
		}
		return true
	}
	if fn.Kind() == "identifier" {
		name := fn.Utf8Text(m.src)
		switch name {
		case "String", "Number", "Boolean", "parseInt", "parseFloat", "encodeURI", "encodeURIComponent", "decodeURI", "decodeURIComponent", "eval":
			return !moduleBinds(m, name) && !m.cachedShadowed(call, name)
		}
	}
	r := c.set.resolveCallSite(m, call)
	switch r.Kind {
	case callKnownClass, callBuiltinMethod, callPackageMember:
		return jsIndependentResults[r.Receiver][r.Method]
	}
	return false
}

func callArgumentsJS(call *sitter.Node) []*sitter.Node {
	var out []*sitter.Node
	args := call.ChildByFieldName("arguments")
	for i := uint(0); args != nil && i < args.NamedChildCount(); i++ {
		out = append(out, args.NamedChild(i))
	}
	return out
}

func (c *jsWitnessCompiler) sqlCall(call, fn *sitter.Node) bool {
	if c.set.verifiedSQLLibrarySink(c.plan.module, call) {
		return true
	}
	if _, ok := sqlJSCall(c.plan.module, fn); ok {
		return true
	}
	if fn.Kind() == "member_expression" {
		if prop := fn.ChildByFieldName("property"); prop != nil && prop.Utf8Text(c.plan.module.src) == "query" {
			return len(c.set.queryBinding(analysis.CandidateUse{Sink: c.plan.module.evidence("sql_query_candidate", call)})) > 0
		}
	}
	return false
}

// A newly resolved summary path cannot inherit the legacy resolver's loose
// treatment of reassigned declarations or mutated imported namespaces.
func jsWitnessStableName(m *sourceModule, name string) bool {
	writes := m.bindingWrites()
	return !writes.assigned[name] && !writes.written[name]
}
func jsWitnessDeclarationName(fn *sitter.Node, src []byte) string {
	if name := fn.ChildByFieldName("name"); name != nil {
		return name.Utf8Text(src)
	}
	if parent := fn.Parent(); parent != nil && parent.Kind() == "variable_declarator" {
		if name := parent.ChildByFieldName("name"); name != nil && name.Kind() == "identifier" {
			return name.Utf8Text(src)
		}
	}
	return ""
}

// Qualified namespace receivers contain no executable operand subtree. A
// constructed/call/computed receiver needs its own lowering before a recipe
// can promise that all effects and parameter reads have been preflighted.
func jsWitnessStaticReceiver(n *sitter.Node) bool {
	for n != nil && n.Kind() == "member_expression" {
		property := n.ChildByFieldName("property")
		if property == nil || property.Kind() != "property_identifier" {
			return false
		}
		n = n.ChildByFieldName("object")
	}
	return n != nil && n.Kind() == "identifier"
}
