package parse

import (
	"fmt"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
)

// helperExpansion bounds one handler's helper-call traversal. The stack stops
// recursion along the current path; budget counts call expansions, not unique names.
type helperExpansion struct {
	budget int
	stack  map[string]bool
}

type boundParam struct {
	name string
	node *sitter.Node
	// optional marks a parameter with a default value, so omitting it is not unknown.
	optional bool
}

// enterHelper analyzes a same-file or relative-imported function body.
// entered means sinks inside the body were sought. precise means the call result
// is the modeled return value rather than a may-dependency on every argument.
func (f *flow) enterHelper(call *sitter.Node, name string, args []value) (ret value, entered bool, precise bool) {
	if f.helpers == nil || callHasSpread(call) {
		return value{}, false, false
	}
	hm, helper := f.set.resolveCall(f.module, call)
	if hm == nil || helper == nil || !supportedCallee(helper) {
		return value{}, false, false
	}
	params, ok := functionParameters(helper, hm.src)
	if !ok || len(args) > len(params) {
		return value{}, false, false
	}
	key := fmt.Sprintf("%s:%d", hm.file, helper.StartByte())
	if f.helpers.stack[key] {
		g := f.gap("recursive_helper", "recursive helper call is not re-entered: "+name, call)
		f.gaps = append(f.gaps, g)
		return value{}, false, false
	}
	if f.helpers.budget <= 0 || f.depth >= 3 {
		kind := "helper_call_limit"
		if f.pathOnly && pathUnrelatedHelper(args, helper) {
			kind = "path_unrelated_helper_limit"
		}
		f.gaps = append(f.gaps, f.gap(kind, "helper call expansion reached its depth or count limit: "+name, call))
		return value{}, false, false
	}
	f.helpers.budget--
	f.helpers.stack[key] = true
	defer delete(f.helpers.stack, key)

	f.context = append(f.context, hm.evidence("helper_definition", helper))
	before := len(f.gaps)
	child := flow{
		pathOnly:     f.pathOnly,
		urlSources:   f.urlSources,
		client:       f.client,
		registration: f.registration,
		module:       hm,
		set:          f.set,
		entry:        f.entry, invocation: f.invocation,
		env:     map[string]value{},
		context: append(append([]analysis.Evidence{}, f.context...), f.module.evidence("helper_call", call)),
		gaps:    append([]analysis.Gap{}, f.gaps...),
		depth:   f.depth + 1,
		helpers: f.helpers,
		facts:   f.facts,
	}
	unbound := false
	for i, p := range params {
		if i < len(args) {
			if f.urlSources && f.request != "" && call.ChildByFieldName("arguments") != nil {
				if argNode := call.ChildByFieldName("arguments").NamedChild(uint(i)); argNode != nil && argNode.Kind() == "identifier" && argNode.Utf8Text(f.module.src) == f.request {
					child.request = p.name
				}
			}
			// Bind on the callee flow so the parameter span stays in the callee file.
			child.env[p.name] = child.transfer(args[i], "parameter_binding", p.node)
			continue
		}
		if p.optional {
			child.env[p.name] = value{}
			continue
		}
		unbound = true
		child.env[p.name] = value{gaps: []analysis.Gap{{Kind: "unknown_value", Detail: "helper parameter has no argument: " + p.name, At: spanOf(hm.file, p.node)}}}
	}
	child.statements(helper.ChildByFieldName("body"))
	f.uses = append(f.uses, child.uses...)
	for _, g := range child.gaps[before:] {
		switch g.Kind {
		case "work_limit", "helper_call_limit", "recursive_helper":
			f.gaps = append(f.gaps, g)
		}
	}
	precise = len(child.returns) > 0 && !unbound
	for _, g := range child.gaps[before:] {
		switch g.Kind {
		case "unsupported_control_flow":
			// Branches merge as may-paths. They stay precise only when no condition
			// can act as a content guard for the values returned.
			if n := nodeAt(hm.tree.RootNode(), g.At.StartByte, g.At.EndByte); n == nil || n.Kind() != "if_statement" ||
				!contentNeutral(n.ChildByFieldName("condition"), helper, hm.src, 0) {
				precise = false
			}
		case "branch_exit", "work_limit", "unsupported_binding", "helper_call_limit", "recursive_helper":
			precise = false
		}
	}
	if !precise {
		return value{}, true, false
	}
	for _, r := range child.returns {
		ret = combine(ret, r)
	}
	if len(child.returns) > 1 {
		ret.gaps = append(ret.gaps, f.gap("conditional_merge", "multiple helper returns merged without path feasibility: "+name, call))
	}
	return ret, true, true
}

func supportedCallee(n *sitter.Node) bool {
	return n.Kind() == "function_declaration" || isFunction(n)
}

func functionParameters(fn *sitter.Node, src []byte) ([]boundParam, bool) {
	params := fn.ChildByFieldName("parameters")
	if params == nil {
		params = fn.ChildByFieldName("parameter")
	}
	if params == nil {
		return nil, true
	}
	// `value => ...` stores the identifier directly. `(value) => ...` wraps it.
	if params.Kind() == "identifier" {
		return []boundParam{{name: params.Utf8Text(src), node: params}}, true
	}
	out := []boundParam{}
	for i := uint(0); i < params.NamedChildCount(); i++ {
		node := params.NamedChild(i)
		if node.Kind() == "required_parameter" || node.Kind() == "optional_parameter" {
			node = node.ChildByFieldName("pattern")
		}
		optional := false
		if node != nil && node.Kind() == "assignment_pattern" {
			node, optional = node.ChildByFieldName("left"), true
		} else if outer := params.NamedChild(i); outer.ChildByFieldName("value") != nil {
			optional = true
		}
		if node == nil || node.Kind() != "identifier" {
			return nil, false
		}
		out = append(out, boundParam{name: node.Utf8Text(src), node: node, optional: optional})
	}
	return out, true
}

func callHasSpread(call *sitter.Node) bool {
	args := call.ChildByFieldName("arguments")
	if args == nil {
		return false
	}
	for i := uint(0); i < args.NamedChildCount(); i++ {
		if args.NamedChild(i).Kind() == "spread_element" {
			return true
		}
	}
	return false
}

// htmlSignificant characters make a literal substring test a possible XSS guard.
const htmlSignificant = "<>\"'&`=/:"

// contentNeutral reports whether a branch condition only tests facts that cannot
// guard browser markup: literal presence/position of a string without HTML-significant
// characters, lengths, typeof, literals and comparisons/logic over those. Local names
// resolve to a single unreassigned declaration in scope. Anything else may be a guard.
func contentNeutral(n, scope *sitter.Node, src []byte, depth int) bool {
	if n == nil || depth > 8 {
		return false
	}
	switch n.Kind() {
	case "parenthesized_expression":
		return n.NamedChildCount() == 1 && contentNeutral(n.NamedChild(0), scope, src, depth+1)
	case "number", "true", "false", "null", "undefined", "string":
		return true
	case "unary_expression":
		op := n.ChildByFieldName("operator")
		if op != nil && op.Utf8Text(src) == "typeof" {
			return true
		}
		return op != nil && op.Utf8Text(src) == "!" && contentNeutral(n.ChildByFieldName("argument"), scope, src, depth+1)
	case "binary_expression":
		op := n.ChildByFieldName("operator")
		if op == nil {
			return false
		}
		switch op.Utf8Text(src) {
		case "&&", "||", ">", "<", ">=", "<=", "==", "===", "!=", "!==":
			return contentNeutral(n.ChildByFieldName("left"), scope, src, depth+1) && contentNeutral(n.ChildByFieldName("right"), scope, src, depth+1)
		}
		return false
	case "member_expression":
		prop := n.ChildByFieldName("property")
		return prop != nil && prop.Utf8Text(src) == "length"
	case "call_expression":
		fn, args := n.ChildByFieldName("function"), n.ChildByFieldName("arguments")
		if fn == nil || fn.Kind() != "member_expression" || args == nil || args.NamedChildCount() != 1 {
			return false
		}
		switch fn.ChildByFieldName("property").Utf8Text(src) {
		case "indexOf", "lastIndexOf", "includes", "startsWith", "endsWith":
		default:
			return false
		}
		lit := args.NamedChild(0)
		if lit.Kind() == "identifier" {
			lit = singleDeclaration(lit.Utf8Text(src), scope, src)
		}
		if lit == nil || lit.Kind() != "string" {
			return false
		}
		text := lit.Utf8Text(src)
		return len(text) >= 2 && !strings.ContainsAny(text[1:len(text)-1], htmlSignificant)
	case "identifier":
		decl := singleDeclaration(n.Utf8Text(src), scope, src)
		return decl != nil && contentNeutral(decl, scope, src, depth+1)
	}
	return false
}

// singleDeclaration returns the initializer of a name declared once in scope and
// never reassigned; otherwise nil.
func singleDeclaration(name string, scope *sitter.Node, src []byte) *sitter.Node {
	var decl *sitter.Node
	count := 0
	var walk func(*sitter.Node)
	walk = func(c *sitter.Node) {
		switch c.Kind() {
		case "variable_declarator":
			if id := c.ChildByFieldName("name"); id != nil && id.Utf8Text(src) == name {
				decl = c.ChildByFieldName("value")
				count++
			}
		case "assignment_expression", "augmented_assignment_expression", "update_expression":
			target := c.ChildByFieldName("left")
			if target == nil {
				target = c.ChildByFieldName("argument")
			}
			if target != nil && target.Utf8Text(src) == name {
				count += 2
			}
		}
		for i := uint(0); i < c.NamedChildCount(); i++ {
			walk(c.NamedChild(i))
		}
	}
	walk(scope)
	if count != 1 {
		return nil
	}
	return decl
}
