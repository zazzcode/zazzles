package langjs

import (
	"math"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/parse"
)

// Reading the text of a SQL statement argument as literal pieces and holes
// (specification 21 and its follow-up). The reader follows, within bounds:
//
//   - a string, a template literal (its substitutions are read too) and "+";
//   - a name bound to such text in the enclosing function, in an outer function
//     or at module level, and a name or member imported from another scanned file;
//   - `[...].join(sep)` and `text.concat(...)`; a list held in a name that is
//     built by a literal and by `push` calls in the same scope;
//   - a call of a function defined in the scanned source: the pieces of its
//     `return` expressions with its parameters as holes (one helper level);
//   - a tagged template: its literal text with a hole for each substitution.
//
// Everything else is a hole. Nothing here names a library, driver or method other
// than the language's own `join`, `concat` and `push`.

// sqlTextMaxNodes bounds the pieces read for one argument.
const sqlTextMaxNodes = 2000

// sqlTextMaxHelpers is the number of helper levels followed.
const sqlTextMaxHelpers = 1

// sqlTextMaxReturns bounds the return expressions read in one helper.
const sqlTextMaxReturns = 8

// sqlTextCollector reads one argument. m is the module the node being read is in;
// it changes when an import or a helper in another file is followed.
type sqlTextCollector struct {
	set     *moduleSet
	m       *sourceModule
	src     []byte
	call    uint
	nodes   int
	helpers int
	// defs are the definitions followed outside the call's own scope: helpers,
	// constants of other scopes and files, and tag functions.
	defs []analysis.Span
}

var sqlTextHole = parse.SQLTextPiece{Hole: true}

func newSQLTextCollector(set *moduleSet, m *sourceModule, call uint) *sqlTextCollector {
	return &sqlTextCollector{set: set, m: m, src: m.src, call: call}
}

func (c *sqlTextCollector) enter(m *sourceModule, call uint) (restore func()) {
	pm, ps, pc := c.m, c.src, c.call
	c.m, c.src, c.call = m, m.src, call
	return func() { c.m, c.src, c.call = pm, ps, pc }
}

func (c *sqlTextCollector) addDef(m *sourceModule, n *sitter.Node) {
	if m == nil || n == nil {
		return
	}
	n = definitionStatement(n)
	sp := parse.Span(m.file, n)
	for _, d := range c.defs {
		if d == sp {
			return
		}
	}
	if len(c.defs) < 8 {
		c.defs = append(c.defs, sp)
	}
}

// definitionStatement widens a value or function node to the declaration that
// holds it (`export const q = ...`, `export function f() {}`).
func definitionStatement(n *sitter.Node) *sitter.Node {
	for p := n.Parent(); p != nil; p = p.Parent() {
		switch p.Kind() {
		case "variable_declarator", "lexical_declaration", "variable_declaration", "export_statement", "expression_statement", "assignment_expression":
			n = p
			continue
		}
		break
	}
	return n
}

func jsUnescape(raw string) string {
	if !strings.Contains(raw, `\`) {
		return raw
	}
	var b strings.Builder
	for i := 0; i < len(raw); i++ {
		if raw[i] != '\\' || i+1 >= len(raw) {
			b.WriteByte(raw[i])
			continue
		}
		i++
		switch raw[i] {
		case 'n', 't', 'r', 'f', 'v':
			b.WriteByte(' ')
		case '\n':
		default:
			b.WriteByte(raw[i])
		}
	}
	return b.String()
}

func (c *sqlTextCollector) pieces(n *sitter.Node, depth int, seen map[string]bool) []parse.SQLTextPiece {
	if n == nil {
		return []parse.SQLTextPiece{sqlTextHole}
	}
	c.nodes++
	if c.nodes > sqlTextMaxNodes {
		return []parse.SQLTextPiece{sqlTextHole}
	}
	switch n.Kind() {
	case "string":
		t := n.Utf8Text(c.src)
		if len(t) >= 2 {
			t = t[1 : len(t)-1]
		}
		return parse.SQLTextLiteral(jsUnescape(t))
	case "template_string":
		var out []parse.SQLTextPiece
		for i := uint(0); i < n.ChildCount(); i++ {
			ch := n.Child(i)
			switch ch.Kind() {
			case "template_substitution":
				if ch.NamedChildCount() == 1 {
					out = append(out, c.pieces(ch.NamedChild(0), depth, seen)...)
				} else {
					out = append(out, sqlTextHole)
				}
			case "string_fragment":
				out = append(out, parse.SQLTextPiece{Text: ch.Utf8Text(c.src)})
			case "escape_sequence":
				out = append(out, parse.SQLTextPiece{Text: jsUnescape(ch.Utf8Text(c.src))})
			}
		}
		return out
	case "parenthesized_expression", "await_expression", "as_expression", "non_null_expression", "satisfies_expression":
		if n.NamedChildCount() > 0 {
			return c.pieces(n.NamedChild(0), depth, seen)
		}
	case "binary_expression":
		if op := n.ChildByFieldName("operator"); op != nil && op.Utf8Text(c.src) == "+" {
			return append(c.pieces(n.ChildByFieldName("left"), depth, seen), c.pieces(n.ChildByFieldName("right"), depth, seen)...)
		}
	case "identifier":
		if depth < 3 {
			if p, ok := c.resolve(n, depth, seen); ok {
				return p
			}
		}
	case "member_expression", "subscript_expression":
		if depth < 3 {
			if p, ok := c.member(n, depth, seen); ok {
				return p
			}
		}
	case "call_expression":
		return c.call2(n, depth, seen)
	}
	return []parse.SQLTextPiece{sqlTextHole}
}

// sqlScope is a scope in which a name may be bound; bound is the byte position
// after which statements are not read.
type sqlScope struct {
	node  *sitter.Node
	bound uint
	// param reports that the scope's function takes the name as a parameter: a
	// name not found in its body is that parameter, a hole.
	param bool
}

// scopes lists the scopes that can bind the name of id, innermost first: the
// enclosing function, its enclosing functions and the module.
func (c *sqlTextCollector) scopes(id *sitter.Node, name string) []sqlScope {
	var out []sqlScope
	fn := enclosingFunction(id)
	for fn != nil {
		out = append(out, sqlScope{node: fn, bound: c.call, param: hasParameter(fn, name, c.src)})
		fn = enclosingFunction(fn)
	}
	var root *sitter.Node
	for p := id; p != nil; p = p.Parent() {
		root = p
	}
	bound := uint(math.MaxUint)
	if len(out) == 0 {
		bound = c.call
	}
	return append(out, sqlScope{node: root, bound: bound})
}

// hasParameter reports a formal parameter of fn that binds name.
func hasParameter(fn *sitter.Node, name string, src []byte) bool {
	if p := fn.ChildByFieldName("parameter"); p != nil && p.Kind() == "identifier" && p.Utf8Text(src) == name {
		return true
	}
	params := fn.ChildByFieldName("parameters")
	if params == nil {
		return false
	}
	found := false
	var walk func(x *sitter.Node)
	walk = func(x *sitter.Node) {
		if found {
			return
		}
		switch x.Kind() {
		case "identifier", "shorthand_property_identifier_pattern":
			if x.Utf8Text(src) == name {
				found = true
			}
			return
		}
		for i := uint(0); i < x.NamedChildCount(); i++ {
			walk(x.NamedChild(i))
		}
	}
	walk(params)
	return found
}

// walkScope visits the nodes of a scope that start before its bound, without
// entering nested functions.
func walkScope(sc sqlScope, visit func(x *sitter.Node)) {
	count := 0
	var walk func(x *sitter.Node)
	walk = func(x *sitter.Node) {
		count++
		if count > 20000 || x.StartByte() >= sc.bound {
			return
		}
		visit(x)
		for i := uint(0); i < x.NamedChildCount(); i++ {
			ch := x.NamedChild(i)
			// do not descend into nested functions other than the scope itself
			switch ch.Kind() {
			case "function_declaration", "function_expression", "arrow_function", "method_definition", "function", "generator_function_declaration":
				continue
			}
			walk(ch)
		}
	}
	walk(sc.node)
}

// resolve follows an identifier to its declarator and the earlier assignments in
// the enclosing function (or module) and joins their pieces. A name not bound
// there is read in the enclosing functions and the module, then in the file it is
// imported from.
func (c *sqlTextCollector) resolve(id *sitter.Node, depth int, seen map[string]bool) ([]parse.SQLTextPiece, bool) {
	name := id.Utf8Text(c.src)
	if seen[name] {
		return nil, false
	}
	seen[name] = true
	defer delete(seen, name)
	for i, sc := range c.scopes(id, name) {
		var out []parse.SQLTextPiece
		found := false
		var decl *sitter.Node
		walkScope(sc, func(x *sitter.Node) {
			switch x.Kind() {
			case "variable_declarator":
				if nm := x.ChildByFieldName("name"); nm != nil && nm.Kind() == "identifier" && nm.Utf8Text(c.src) == name {
					if v := x.ChildByFieldName("value"); v != nil {
						out = c.pieces(v, depth+1, seen)
						found, decl = true, x
					}
				}
			case "assignment_expression":
				if l := x.ChildByFieldName("left"); l != nil && l.Kind() == "identifier" && l.Utf8Text(c.src) == name {
					out = c.pieces(x.ChildByFieldName("right"), depth+1, seen)
					found, decl = true, x
				}
			case "augmented_assignment_expression":
				if l := x.ChildByFieldName("left"); l != nil && l.Kind() == "identifier" && l.Utf8Text(c.src) == name && found {
					if op := x.ChildByFieldName("operator"); op != nil && op.Utf8Text(c.src) == "+=" {
						out = append(out, c.pieces(x.ChildByFieldName("right"), depth+1, seen)...)
					}
				}
			}
		})
		if found {
			if i > 0 {
				c.addDef(c.m, decl)
			}
			return out, true
		}
		if sc.param {
			return nil, false
		}
	}
	return c.imported(name, depth)
}

// moduleExport returns the value a scanned module exports under key: an exported
// constant, a property of its exported object, or a CommonJS export assignment.
func (c *sqlTextCollector) moduleExport(target *sourceModule, key string) *sitter.Node {
	fromObject := func(obj *sitter.Node, k string) *sitter.Node {
		if obj == nil || obj.Kind() != "object" {
			return nil
		}
		v := propertyOrShorthand(obj, k, target.src)
		if v != nil && (v.Kind() == "shorthand_property_identifier" || v.Kind() == "identifier") {
			return topVariable(target, v.Utf8Text(target.src))
		}
		return v
	}
	if rest, ok := strings.CutPrefix(key, "default."); ok {
		return fromObject(target.exports["default"], rest)
	}
	if key == "default" || key == "*" {
		return nil
	}
	if exportedName(target, key) {
		if v := topVariable(target, key); v != nil {
			return v
		}
	}
	if v := fromObject(target.exports["default"], key); v != nil {
		return v
	}
	root := target.tree.RootNode()
	for i := uint(0); i < root.NamedChildCount(); i++ {
		st := root.NamedChild(i)
		if st.Kind() != "expression_statement" || st.NamedChildCount() != 1 {
			continue
		}
		a := st.NamedChild(0)
		if a.Kind() != "assignment_expression" {
			continue
		}
		left, right := a.ChildByFieldName("left"), a.ChildByFieldName("right")
		if left == nil || right == nil {
			continue
		}
		switch left.Utf8Text(target.src) {
		case "exports." + key, "module.exports." + key:
			return right
		case "module.exports":
			if v := fromObject(right, key); v != nil {
				return v
			}
		}
	}
	return nil
}

// inModule reads node, which lies in target, as an imported value.
func (c *sqlTextCollector) inModule(target *sourceModule, node *sitter.Node, depth int) []parse.SQLTextPiece {
	restore := c.enter(target, math.MaxUint)
	defer restore()
	c.addDef(target, node)
	return c.pieces(node, depth+1, map[string]bool{})
}

// imported reads a name imported from another scanned file.
func (c *sqlTextCollector) imported(name string, depth int) ([]parse.SQLTextPiece, bool) {
	if c.set == nil || depth >= 3 {
		return nil, false
	}
	imp, ok := c.m.imports[name]
	if !ok || imp.name == "*" || imp.name == "default" {
		return nil, false
	}
	target := c.set.importModule(c.m, imp.module)
	if target == nil {
		return nil, false
	}
	node := c.moduleExport(target, imp.name)
	if node == nil {
		return nil, false
	}
	return c.inModule(target, node, depth), true
}

// memberKey returns the property name of `a.b` or `a["b"]`.
func (c *sqlTextCollector) memberKey(n *sitter.Node) (obj *sitter.Node, key string, ok bool) {
	obj = n.ChildByFieldName("object")
	if obj == nil {
		return nil, "", false
	}
	if n.Kind() == "member_expression" {
		p := n.ChildByFieldName("property")
		if p == nil {
			return nil, "", false
		}
		return obj, p.Utf8Text(c.src), true
	}
	idx := n.ChildByFieldName("index")
	if k, isString := stringLiteral(idx, c.src); isString {
		return obj, k, true
	}
	return nil, "", false
}

// member reads `Q.name`: a property of an object literal bound in this file, or
// an export of an imported module (`require('./q').name`, `import * as q`).
func (c *sqlTextCollector) member(n *sitter.Node, depth int, seen map[string]bool) ([]parse.SQLTextPiece, bool) {
	obj, key, ok := c.memberKey(n)
	if !ok || c.set == nil {
		return nil, false
	}
	if n.Kind() == "member_expression" {
		if path, member, isRequire := requireBinding(c.m, n); isRequire && member == key {
			if target := c.set.importModule(c.m, path); target != nil {
				if node := c.moduleExport(target, key); node != nil {
					return c.inModule(target, node, depth), true
				}
			}
			return nil, false
		}
	}
	if obj.Kind() != "identifier" {
		return nil, false
	}
	name := obj.Utf8Text(c.src)
	// An object literal bound in an enclosing scope.
scopes:
	for i, sc := range c.scopes(obj, name) {
		var value, decl *sitter.Node
		walkScope(sc, func(x *sitter.Node) {
			if x.Kind() == "variable_declarator" {
				if nm := x.ChildByFieldName("name"); nm != nil && nm.Kind() == "identifier" && nm.Utf8Text(c.src) == name {
					value, decl = x.ChildByFieldName("value"), x
				}
			}
		})
		if value != nil {
			for value.Kind() == "as_expression" || value.Kind() == "satisfies_expression" || value.Kind() == "parenthesized_expression" {
				if value.NamedChildCount() == 0 {
					break
				}
				value = value.NamedChild(0)
			}
			if value.Kind() != "object" {
				// e.g. the result of require(): read through the import below
				break scopes
			}
			v := propertyOrShorthand(value, key, c.src)
			if v == nil {
				return nil, false
			}
			if i > 0 {
				c.addDef(c.m, decl)
			}
			return c.pieces(v, depth+1, seen), true
		}
		if sc.param {
			return nil, false
		}
	}
	imp, ok := c.m.imports[name]
	if !ok {
		return nil, false
	}
	target := c.set.importModule(c.m, imp.module)
	if target == nil {
		return nil, false
	}
	var node *sitter.Node
	switch imp.name {
	case "*":
		node = c.moduleExport(target, key)
	case "default":
		node = c.moduleExport(target, "default."+key)
	default:
		// a named import of an exported object
		if o := c.moduleExport(target, imp.name); o != nil && o.Kind() == "object" {
			node = propertyOrShorthand(o, key, target.src)
			if node != nil && (node.Kind() == "shorthand_property_identifier" || node.Kind() == "identifier") {
				node = topVariable(target, node.Utf8Text(target.src))
			}
		}
	}
	if node == nil {
		return nil, false
	}
	return c.inModule(target, node, depth), true
}

// list reads an expression as a list of elements, each as pieces. A spread or an
// element that is not literal is a hole element.
func (c *sqlTextCollector) list(n *sitter.Node, depth int, seen map[string]bool) ([][]parse.SQLTextPiece, bool) {
	if n == nil {
		return nil, false
	}
	switch n.Kind() {
	case "array":
		return c.elements(n, depth, seen), true
	case "parenthesized_expression", "as_expression", "non_null_expression", "satisfies_expression":
		if n.NamedChildCount() > 0 {
			return c.list(n.NamedChild(0), depth, seen)
		}
	case "identifier":
		if depth >= 3 {
			return nil, false
		}
		name := n.Utf8Text(c.src)
		if seen[name] {
			return nil, false
		}
		seen[name] = true
		defer delete(seen, name)
		for _, sc := range c.scopes(n, name) {
			var out [][]parse.SQLTextPiece
			found, ok := false, true
			walkScope(sc, func(x *sitter.Node) {
				switch x.Kind() {
				case "variable_declarator":
					if nm := x.ChildByFieldName("name"); nm != nil && nm.Kind() == "identifier" && nm.Utf8Text(c.src) == name {
						if v := x.ChildByFieldName("value"); v != nil {
							out, ok = c.list(v, depth+1, seen)
							found = true
						}
					}
				case "assignment_expression":
					if l := x.ChildByFieldName("left"); l != nil && l.Kind() == "identifier" && l.Utf8Text(c.src) == name {
						out, ok = c.list(x.ChildByFieldName("right"), depth+1, seen)
						found = true
					}
				case "call_expression":
					fn, args := x.ChildByFieldName("function"), x.ChildByFieldName("arguments")
					if !found || !ok || fn == nil || args == nil || fn.Kind() != "member_expression" {
						return
					}
					obj, prop := fn.ChildByFieldName("object"), fn.ChildByFieldName("property")
					if obj != nil && prop != nil && obj.Kind() == "identifier" && obj.Utf8Text(c.src) == name && prop.Utf8Text(c.src) == "push" {
						out = append(out, c.elements(args, depth, seen)...)
					}
				}
			})
			if found {
				return out, ok
			}
			if sc.param {
				return nil, false
			}
		}
	}
	return nil, false
}

func (c *sqlTextCollector) elements(parent *sitter.Node, depth int, seen map[string]bool) [][]parse.SQLTextPiece {
	var out [][]parse.SQLTextPiece
	for i := uint(0); i < parent.NamedChildCount(); i++ {
		e := parent.NamedChild(i)
		switch e.Kind() {
		case "comment":
			continue
		case "spread_element":
			out = append(out, []parse.SQLTextPiece{sqlTextHole})
		default:
			out = append(out, c.pieces(e, depth, seen))
		}
	}
	return out
}

// stringShaped reports a receiver that is text, not a list: `"a".concat(b)`.
func stringShaped(n *sitter.Node) bool {
	switch n.Kind() {
	case "string", "template_string", "binary_expression":
		return true
	case "parenthesized_expression", "as_expression", "non_null_expression":
		return n.NamedChildCount() > 0 && stringShaped(n.NamedChild(0))
	}
	return false
}

// call2 reads a call: a tagged template, a join, a concat or a helper's returns.
func (c *sqlTextCollector) call2(n *sitter.Node, depth int, seen map[string]bool) []parse.SQLTextPiece {
	fn, args := n.ChildByFieldName("function"), n.ChildByFieldName("arguments")
	if fn == nil || args == nil {
		return []parse.SQLTextPiece{sqlTextHole}
	}
	if args.Kind() == "template_string" {
		// A tagged template: its literal text, a hole for each substitution. Whether
		// the tag binds the substitutions is not decided here.
		if c.set != nil {
			if target, def := c.set.resolveCall(c.m, n); def != nil && isCallable(def) {
				c.addDef(target, def)
			}
		}
		return c.pieces(args, depth, seen)
	}
	if fn.Kind() == "member_expression" {
		obj, prop := fn.ChildByFieldName("object"), fn.ChildByFieldName("property")
		if obj != nil && prop != nil {
			switch prop.Utf8Text(c.src) {
			case "join":
				if elems, ok := c.list(obj, depth, seen); ok && args.NamedChildCount() <= 1 {
					sep := parse.SQLTextLiteral(",")
					if args.NamedChildCount() == 1 {
						sep = c.pieces(args.NamedChild(0), depth, seen)
					}
					var out []parse.SQLTextPiece
					for i, e := range elems {
						if i > 0 {
							out = append(out, sep...)
						}
						out = append(out, e...)
					}
					return out
				}
				return []parse.SQLTextPiece{sqlTextHole}
			case "concat":
				if stringShaped(obj) {
					out := c.pieces(obj, depth, seen)
					for i := uint(0); i < args.NamedChildCount(); i++ {
						out = append(out, c.pieces(args.NamedChild(i), depth, seen)...)
					}
					return out
				}
			}
		}
	}
	return c.helper(n, fn, depth)
}

func isCallable(n *sitter.Node) bool {
	switch n.Kind() {
	case "function_declaration", "function_expression", "arrow_function", "function", "method_definition", "generator_function_declaration":
		return true
	}
	return false
}

// returnExpressions lists the expressions a function returns (without nested
// functions); an arrow function with an expression body returns that expression.
func returnExpressions(fn *sitter.Node) []*sitter.Node {
	body := fn.ChildByFieldName("body")
	if body == nil {
		return nil
	}
	if body.Kind() != "statement_block" {
		return []*sitter.Node{body}
	}
	var out []*sitter.Node
	count := 0
	var walk func(x *sitter.Node)
	walk = func(x *sitter.Node) {
		count++
		if count > 5000 || len(out) >= sqlTextMaxReturns {
			return
		}
		if x.Kind() == "return_statement" && x.NamedChildCount() > 0 {
			out = append(out, x.NamedChild(0))
			return
		}
		for i := uint(0); i < x.NamedChildCount(); i++ {
			ch := x.NamedChild(i)
			if isCallable(ch) {
				continue
			}
			walk(ch)
		}
	}
	walk(body)
	return out
}

// helper reads the call of a function defined in the scanned source as the
// pieces of its return expressions, its parameters being holes. The expression
// that is statement text, when one is, stands for the call.
func (c *sqlTextCollector) helper(n, fn *sitter.Node, depth int) []parse.SQLTextPiece {
	hole := []parse.SQLTextPiece{sqlTextHole}
	if c.set == nil || c.helpers >= sqlTextMaxHelpers {
		return hole
	}
	target, def := c.set.resolveCall(c.m, n)
	if def == nil && fn.Kind() == "member_expression" {
		if obj := fn.ChildByFieldName("object"); obj != nil && obj.Kind() == "identifier" {
			if lit := topVariable(c.m, obj.Utf8Text(c.src)); lit != nil && lit.Kind() == "object" && !bindingReassigned(c.m, obj.Utf8Text(c.src)) {
				if p := fn.ChildByFieldName("property"); p != nil {
					target, def = c.m, objectMethod(lit, p.Utf8Text(c.src), c.src)
				}
			}
		}
	}
	if def == nil || target == nil || !isCallable(def) {
		return hole
	}
	rets := returnExpressions(def)
	if len(rets) == 0 {
		return hole
	}
	restore := c.enter(target, 0)
	defer restore()
	c.helpers++
	defer func() { c.helpers-- }()
	var first []parse.SQLTextPiece
	for i, r := range rets {
		c.call = r.StartByte()
		p := c.pieces(r, depth+1, map[string]bool{})
		if parse.SQLStatementText(p).Matched {
			c.addDef(target, def)
			return p
		}
		if i == 0 {
			first = p
		}
	}
	c.addDef(target, def)
	return first
}

// taggedTemplate returns the call node of a tagged template expression that n is,
// seen through parentheses and await.
func taggedTemplate(n *sitter.Node) *sitter.Node {
	for n != nil {
		switch n.Kind() {
		case "parenthesized_expression", "await_expression", "as_expression", "non_null_expression", "satisfies_expression":
			if n.NamedChildCount() == 0 {
				return nil
			}
			n = n.NamedChild(0)
			continue
		case "call_expression":
			if args := n.ChildByFieldName("arguments"); args != nil && args.Kind() == "template_string" {
				return n
			}
		}
		return nil
	}
	return nil
}
