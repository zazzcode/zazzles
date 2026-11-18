package parse

import (
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
)

// Syntactic scan of one callable for its summary (callable_summary.go): the
// parameters it reads, the reasons it may see data other than its parameters and
// load-time constants, and its in-repository call sites.

// scan records the callable's local facts: parameters, reads, reasons and
// in-repository call sites.
func (c *callableSummary) scan(s *moduleSet) {
	m, fn := c.module, c.node
	params, ok := functionParameters(fn, m.src)
	c.indexed = ok
	if !ok {
		c.reason("unsupported_parameters", fn)
	}
	if len(params) > summaryMaxParams {
		c.reason("summary_limit", fn)
		params, c.indexed = params[:summaryMaxParams], false
	}
	for _, p := range params {
		c.params = append(c.params, p.name)
	}
	c.locals, c.fresh = declaredNames(fn, m.src)
	for p := fn.Parent(); p != nil; p = p.Parent() {
		if isFunction(p) || p.Kind() == "function_declaration" || p.Kind() == "generator_function_declaration" || p.Kind() == "method_definition" {
			c.nested = true
			break
		}
	}
	w := summaryWalker{set: s, c: c}
	w.pattern(fn.ChildByFieldName("parameters"))
	w.pattern(fn.ChildByFieldName("parameter"))
	w.walk(fn.ChildByFieldName("body"))
}

type summaryWalker struct {
	set *moduleSet
	c   *callableSummary
}

func (w summaryWalker) text(n *sitter.Node) string { return n.Utf8Text(w.c.module.src) }

func (w summaryWalker) walk(n *sitter.Node) {
	if n == nil {
		return
	}
	switch n.Kind() {
	case "identifier", "shorthand_property_identifier":
		w.ref(n)
	case "this", "super":
		w.c.reason("this_or_arguments", n)
	case "variable_declarator":
		w.pattern(n.ChildByFieldName("name"))
		w.walk(n.ChildByFieldName("value"))
	case "function_declaration", "generator_function_declaration", "function_expression", "function", "generator_function", "arrow_function", "method_definition":
		w.pattern(n.ChildByFieldName("parameters"))
		w.pattern(n.ChildByFieldName("parameter"))
		w.walk(n.ChildByFieldName("body"))
	case "catch_clause":
		w.pattern(n.ChildByFieldName("parameter"))
		w.walk(n.ChildByFieldName("body"))
	case "for_in_statement":
		if left := n.ChildByFieldName("left"); left != nil {
			if n.ChildByFieldName("kind") != nil {
				w.pattern(left)
			} else {
				w.write(left)
			}
		}
		w.walk(n.ChildByFieldName("right"))
		w.walk(n.ChildByFieldName("body"))
	case "assignment_expression", "augmented_assignment_expression":
		w.write(n.ChildByFieldName("left"))
		w.walk(n.ChildByFieldName("right"))
	case "update_expression":
		w.write(n.ChildByFieldName("argument"))
	case "unary_expression":
		if op := n.ChildByFieldName("operator"); op != nil && w.text(op) == "delete" {
			w.write(n.ChildByFieldName("argument"))
			return
		}
		w.children(n)
	case "call_expression":
		w.call(n)
	case "new_expression":
		ctor := n.ChildByFieldName("constructor")
		if ctor == nil || ctor.Kind() != "identifier" || w.text(ctor) != "Date" || !w.set.unboundBuiltin(w.c.module, n, "Date") {
			w.c.reason("unmodeled_constructor", n)
		}
		w.walk(n.ChildByFieldName("arguments"))
	case "member_expression":
		w.walk(n.ChildByFieldName("object"))
	case "subscript_expression":
		w.walk(n.ChildByFieldName("object"))
		w.walk(n.ChildByFieldName("index"))
	case "pair":
		if key := n.ChildByFieldName("key"); key != nil && key.Kind() == "computed_property_name" {
			w.walk(key)
		}
		w.walk(n.ChildByFieldName("value"))
	case "with_statement":
		w.c.reason("dynamic_code", n)
		w.children(n)
	case "class_declaration", "class":
		w.walk(n.ChildByFieldName("body"))
		for i := uint(0); i < n.NamedChildCount(); i++ {
			if child := n.NamedChild(i); child.Kind() == "class_heritage" {
				w.walk(child)
			}
		}
	case "type_annotation", "type_arguments", "type_parameters", "type_alias_declaration", "interface_declaration", "comment":
	default:
		w.children(n)
	}
}

func (w summaryWalker) children(n *sitter.Node) {
	for i := uint(0); i < n.NamedChildCount(); i++ {
		w.walk(n.NamedChild(i))
	}
}

// pattern walks only the default values and computed keys of a binding pattern.
func (w summaryWalker) pattern(p *sitter.Node) {
	if p == nil {
		return
	}
	switch p.Kind() {
	case "identifier", "shorthand_property_identifier_pattern":
	case "assignment_pattern", "object_assignment_pattern":
		w.pattern(p.ChildByFieldName("left"))
		w.walk(p.ChildByFieldName("right"))
	case "pair_pattern":
		if key := p.ChildByFieldName("key"); key != nil && key.Kind() == "computed_property_name" {
			w.walk(key)
		}
		w.pattern(p.ChildByFieldName("value"))
	case "required_parameter", "optional_parameter":
		w.pattern(p.ChildByFieldName("pattern"))
		w.walk(p.ChildByFieldName("value"))
	case "type_annotation", "comment":
	default:
		for i := uint(0); i < p.NamedChildCount(); i++ {
			w.pattern(p.NamedChild(i))
		}
	}
}

func (w summaryWalker) ref(n *sitter.Node) {
	c, name := w.c, w.text(n)
	if c.locals[name] && boundInScope(n, c.node, name, c.module.src) {
		if ownParam(c, n, name) {
			c.reads |= c.paramBit(name)
		}
		return
	}
	if c.locals[name] {
		// Declared only in a scope that does not enclose this use.
		c.reason("free_variable", n)
		return
	}
	if c.nested {
		// A nested callable's free names may be enclosing-function bindings.
		c.reason("free_variable", n)
		return
	}
	if name == "arguments" {
		c.reason("this_or_arguments", n)
		c.reads |= c.allParams()
		return
	}
	switch moduleBindingClass(w.set, c.module, n, name) {
	case "constant":
	case "imported":
		c.reason("imported_value", n)
	case "mutable":
		c.reason("mutable_module_binding", n)
	default:
		c.reason("free_variable", n)
	}
}

// write records a write target. Writes to callable locals are local effects,
// except member writes on a local that is not a fresh literal (it may alias a
// parameter or a module object).
func (w summaryWalker) write(target *sitter.Node) {
	if target == nil {
		return
	}
	c := w.c
	switch target.Kind() {
	case "identifier":
		if !c.locals[w.text(target)] || !boundInScope(target, c.node, w.text(target), c.module.src) {
			c.reason("heap_write", target)
		}
	case "member_expression", "subscript_expression":
		root, levels := target, 0
		for root.Kind() == "member_expression" || root.Kind() == "subscript_expression" {
			levels++
			if root.Kind() == "subscript_expression" {
				w.walk(root.ChildByFieldName("index"))
			}
			root = root.ChildByFieldName("object")
			if root == nil {
				c.reason("heap_write", target)
				return
			}
		}
		// Only a direct field of a fresh literal is local; a deeper path may reach
		// a parameter or module object stored in it.
		if root.Kind() != "identifier" || levels > 1 || !c.fresh[w.text(root)] || !boundInScope(root, c.node, w.text(root), c.module.src) {
			c.reason("heap_write", target)
		}
		w.walk(root)
	default:
		c.reason("heap_write", target)
		w.pattern(target)
	}
}

func (w summaryWalker) call(n *sitter.Node) {
	c, m := w.c, w.c.module
	fn := n.ChildByFieldName("function")
	if fn == nil || fn.Kind() == "import" || (fn.Kind() == "identifier" && w.text(fn) == "eval" && !c.locals["eval"]) {
		c.reason("dynamic_code", n)
		w.walk(n.ChildByFieldName("arguments"))
		return
	}
	if w.set.unloadedImport(m, summaryCalleeRoot(fn, m.src)) {
		c.reason("callee_not_loaded", n)
		w.walk(n.ChildByFieldName("arguments"))
		return
	}
	if hm, def := w.set.resolveCall(m, n); def != nil {
		if supportedCallee(def) {
			c.sites = append(c.sites, summarySite{call: n, module: hm, fn: def})
		} else {
			c.reason("unmodeled_call", n)
		}
		w.walk(n.ChildByFieldName("arguments"))
		return
	}
	// Read the call index without filling it: a resolution made while modules
	// may not load must not be cached for flow.
	r, cached := m.calls[n.Id()]
	if !cached {
		r = w.set.resolveCallSite(m, n)
	}
	switch r.Kind {
	case callKnownClass, callBuiltinMethod, callPackageMember:
		if jsIndependentResults[r.Receiver][r.Method] {
			// The receiver of `new Date(x).m()` is evaluated too; an identifier
			// receiver is the typed module or builtin itself.
			if obj := fn.ChildByFieldName("object"); obj != nil && obj.Kind() != "identifier" {
				w.walk(obj)
			}
			w.walk(n.ChildByFieldName("arguments"))
			return
		}
	}
	c.reason("unmodeled_call", n)
	w.walk(n.ChildByFieldName("arguments"))
}

// summaryBuiltinConstants are global values a closed body may read as members
// (Math.PI) when no module binding shadows them. Calls on them still need the
// 1D effect table.
var summaryBuiltinConstants = map[string]bool{"Math": true, "JSON": true, "Number": true, "String": true, "Boolean": true, "Array": true, "Object": true, "Date": true, "Infinity": true, "NaN": true}

// moduleBindingClass classifies a name that is not a callable local:
// "constant" (a load-time value no request can reach), "imported" (an import
// whose value may change), "mutable" (a module binding that is written,
// mutated or escapes) or "" (an enclosing-function or global binding).
func moduleBindingClass(s *moduleSet, m *sourceModule, at *sitter.Node, name string) string {
	if imp, ok := m.imports[name]; ok {
		if strings.HasSuffix(imp.module, ".json") && m.moduleRefsStable(name) {
			return "constant"
		}
		return "imported"
	}
	if decl := topDeclaration(m, name); decl != nil {
		if (decl.Kind() == "function_declaration" || decl.Kind() == "generator_function_declaration" || decl.Kind() == "variable_declarator") && m.moduleRefsStable(name) {
			return "constant"
		}
		return "mutable"
	}
	if summaryBuiltinConstants[name] && !shadowed(at, name, m.src) {
		writes := m.bindingWrites()
		if !writes.assigned[name] && !writes.written[name] && m.funcs[name] == nil {
			return "constant"
		}
	}
	return ""
}

// topDeclaration returns the single top-level declaration of name (a variable
// declarator, function or class), or nil when there is none or more than one.
func topDeclaration(m *sourceModule, name string) *sitter.Node {
	root := m.tree.RootNode()
	var found *sitter.Node
	count := 0
	for i := uint(0); i < root.NamedChildCount(); i++ {
		n := root.NamedChild(i)
		if n.Kind() == "export_statement" {
			if d := n.ChildByFieldName("declaration"); d != nil {
				n = d
			}
		}
		switch n.Kind() {
		case "lexical_declaration", "variable_declaration":
			for j := uint(0); j < n.NamedChildCount(); j++ {
				d := n.NamedChild(j)
				if id := d.ChildByFieldName("name"); id != nil && id.Kind() == "identifier" && id.Utf8Text(m.src) == name {
					found, count = d, count+1
				}
			}
		case "function_declaration", "generator_function_declaration", "class_declaration":
			if id := n.ChildByFieldName("name"); id != nil && id.Utf8Text(m.src) == name {
				found, count = n, count+1
			}
		}
	}
	if count != 1 {
		return nil
	}
	return found
}

// moduleRefsStable reports whether every use of name in the module only reads
// it: the object of a member or subscript read that is not a call receiver or
// write target, an iterated collection, or an operand. The answer is name-based
// and module-wide, like the binding index.
func (m *sourceModule) moduleRefsStable(name string) bool {
	if m.refsUnstable == nil {
		m.refsUnstable = buildUnstableRefs(m)
	}
	writes := m.bindingWrites()
	return !m.refsUnstable[name] && !writes.assigned[name] && !writes.written[name]
}

func buildUnstableRefs(m *sourceModule) map[string]bool {
	out := map[string]bool{}
	cursor := m.tree.RootNode().Walk()
	defer cursor.Close()
	for {
		n := cursor.Node()
		switch n.Kind() {
		case "identifier":
			if !readOnlyUse(n) {
				out[n.Utf8Text(m.src)] = true
			}
		case "shorthand_property_identifier":
			out[n.Utf8Text(m.src)] = true
		}
		if cursor.GotoFirstChild() {
			continue
		}
		for !cursor.GotoNextSibling() {
			if !cursor.GotoParent() {
				return out
			}
		}
	}
}

func readOnlyUse(n *sitter.Node) bool {
	p := n.Parent()
	if p == nil {
		return false
	}
	switch p.Kind() {
	case "variable_declarator":
		// The declared name itself; an alias (`const a = name`) is not read-only.
		return sameNode(p.ChildByFieldName("name"), n)
	case "function_declaration", "generator_function_declaration", "class_declaration", "import_specifier", "import_clause", "namespace_import":
		return true
	case "for_in_statement":
		return sameNode(p.ChildByFieldName("right"), n)
	case "binary_expression", "template_substitution", "parenthesized_expression":
		return true
	case "unary_expression":
		op := p.ChildByFieldName("operator")
		return op != nil && op.Kind() != "delete"
	case "member_expression", "subscript_expression":
		if !sameNode(p.ChildByFieldName("object"), n) {
			return true // a computed index or property position: an operand read
		}
		top := p
		for q := top.Parent(); q != nil && (q.Kind() == "member_expression" || q.Kind() == "subscript_expression") && sameNode(q.ChildByFieldName("object"), top); q = q.Parent() {
			top = q
		}
		q := top.Parent()
		if q == nil {
			return true
		}
		// A read is stable only where the value is consumed or returned, never
		// where it is passed, aliased, stored, mutated or called.
		switch q.Kind() {
		case "return_statement", "binary_expression", "template_substitution", "parenthesized_expression", "ternary_expression", "expression_statement":
			return true
		case "arrow_function":
			return sameNode(q.ChildByFieldName("body"), top)
		case "for_in_statement":
			return sameNode(q.ChildByFieldName("right"), top)
		case "unary_expression":
			op := q.ChildByFieldName("operator")
			return op != nil && op.Kind() != "delete"
		}
		return false
	}
	return false
}

// declaredNames collects every name bound inside a callable, its parameters and
// nested functions included, and the subset declared once with a fresh literal.
func declaredNames(fn *sitter.Node, src []byte) (map[string]bool, map[string]bool) {
	names, fresh, counts := map[string]bool{}, map[string]bool{}, map[string]int{}
	add := func(n *sitter.Node) {
		for _, name := range patternNames(n, src) {
			names[name] = true
			counts[name] += 2
		}
	}
	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		switch n.Kind() {
		case "variable_declarator":
			name, v := n.ChildByFieldName("name"), n.ChildByFieldName("value")
			if name != nil && name.Kind() == "identifier" && v != nil && (v.Kind() == "object" || v.Kind() == "array") {
				names[name.Utf8Text(src)] = true
				counts[name.Utf8Text(src)]++
			} else {
				add(name)
			}
		case "function_declaration", "generator_function_declaration", "function_expression", "function", "generator_function", "arrow_function", "method_definition", "class_declaration", "class":
			if name := n.ChildByFieldName("name"); name != nil && name.Kind() == "identifier" {
				add(name)
			}
			add(n.ChildByFieldName("parameters"))
			add(n.ChildByFieldName("parameter"))
		case "catch_clause":
			add(n.ChildByFieldName("parameter"))
		case "for_in_statement":
			if n.ChildByFieldName("kind") != nil {
				add(n.ChildByFieldName("left"))
			}
		case "assignment_expression", "augmented_assignment_expression":
			if left := n.ChildByFieldName("left"); left != nil && left.Kind() == "identifier" {
				counts[left.Utf8Text(src)] += 2
			}
		}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			visit(n.NamedChild(i))
		}
	}
	visit(fn)
	for name, count := range counts {
		if count == 1 {
			fresh[name] = true
		}
	}
	return names, fresh
}

// patternNames lists the identifiers a binding pattern or parameter list binds.
func patternNames(p *sitter.Node, src []byte) []string {
	if p == nil {
		return nil
	}
	switch p.Kind() {
	case "identifier", "shorthand_property_identifier_pattern":
		return []string{p.Utf8Text(src)}
	case "assignment_pattern", "object_assignment_pattern":
		return patternNames(p.ChildByFieldName("left"), src)
	case "pair_pattern":
		return patternNames(p.ChildByFieldName("value"), src)
	case "required_parameter", "optional_parameter":
		return patternNames(p.ChildByFieldName("pattern"), src)
	case "type_annotation", "comment":
		return nil
	}
	var out []string
	for i := uint(0); i < p.NamedChildCount(); i++ {
		out = append(out, patternNames(p.NamedChild(i), src)...)
	}
	return out
}

// summaryCalleeRoot is the first name of a callee expression (`a` in `a.b.c`), or "".
func summaryCalleeRoot(fn *sitter.Node, src []byte) string {
	for fn != nil && fn.Kind() == "member_expression" {
		fn = fn.ChildByFieldName("object")
	}
	if fn == nil || fn.Kind() != "identifier" {
		return ""
	}
	return fn.Utf8Text(src)
}

// unloadedImport reports whether name imports an in-repository module that is
// not loaded yet. importModule would load the first allowed candidate.
func (s *moduleSet) unloadedImport(m *sourceModule, name string) bool {
	imp, ok := m.imports[name]
	if !ok || name == "" {
		return false
	}
	for _, p := range s.moduleCandidates(m, imp.module) {
		if s.allowed[p] {
			return s.modules[p] == nil
		}
	}
	return false
}

// boundInScope reports whether name is bound in a scope that encloses use,
// from use up to and including the callable fn: a function's parameters, name
// and var/function declarations, or a block's lexical declarations.
func boundInScope(use, fn *sitter.Node, name string, src []byte) bool {
	for p := use.Parent(); p != nil; p = p.Parent() {
		switch p.Kind() {
		case "function_declaration", "generator_function_declaration", "function_expression", "function", "generator_function", "arrow_function", "method_definition":
			for _, field := range []string{"parameters", "parameter"} {
				for _, n := range patternNames(p.ChildByFieldName(field), src) {
					if n == name {
						return true
					}
				}
			}
			if id := p.ChildByFieldName("name"); id != nil && p.Kind() != "function_declaration" && id.Utf8Text(src) == name {
				return true
			}
			if varDeclared(p.ChildByFieldName("body"), name, src) {
				return true
			}
		case "statement_block", "program", "switch_body":
			if blockDeclares(p, name, src) {
				return true
			}
		case "for_in_statement", "for_statement":
			for _, field := range []string{"left", "initializer"} {
				if l := p.ChildByFieldName(field); l != nil && (p.ChildByFieldName("kind") != nil || l.Kind() == "lexical_declaration" || l.Kind() == "variable_declaration") {
					if containsName(patternNamesOfDecl(l, src), name) {
						return true
					}
				}
			}
		case "catch_clause":
			if containsName(patternNames(p.ChildByFieldName("parameter"), src), name) {
				return true
			}
		case "class_declaration", "class":
			if id := p.ChildByFieldName("name"); id != nil && id.Utf8Text(src) == name {
				return true
			}
		}
		if sameNode(p, fn) {
			return false
		}
	}
	return false
}

func containsName(names []string, name string) bool {
	for _, n := range names {
		if n == name {
			return true
		}
	}
	return false
}

func patternNamesOfDecl(n *sitter.Node, src []byte) []string {
	if n.Kind() != "lexical_declaration" && n.Kind() != "variable_declaration" {
		return patternNames(n, src)
	}
	var out []string
	for i := uint(0); i < n.NamedChildCount(); i++ {
		if d := n.NamedChild(i); d.Kind() == "variable_declarator" {
			out = append(out, patternNames(d.ChildByFieldName("name"), src)...)
		}
	}
	return out
}

// blockDeclares reports a declaration of name directly in a block.
func blockDeclares(b *sitter.Node, name string, src []byte) bool {
	for i := uint(0); i < b.NamedChildCount(); i++ {
		d := b.NamedChild(i)
		switch d.Kind() {
		case "lexical_declaration", "variable_declaration":
			if containsName(patternNamesOfDecl(d, src), name) {
				return true
			}
		case "function_declaration", "generator_function_declaration", "class_declaration":
			if id := d.ChildByFieldName("name"); id != nil && id.Utf8Text(src) == name {
				return true
			}
		}
	}
	return false
}

// varDeclared reports a function-scoped `var` or function declaration of name
// in body, outside nested functions.
func varDeclared(body *sitter.Node, name string, src []byte) bool {
	if body == nil {
		return false
	}
	found := false
	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		if found {
			return
		}
		switch n.Kind() {
		case "variable_declaration":
			found = containsName(patternNamesOfDecl(n, src), name)
			return
		case "function_declaration", "generator_function_declaration":
			if id := n.ChildByFieldName("name"); id != nil && id.Utf8Text(src) == name {
				found = true
			}
			return
		case "function_expression", "function", "generator_function", "arrow_function", "method_definition", "class_declaration", "class":
			return
		}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			visit(n.NamedChild(i))
		}
	}
	visit(body)
	return found
}

// ownParam reports whether a use of name resolves to the callable's own
// parameter rather than a nested binding of the same name.
func ownParam(c *callableSummary, use *sitter.Node, name string) bool {
	if c.paramBit(name) == 0 {
		return false
	}
	for p := use.Parent(); p != nil && !sameNode(p, c.node); p = p.Parent() {
		if p.Kind() == "statement_block" && blockDeclares(p, name, c.module.src) && p.Parent() != nil && !sameNode(p.Parent(), c.node) {
			return false
		}
		switch p.Kind() {
		case "function_declaration", "generator_function_declaration", "function_expression", "function", "generator_function", "arrow_function", "method_definition":
			if containsName(patternNames(p.ChildByFieldName("parameters"), c.module.src), name) || containsName(patternNames(p.ChildByFieldName("parameter"), c.module.src), name) {
				return false
			}
		}
	}
	return true
}
