package langjs

import (
	sitter "github.com/tree-sitter/go-tree-sitter"
)

// maxConstFoldDepth bounds the literal-constant chain a destination may follow.
const maxConstFoldDepth = 4 // identifier hops

// literalConstFoldable reports whether n evaluates, in module m, to a fixed
// string: a string literal, a template whose substitutions are all foldable, or
// an identifier naming a module-level `const` (declared here or imported by
// name from a project module) whose initializer is itself foldable. A
// process.env read, a call, a request value, a `let`/`var`, a reassigned or
// locally shadowed binding never folds, so the result can only establish a
// destination that no input or environment can change.
func (s *moduleSet) literalConstFoldable(m *sourceModule, n *sitter.Node, depth int) bool {
	if s == nil || m == nil || n == nil || depth > maxConstFoldDepth {
		return false
	}
	n = unwrapTS(n)
	switch n.Kind() {
	case "string":
		return true
	case "template_string":
		for i := uint(0); i < n.NamedChildCount(); i++ {
			c := n.NamedChild(i)
			if c.Kind() != "template_substitution" {
				continue
			}
			if c.NamedChildCount() != 1 || !s.literalConstFoldable(m, c.NamedChild(0), depth) {
				return false
			}
		}
		return true
	case "identifier":
		name := n.Utf8Text(m.src)
		if shadowed(n, name, m.src) || boundByEnclosingFunction(n, name, m.src) {
			return false
		}
		target, local := m, name
		if imp, ok := m.imports[name]; ok && topVariable(m, name) == nil {
			if imp.name == "default" || imp.name == "*" || imp.name == "" {
				return false
			}
			d, l, _ := s.namedExport(m, imp.module, imp.name, 0)
			if d == nil {
				return false
			}
			target, local = d, l
		}
		init := topConstInitializer(target, local)
		if init == nil || bindingReassigned(target, local) || shadowedAnywhere(target, local) {
			return false
		}
		return s.literalConstFoldable(target, init, depth+1)
	}
	return false
}

// topConstInitializer returns the initializer of a module-level `const`
// declaration of name, and nil for `let`, `var` or a missing binding.
func topConstInitializer(m *sourceModule, name string) *sitter.Node {
	root := m.tree.RootNode()
	for i := uint(0); i < root.NamedChildCount(); i++ {
		d := root.NamedChild(i)
		if d.Kind() == "export_statement" {
			d = d.ChildByFieldName("declaration")
		}
		if d == nil || (d.Kind() != "lexical_declaration" && d.Kind() != "variable_declaration") {
			continue
		}
		for j := uint(0); j < d.NamedChildCount(); j++ {
			decl := d.NamedChild(j)
			id := decl.ChildByFieldName("name")
			if id == nil || id.Kind() != "identifier" || id.Utf8Text(m.src) != name {
				continue
			}
			if d.Kind() != "lexical_declaration" || d.ChildCount() == 0 || d.Child(0).Kind() != "const" {
				return nil
			}
			return decl.ChildByFieldName("value")
		}
	}
	return nil
}

// boundByEnclosingFunction reports a parameter (plain, defaulted, destructured
// or the single arrow parameter) or catch binding of that name in any
// function or catch clause enclosing n.
func boundByEnclosingFunction(n *sitter.Node, name string, src []byte) bool {
	var has func(*sitter.Node) bool
	has = func(x *sitter.Node) bool {
		switch x.Kind() {
		case "identifier", "shorthand_property_identifier_pattern":
			if x.Utf8Text(src) == name {
				return true
			}
		}
		for i := uint(0); i < x.NamedChildCount(); i++ {
			if has(x.NamedChild(i)) {
				return true
			}
		}
		return false
	}
	for p := n.Parent(); p != nil; p = p.Parent() {
		for _, field := range []string{"parameters", "parameter"} {
			if params := p.ChildByFieldName(field); params != nil && has(params) {
				return true
			}
		}
		if p.Kind() == "catch_clause" {
			if param := p.ChildByFieldName("parameter"); param != nil && has(param) {
				return true
			}
		}
	}
	return false
}
