package langjs

import (
	sitter "github.com/tree-sitter/go-tree-sitter"
	"strings"
)

// fixedOriginDestination reports whether every value a redirect destination
// can take has its origin fixed by construction: a same-site path whose first
// two characters are a single slash and a non-slash, non-backslash character.
// It follows const bindings, ternaries whose branches are all fixed,
// concatenation and templates led by a fixed path, and `new URL(path, base)`
// with a fixed path, which keeps the base's origin whatever the base is.
// Anything mutable, environment-derived or request-led is not fixed.
func (f *flow) fixedOriginDestination(n *sitter.Node, depth int) bool {
	n = unwrapTS(n)
	if n == nil || depth > 6 {
		return false
	}
	m := f.module
	switch n.Kind() {
	case "string":
		text, ok := stringLiteral(n, m.src)
		return ok && fixedSitePath(text)
	case "template_string":
		if n.NamedChildCount() == 0 {
			return false
		}
		first := n.NamedChild(0)
		switch first.Kind() {
		case "string_fragment":
			// Reject escapes: a leading fragment is only reliable as written.
			return fixedSitePath(first.Utf8Text(m.src)) && n.StartByte()+1 == first.StartByte()
		case "template_substitution":
			if first.NamedChildCount() != 1 || n.StartByte()+1 != first.StartByte() {
				return false
			}
			return f.fixedOriginDestination(first.NamedChild(0), depth+1)
		}
		return false
	case "binary_expression":
		op := n.ChildByFieldName("operator")
		return op != nil && op.Utf8Text(m.src) == "+" && f.fixedOriginDestination(n.ChildByFieldName("left"), depth+1)
	case "ternary_expression":
		return f.fixedOriginDestination(n.ChildByFieldName("consequence"), depth+1) && f.fixedOriginDestination(n.ChildByFieldName("alternative"), depth+1)
	case "identifier":
		name := n.Utf8Text(m.src)
		if bindingReassigned(m, name) {
			return false
		}
		init := localInitializer(m, n, name)
		if init == nil || !constDeclarator(init) {
			return false
		}
		return f.fixedOriginDestination(init, depth+1)
	case "new_expression":
		ctor, args := n.ChildByFieldName("constructor"), n.ChildByFieldName("arguments")
		if ctor == nil || args == nil || args.NamedChildCount() < 2 || ctor.Kind() != "identifier" || ctor.Utf8Text(m.src) != "URL" {
			return false
		}
		if shadowed(n, "URL", m.src) || topLevelBinding(m, "URL") || bindingReassigned(m, "URL") {
			return false
		}
		return f.fixedOriginDestination(args.NamedChild(0), depth+1)
	}
	return false
}

// constDeclarator reports whether an initializer belongs to a `const` declaration.
func constDeclarator(init *sitter.Node) bool {
	decl := init.Parent()
	if decl == nil || decl.Kind() != "variable_declarator" {
		return false
	}
	list := decl.Parent()
	if list == nil || list.Kind() != "lexical_declaration" {
		return false
	}
	return list.ChildCount() > 0 && list.Child(0).Kind() == "const"
}

func fixedSitePath(text string) bool {
	return len(text) > 1 && text[0] == '/' && text[1] != '/' && text[1] != '\\' && !strings.ContainsAny(text[:2], "\t\r\n")
}
