package langphp

import (
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
)

func (f *phpFlow) phpYAMLFlags(n *sitter.Node) (object, literal bool) {
	m := f.module
	switch n.Kind() {
	case "parenthesized_expression":
		if n.NamedChildCount() == 1 {
			return f.phpYAMLFlags(n.NamedChild(0))
		}
	case "integer":
		// An integer can include the object bit without naming the constant.
		return false, phpText(m, n) == "0"
	case "class_constant_access_expression":
		if n.NamedChildCount() == 2 && f.phpSymfonyYAML(n.NamedChild(0)) {
			return phpText(m, n.NamedChild(1)) == "PARSE_OBJECT", true
		}
	case "binary_expression":
		if phpText(m, phpField(n, "operator")) == "|" {
			left, right := phpField(n, "left"), phpField(n, "right")
			if left != nil && right != nil {
				a, aLiteral := f.phpYAMLFlags(left)
				b, bLiteral := f.phpYAMLFlags(right)
				return a || b, aLiteral && bLiteral
			}
		}
	}
	return false, false
}

func (f *phpFlow) deserializationOptions(call, option *sitter.Node) *sitter.Node {
	m := f.module
	if option.Kind() == "array_creation_expression" {
		return option
	}
	if option.Kind() == "name" {
		root := m.tree.RootNode()
		for i := uint(0); i < root.NamedChildCount(); i++ {
			decl := root.NamedChild(i)
			if decl.Kind() != "const_declaration" {
				continue
			}
			for j := uint(0); j < decl.NamedChildCount(); j++ {
				item := decl.NamedChild(j)
				if item.Kind() == "const_element" && item.NamedChildCount() == 2 && phpText(m, item.NamedChild(0)) == phpText(m, option) {
					return item.NamedChild(1)
				}
			}
		}
		return nil
	}
	if option.Kind() != "variable_name" {
		return nil
	}
	return phpImmutableInitializer(m, call, option)
}

// phpImmutableInitializer returns the initializer of an options variable only
// when the variable provably keeps it: in its variable scope the name occurs
// as the target of one dominating assignment statement and as the options
// argument, and nowhere else. Any other occurrence (a second write, a
// reference, an argument, a loop or destructuring target) leaves the value
// unresolved, as does a construct that can write a variable by name.
func phpImmutableInitializer(m *phpModule, call, option *sitter.Node) *sitter.Node {
	var scope *sitter.Node
	for p := call.Parent(); p != nil && scope == nil; p = p.Parent() {
		switch p.Kind() {
		case "function_definition", "method_declaration", "anonymous_function", "arrow_function", "program":
			scope = p
		}
	}
	if scope == nil {
		return nil
	}
	name := phpText(m, option)
	var initializer *sitter.Node
	proven := true
	// inner marks a nested callable body, which has its own variables.
	var visit func(n *sitter.Node, inner bool)
	visit = func(n *sitter.Node, inner bool) {
		if !proven {
			return
		}
		switch n.Kind() {
		case "dynamic_variable_name":
			proven = proven && inner
			return
		case "function_call_expression":
			switch strings.ToLower(strings.TrimPrefix(phpText(m, phpCallee(n)), `\`)) {
			case "extract", "parse_str", "mb_parse_str":
				proven = proven && inner
			}
		case "variable_name":
			if phpText(m, n) != name || n.Id() == option.Id() {
				return
			}
			if inner {
				// A nested callable shares the name only through `global`.
				parent := n.Parent()
				proven = !(scope.Kind() == "program" && parent != nil && parent.Kind() == "global_declaration")
				return
			}
			if value := phpDominatingInitializer(n, call); value != nil && initializer == nil {
				initializer = value
				return
			}
			proven = false
			return
		}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			c := n.NamedChild(i)
			nested := inner
			switch n.Kind() {
			case "function_definition", "method_declaration", "arrow_function":
				nested = nested || n.Id() != scope.Id()
			case "anonymous_function":
				// The use clause names variables of the enclosing scope.
				nested = nested || n.Id() != scope.Id() && c.Kind() != "anonymous_function_use_clause"
			}
			visit(c, nested)
		}
	}
	visit(scope, false)
	if !proven {
		return nil
	}
	return initializer
}

// phpDominatingInitializer returns the assigned value when n is the target of
// a plain assignment statement that precedes the call in one of its enclosing
// blocks.
func phpDominatingInitializer(n, call *sitter.Node) *sitter.Node {
	assign := n.Parent()
	if assign == nil || assign.Kind() != "assignment_expression" || assign.EndByte() >= call.StartByte() {
		return nil
	}
	if left := phpField(assign, "left"); left == nil || left.Id() != n.Id() {
		return nil
	}
	stmt := assign.Parent()
	if stmt == nil || stmt.Kind() != "expression_statement" || stmt.Parent() == nil {
		return nil
	}
	for p := call.Parent(); p != nil; p = p.Parent() {
		if p.Id() == stmt.Parent().Id() {
			return phpField(assign, "right")
		}
	}
	return nil
}

func phpAllowedClasses(m *phpModule, option *sitter.Node) *sitter.Node {
	if option == nil || option.Kind() != "array_creation_expression" {
		return nil
	}
	var out *sitter.Node
	for i := uint(0); i < option.NamedChildCount(); i++ {
		pair := option.NamedChild(i)
		if pair.Kind() != "array_element_initializer" || pair.NamedChildCount() != 2 {
			// A spread can override a previous key.
			if strings.HasPrefix(phpText(m, pair), "...") {
				out = nil
			}
			continue
		}
		key, ok := phpStringLiteral(m, pair.NamedChild(0))
		if !ok {
			out = nil
		} else if key == "allowed_classes" {
			out = pair.NamedChild(1)
		}
	}
	return out
}

func phpLiteralClassList(m *phpModule, n *sitter.Node) bool {
	if n.Kind() != "array_creation_expression" {
		return false
	}
	for i := uint(0); i < n.NamedChildCount(); i++ {
		pair := n.NamedChild(i)
		if pair.Kind() == "comment" {
			continue
		}
		if pair.Kind() != "array_element_initializer" || pair.NamedChildCount() != 1 {
			return false
		}
		item := pair.NamedChild(0)
		if _, ok := phpStringLiteral(m, item); ok {
			continue
		}
		if item.Kind() != "class_constant_access_expression" || item.NamedChildCount() != 2 || !strings.EqualFold(phpText(m, item.NamedChild(1)), "class") || item.NamedChild(0).Kind() == "variable_name" {
			return false
		}
	}
	return true
}
