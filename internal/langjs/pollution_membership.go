package langjs

import (
	"slices"

	sitter "github.com/tree-sitter/go-tree-sitter"
)

// pollutionMembershipGuard reads literal collections whose contents cannot
// change before the test. In particular, const alone does not protect a Set
// from mutation or a list from escaping to another function.
func pollutionMembershipGuard(m *sourceModule, call *sitter.Node, key string, passes, stringKey bool) ([]string, bool) {
	fn, args := call.ChildByFieldName("function"), call.ChildByFieldName("arguments")
	if !stringKey || passes || fn == nil || fn.Kind() != "member_expression" || fn.ChildByFieldName("optional_chain") != nil ||
		args == nil || args.NamedChildCount() != 1 || compactPollutionText(pollutionUnwrap(args.NamedChild(0)), m.src) != key {
		return nil, false
	}
	method := compactPollutionText(fn.ChildByFieldName("property"), m.src)
	list := pollutionUnwrap(fn.ChildByFieldName("object"))
	if list == nil {
		return nil, false
	}
	if list.Kind() == "identifier" {
		use := list
		name := use.Utf8Text(m.src)
		init := localInitializer(m, use, name)
		if init == nil {
			return nil, false
		}
		decl := init.Parent()
		if init.EndByte() > use.StartByte() || (decl.Kind() != "variable_declarator" || !isConstDeclaration(m, decl)) || !pollutionReadOnlyCollection(m, decl.ChildByFieldName("name"), method) {
			return nil, false
		}
		list = pollutionUnwrap(init)
	}
	switch method {
	case "has":
		if list == nil || list.Kind() != "new_expression" {
			return nil, false
		}
		constructor, args := list.ChildByFieldName("constructor"), list.ChildByFieldName("arguments")
		if pollutionIdentifier(constructor, m.src) != "Set" || args == nil || args.NamedChildCount() != 1 ||
			!pollutionBuiltin(m, list, "Set", "prototype.has") {
			return nil, false
		}
		list = pollutionUnwrap(args.NamedChild(0))
	case "includes":
		if !pollutionBuiltin(m, call, "Array", "prototype.includes") {
			return nil, false
		}
	default:
		return nil, false
	}
	if list == nil || list.Kind() != "array" {
		return nil, false
	}
	var blocked []string
	for i := uint(0); i < list.NamedChildCount(); i++ {
		item := list.NamedChild(i)
		if item.Kind() == "comment" {
			continue
		}
		name, ok := stringLiteral(item, m.src)
		if !ok {
			return nil, false
		}
		if slices.Contains(allPrototypeKeys(), name) {
			blocked = append(blocked, name)
		}
	}
	return blocked, true
}

func pollutionReadOnlyCollection(m *sourceModule, binding *sitter.Node, methods ...string) bool {
	name := binding.Utf8Text(m.src)
	cursor := m.tree.RootNode().Walk()
	defer cursor.Close()
	for {
		n := cursor.Node()
		if (n.Kind() == "identifier" || n.Kind() == "shorthand_property_identifier" || n.Kind() == "shorthand_property_identifier_pattern") &&
			n.Utf8Text(m.src) == name && !sameNode(n, binding) {
			member := n.Parent()
			call := member.Parent()
			if member.Kind() != "member_expression" || !sameNode(member.ChildByFieldName("object"), n) ||
				!slices.Contains(methods, compactPollutionText(member.ChildByFieldName("property"), m.src)) || call == nil ||
				call.Kind() != "call_expression" || !sameNode(call.ChildByFieldName("function"), member) {
				return false
			}
		}
		if cursor.GotoFirstChild() {
			continue
		}
		for !cursor.GotoNextSibling() {
			if !cursor.GotoParent() {
				return true
			}
		}
	}
}
