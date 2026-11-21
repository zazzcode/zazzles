package langjs

import (
	sitter "github.com/tree-sitter/go-tree-sitter"
)

// pollutionAliases holds the locals of one key loop that stand for the
// current source value or the current target slot.
type pollutionAliases struct {
	loop   pollutionLoop
	values map[string]*sitter.Node            // local -> declarator holding source[key]
	slots  map[string]map[string]*sitter.Node // parameter -> local -> declarator holding parameter[key]
}

func pollutionLoopAliases(m *sourceModule, loop pollutionLoop) pollutionAliases {
	a := pollutionAliases{loop: loop, values: map[string]*sitter.Node{}, slots: map[string]map[string]*sitter.Node{}}
	descriptors := map[string]bool{}
	pollutionWalk(loop.body, func(n *sitter.Node) {
		if n.Kind() != "variable_declarator" {
			return
		}
		name, init := pollutionIdentifier(n.ChildByFieldName("name"), m.src), pollutionUnwrap(n.ChildByFieldName("value"))
		if name == "" || init == nil {
			return
		}
		if pollutionSubscript(init, loop.source, loop.key, m.src) || pollutionDescriptorValue(m, init, loop, descriptors) {
			a.values[name] = n
			return
		}
		if pollutionDescriptor(m, init, loop) {
			descriptors[name] = true
			return
		}
		if slot := pollutionSlot(init, loop.key, m.src); slot != "" && slot != loop.source {
			if a.slots[slot] == nil {
				a.slots[slot] = map[string]*sitter.Node{}
			}
			a.slots[slot][name] = n
		}
	})
	return a
}

// pollutionSlot names the object of `object[key]`, also when the lookup is the
// left side of a chained assignment such as `t = object[key] = {}`.
func pollutionSlot(n *sitter.Node, key string, src []byte) string {
	n = pollutionUnwrap(n)
	if n != nil && n.Kind() == "assignment_expression" {
		n = pollutionUnwrap(n.ChildByFieldName("left"))
	}
	if n == nil || n.Kind() != "subscript_expression" || pollutionIdentifier(n.ChildByFieldName("index"), src) != key {
		return ""
	}
	return pollutionIdentifier(n.ChildByFieldName("object"), src)
}

func pollutionUnwrap(n *sitter.Node) *sitter.Node {
	for n = unwrapTS(n); n != nil && n.Kind() == "parenthesized_expression" && n.NamedChildCount() == 1; {
		n = unwrapTS(n.NamedChild(0))
	}
	return n
}

// pollutionDescriptor matches Object.getOwnPropertyDescriptor(source, key).
func pollutionDescriptor(m *sourceModule, n *sitter.Node, loop pollutionLoop) bool {
	args, ok := pollutionAPI(n, "Object.getOwnPropertyDescriptor", m.src)
	return ok && args != nil && args.NamedChildCount() == 2 && pollutionBuiltin(m, n, "Object", "getOwnPropertyDescriptor") &&
		pollutionIdentifier(args.NamedChild(0), m.src) == loop.source && pollutionIdentifier(args.NamedChild(1), m.src) == loop.key
}

func pollutionDescriptorValue(m *sourceModule, n *sitter.Node, loop pollutionLoop, descriptors map[string]bool) bool {
	if n.Kind() != "member_expression" {
		return false
	}
	object, property := pollutionUnwrap(n.ChildByFieldName("object")), n.ChildByFieldName("property")
	if object == nil || property == nil || property.Utf8Text(m.src) != "value" {
		return false
	}
	return descriptors[pollutionIdentifier(object, m.src)] || pollutionDescriptor(m, object, loop)
}

// recursiveOperands accepts a recursive call on the current target slot and the
// current source value, each written directly or through one unchanged local.
func (a pollutionAliases) recursiveOperands(m *sourceModule, call, args *sitter.Node, targetAt, sourceAt int, target string) bool {
	t, s := pollutionArg(args, targetAt), pollutionArg(args, sourceAt)
	loop, src := a.loop, m.src
	if !pollutionSubscript(t, target, loop.key, src) {
		slot := a.slots[target][pollutionIdentifier(t, src)]
		if slot == nil || !a.unchanged(m, slot, call, target) {
			return false
		}
	}
	if pollutionSubscript(s, loop.source, loop.key, src) || loop.value != "" && pollutionIdentifier(s, src) == loop.value {
		return true
	}
	current := a.values[pollutionIdentifier(s, src)]
	return current != nil && a.unchanged(m, current, call, "")
}

// unchanged reports that the local still holds its declared lookup at the call.
// A slot alias may be assigned the same slot again; any other write ends it.
func (a pollutionAliases) unchanged(m *sourceModule, declarator, call *sitter.Node, slot string) bool {
	name := pollutionIdentifier(declarator.ChildByFieldName("name"), m.src)
	if declarator.EndByte() > call.StartByte() {
		return false
	}
	stable := true
	pollutionWalk(a.loop.body, func(n *sitter.Node) {
		if n.StartByte() < declarator.EndByte() || n.EndByte() > call.StartByte() {
			return
		}
		switch n.Kind() {
		case "assignment_expression":
			if pollutionIdentifier(n.ChildByFieldName("left"), m.src) == name &&
				(slot == "" || pollutionSlot(n.ChildByFieldName("right"), a.loop.key, m.src) != slot) {
				stable = false
			}
		case "augmented_assignment_expression":
			stable = stable && pollutionIdentifier(n.ChildByFieldName("left"), m.src) != name
		case "update_expression":
			stable = stable && pollutionIdentifier(n.ChildByFieldName("argument"), m.src) != name
		case "variable_declarator":
			stable = stable && pollutionIdentifier(n.ChildByFieldName("name"), m.src) != name
		}
	})
	return stable
}

// pollutionOptionGates lists the tests on another parameter that enclose the
// recursive call. The caller sets such an option; it does not restrict the key.
func pollutionOptionGates(m *sourceModule, loop pollutionLoop, call *sitter.Node, params []boundParam, source, target int) []pollutionBranch {
	var gates []pollutionBranch
	child := call
	for parent := child.Parent(); parent != nil && child.Id() != loop.body.Id(); child, parent = parent, parent.Parent() {
		if parent.Kind() != "if_statement" {
			continue
		}
		cond, consequence := parent.ChildByFieldName("condition"), parent.ChildByFieldName("consequence")
		if cond == nil || consequence == nil || sameNode(cond, child) || pollutionBareKeyUse(cond, loop.key, m.src) {
			continue
		}
		for i, p := range params {
			if i != source && i != target && pollutionMentions(cond, p.name, m.src) {
				gates = append(gates, pollutionBranch{cond, sameNode(consequence, child)})
				break
			}
		}
	}
	return gates
}

func pollutionMentions(n *sitter.Node, name string, src []byte) bool {
	if n.Kind() == "identifier" {
		return n.Utf8Text(src) == name
	}
	for i := uint(0); i < n.NamedChildCount(); i++ {
		if pollutionMentions(n.NamedChild(i), name, src) {
			return true
		}
	}
	return false
}
