package langjs

import (
	"slices"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysispacks"
)

func allPrototypeKeys() []string {
	_, keys := analysispacks.ListPrototypeKeys(nil)
	return keys
}

// pollutionPartitionGuard reads only predicates that must pass before the
// prototype lookup. A key reassigned after a test no longer has that control.
func pollutionPartitionGuard(m *sourceModule, boundary *sitter.Node, key, target string, stringKey bool, site *sitter.Node) pollutionGuard {
	var guard pollutionGuard
	add := func(condition *sitter.Node, passes bool) {
		if condition == nil || !pollutionBareKeyUse(condition, key, m.src) {
			return
		}
		blocked, own, known := pollutionKeyPredicate(m, condition, key, target, passes, stringKey)
		if !known {
			guard.unknown = true
			if guard.kind == "" {
				guard.kind = "unknown"
			}
		}
		if len(blocked) > 0 && guard.kind != "own_property" {
			guard.kind = "deny_list"
		}
		if own {
			guard.kind, blocked = "own_property", allPrototypeKeys()
		}
		guard.blocked = append(guard.blocked, blocked...)
		guard.evidence = append(guard.evidence, m.evidence("key_guard", condition))
	}
	child := site
	for parent := child.Parent(); parent != nil; child, parent = parent, parent.Parent() {
		switch parent.Kind() {
		case "statement_block":
			for i := uint(0); i < parent.NamedChildCount(); i++ {
				sibling := parent.NamedChild(i)
				if sibling.StartByte() >= child.StartByte() {
					break
				}
				if sibling.Kind() == "if_statement" && sibling.ChildByFieldName("alternative") == nil && pollutionGuardExit(sibling.ChildByFieldName("consequence")) {
					cond := sibling.ChildByFieldName("condition")
					if pollutionBareKeyUse(cond, key, m.src) && pollutionStableBetween(m, key, target, cond, site) {
						add(cond, false)
					}
				}
			}
		case "if_statement":
			if consequence := parent.ChildByFieldName("consequence"); consequence != nil {
				cond := parent.ChildByFieldName("condition")
				if pollutionBareKeyUse(cond, key, m.src) && pollutionStableBetween(m, key, target, cond, site) {
					add(cond, consequence.Id() == child.Id())
				}
			}
		}
		if boundary != nil && parent.Id() == boundary.Id() {
			break
		}
		if isFunction(parent) || parent.Kind() == "function_declaration" {
			break
		}
	}
	return guard
}

func intersectPollutionGuards(a, b pollutionGuard) pollutionGuard {
	var guard pollutionGuard
	guard.evidence = append(append(guard.evidence, a.evidence...), b.evidence...)
	guard.unknown = a.unknown || b.unknown
	for _, name := range allPrototypeKeys() {
		if slices.Contains(a.blocked, name) && slices.Contains(b.blocked, name) {
			guard.blocked = append(guard.blocked, name)
		}
	}
	switch {
	case a.kind == "own_property" && b.kind == "own_property":
		guard.kind = "own_property"
	case len(guard.blocked) > 0:
		guard.kind = "deny_list"
	case guard.unknown:
		guard.kind = "unknown"
	}
	return guard
}

func pollutionStableBetween(m *sourceModule, key, target string, cond, site *sitter.Node) bool {
	if cond == nil {
		return false
	}
	stable := true
	root := site
	for root.Parent() != nil && root.StartByte() > cond.StartByte() {
		root = root.Parent()
	}
	pollutionWalk(root, func(n *sitter.Node) {
		if n.StartByte() <= cond.EndByte() || n.StartByte() >= site.StartByte() {
			return
		}
		var binding *sitter.Node
		switch n.Kind() {
		case "assignment_expression", "augmented_assignment_expression":
			binding = n.ChildByFieldName("left")
		case "variable_declarator":
			binding = n.ChildByFieldName("name")
		case "update_expression":
			binding = n.ChildByFieldName("argument")
		}
		if binding != nil {
			text := binding.Utf8Text(m.src)
			stable = stable && text != key && text != target
		}
	})
	return stable
}

func pollutionGuardExit(n *sitter.Node) bool {
	if n != nil && n.Kind() == "statement_block" {
		var actual *sitter.Node
		for i := uint(0); i < n.NamedChildCount(); i++ {
			c := n.NamedChild(i)
			if c.Kind() == "comment" {
				continue
			}
			if actual != nil {
				return false
			}
			actual = c
		}
		n = actual
	}
	if n == nil {
		return false
	}
	switch n.Kind() {
	case "continue_statement":
		return n.NamedChildCount() == 0
	case "return_statement", "throw_statement":
		return true
	}
	return false
}

func pollutionKeyPredicate(m *sourceModule, n *sitter.Node, key, target string, passes, stringKey bool) (blocked []string, own, known bool) {
	n = unwrapTS(n)
	if n == nil {
		return nil, false, false
	}
	if n.Kind() == "unary_expression" {
		if op := n.ChildByFieldName("operator"); op != nil && op.Kind() == "!" {
			return pollutionKeyPredicate(m, n.ChildByFieldName("argument"), key, target, !passes, stringKey)
		}
	}
	if n.Kind() == "binary_expression" {
		return pollutionKeyBinary(m, n, key, target, passes, stringKey)
	}
	if n.Kind() == "call_expression" && passes {
		for _, fn := range []string{"Object.hasOwn", "Object.prototype.hasOwnProperty.call"} {
			if args, ok := pollutionAPI(n, fn, m.src); ok && args != nil && args.NamedChildCount() == 2 && pollutionBuiltin(m, n, "Object", strings.TrimPrefix(fn, "Object.")) {
				a, b := args.NamedChild(0), args.NamedChild(1)
				return nil, a.Utf8Text(m.src) == target && b.Utf8Text(m.src) == key, true
			}
		}
	}
	return nil, false, false
}

func pollutionKeyBinary(m *sourceModule, n *sitter.Node, key, target string, passes, stringKey bool) ([]string, bool, bool) {
	left, right, op := n.ChildByFieldName("left"), n.ChildByFieldName("right"), n.ChildByFieldName("operator")
	if left == nil || right == nil || op == nil {
		return nil, false, false
	}
	if (op.Kind() == "||" && !passes) || (op.Kind() == "&&" && passes) {
		a, ownA, knownA := pollutionKeyPredicate(m, left, key, target, passes, stringKey)
		b, ownB, knownB := pollutionKeyPredicate(m, right, key, target, passes, stringKey)
		return append(a, b...), ownA || ownB, knownA && knownB
	}
	if !stringKey || !containsString([]string{"===", "==", "!==", "!="}, op.Kind()) {
		return nil, false, false
	}
	excludes := passes == strings.HasPrefix(op.Kind(), "!")
	if !excludes {
		return nil, false, false
	}
	if right.Utf8Text(m.src) == key {
		left, right = right, left
	}
	name, ok := stringLiteral(right, m.src)
	if left.Utf8Text(m.src) == key && ok {
		if containsString(allPrototypeKeys(), name) {
			return []string{name}, false, true
		}
		return nil, false, true
	}
	return nil, false, false
}

// A merge's ordinary field type/shape tests can read source[key] without
// restricting the key itself. Direct uses like permit(key) are unresolved.
func pollutionBareKeyUse(n *sitter.Node, key string, src []byte) bool {
	if n == nil {
		return false
	}
	if n.Utf8Text(src) == key {
		return true
	}
	if n.Kind() == "subscript_expression" || n.Kind() == "string" || n.Kind() == "comment" {
		return false
	}
	for i := uint(0); i < n.NamedChildCount(); i++ {
		if pollutionBareKeyUse(n.NamedChild(i), key, src) {
			return true
		}
	}
	return false
}
