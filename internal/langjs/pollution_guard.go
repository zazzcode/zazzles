package langjs

import (
	"slices"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
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

// pollutionTypeofString returns the operator of `typeof key <op> 'string'`.
func pollutionTypeofString(n *sitter.Node, key string, src []byte) string {
	n = pollutionUnwrap(n)
	if n == nil || n.Kind() != "binary_expression" {
		return ""
	}
	left, right, op := pollutionUnwrap(n.ChildByFieldName("left")), n.ChildByFieldName("right"), n.ChildByFieldName("operator")
	if left == nil || right == nil || op == nil || left.Kind() != "unary_expression" {
		return ""
	}
	of, operand := left.ChildByFieldName("operator"), left.ChildByFieldName("argument")
	if name, ok := stringLiteral(right, src); !ok || name != "string" || of == nil || of.Kind() != "typeof" || operand == nil || operand.Utf8Text(src) != key {
		return ""
	}
	return op.Kind()
}

// pollutionStringChecked reports that a part which is not a string never
// reaches the lookup: an earlier statement of an enclosing block exits when
// `typeof key !== 'string'`, alone or as one alternative of an `||` test.
func pollutionStringChecked(m *sourceModule, boundary *sitter.Node, key, target string, site *sitter.Node) bool {
	var rejects func(*sitter.Node) bool
	rejects = func(cond *sitter.Node) bool {
		cond = pollutionUnwrap(cond)
		if cond == nil {
			return false
		}
		if op := pollutionTypeofString(cond, key, m.src); op != "" {
			return op == "!==" || op == "!="
		}
		if cond.Kind() == "binary_expression" {
			if op := cond.ChildByFieldName("operator"); op != nil && op.Kind() == "||" {
				return rejects(cond.ChildByFieldName("left")) || rejects(cond.ChildByFieldName("right"))
			}
		}
		return false
	}
	child := site
	for parent := child.Parent(); parent != nil; child, parent = parent, parent.Parent() {
		if parent.Kind() == "statement_block" {
			for i := uint(0); i < parent.NamedChildCount(); i++ {
				sibling := parent.NamedChild(i)
				if sibling.StartByte() >= child.StartByte() {
					break
				}
				if sibling.Kind() == "if_statement" && sibling.ChildByFieldName("alternative") == nil && pollutionGuardExit(sibling.ChildByFieldName("consequence")) {
					if cond := sibling.ChildByFieldName("condition"); rejects(cond) && pollutionStableBetween(m, key, target, cond, site) {
						return true
					}
				}
			}
		}
		if boundary != nil && sameNode(parent, boundary) || isFunction(parent) || parent.Kind() == "function_declaration" {
			break
		}
	}
	return false
}

// unitePollutionGuards combines two guards that both stand before one lookup.
// A name either of them blocks is blocked.
func unitePollutionGuards(a, b pollutionGuard) pollutionGuard {
	if b.kind == "" && len(b.evidence) == 0 {
		return a
	}
	guard := pollutionGuard{unknown: a.unknown || b.unknown, evidence: append([]analysis.Evidence{}, a.evidence...)}
	for _, e := range b.evidence {
		if !slices.ContainsFunc(guard.evidence, func(prior analysis.Evidence) bool { return prior.Span == e.Span }) {
			guard.evidence = append(guard.evidence, e)
		}
	}
	guard.blocked = append(append(guard.blocked, a.blocked...), b.blocked...)
	switch {
	case a.kind == "own_property" || b.kind == "own_property":
		guard.kind = "own_property"
	case len(guard.blocked) > 0:
		guard.kind = "deny_list"
	case guard.unknown:
		guard.kind = "unknown"
	}
	return guard
}

// pollutionPathNames lists the bindings that hold the whole path of a walk: the
// array of parts and the string it was split from.
func pollutionPathNames(parts string, w pollutionWrite, params []boundParam, keys *pollutionLoop) []string {
	names := []string{parts}
	if w.operand == "source_keys" && keys != nil {
		names = append(names, keys.key)
	} else if w.source >= 0 && w.source < len(params) && params[w.source].name != parts {
		names = append(names, params[w.source].name)
	}
	return names
}

// pollutionWholePathGuard reads deny-list tests on the whole path that must
// pass before the walk: `if (path.includes('__proto__')) return`. Such a test
// rejects the name in every part. Other tests on the path are not key guards.
func pollutionWholePathGuard(m *sourceModule, walk *sitter.Node, names []string) pollutionGuard {
	var guard pollutionGuard
	add := func(cond *sitter.Node, passes bool) {
		var blocked []string
		for _, name := range names {
			if found := pollutionContainsTests(m, cond, name, passes); len(found) > 0 && pollutionStableBetween(m, name, "", cond, walk) {
				blocked = append(blocked, found...)
			}
		}
		if len(blocked) > 0 {
			guard.kind = "deny_list"
			guard.blocked = append(guard.blocked, blocked...)
			guard.evidence = append(guard.evidence, m.evidence("key_guard", cond))
		}
	}
	child := walk
	for parent := child.Parent(); parent != nil; child, parent = parent, parent.Parent() {
		switch parent.Kind() {
		case "statement_block":
			for i := uint(0); i < parent.NamedChildCount(); i++ {
				sibling := parent.NamedChild(i)
				if sibling.StartByte() >= child.StartByte() {
					break
				}
				if sibling.Kind() == "if_statement" && sibling.ChildByFieldName("alternative") == nil && pollutionGuardExit(sibling.ChildByFieldName("consequence")) {
					add(sibling.ChildByFieldName("condition"), false)
				}
			}
		case "if_statement":
			cond, consequence := parent.ChildByFieldName("condition"), parent.ChildByFieldName("consequence")
			if cond != nil && consequence != nil && !sameNode(cond, child) {
				add(cond, sameNode(consequence, child))
			}
		}
		if isFunction(parent) || parent.Kind() == "function_declaration" || parent.Kind() == "method_definition" {
			break
		}
	}
	return guard
}

// pollutionContainsTests lists the prototype names that name cannot contain
// once the condition has the given outcome.
func pollutionContainsTests(m *sourceModule, n *sitter.Node, name string, passes bool) []string {
	n = pollutionUnwrap(n)
	if n == nil {
		return nil
	}
	contains := func(call *sitter.Node, method string) string {
		call = pollutionUnwrap(call)
		if call == nil || call.Kind() != "call_expression" {
			return ""
		}
		fn, args := call.ChildByFieldName("function"), call.ChildByFieldName("arguments")
		if fn == nil || fn.Kind() != "member_expression" || args == nil || args.NamedChildCount() != 1 {
			return ""
		}
		prop := fn.ChildByFieldName("property")
		literal, ok := stringLiteral(args.NamedChild(0), m.src)
		if prop == nil || prop.Utf8Text(m.src) != method || !ok || pollutionIdentifier(fn.ChildByFieldName("object"), m.src) != name || !containsString(allPrototypeKeys(), literal) {
			return ""
		}
		return literal
	}
	switch n.Kind() {
	case "unary_expression":
		if op := n.ChildByFieldName("operator"); op != nil && op.Kind() == "!" {
			return pollutionContainsTests(m, n.ChildByFieldName("argument"), name, !passes)
		}
	case "call_expression":
		if literal := contains(n, "includes"); literal != "" && !passes {
			return []string{literal}
		}
	case "binary_expression":
		left, right, op := n.ChildByFieldName("left"), n.ChildByFieldName("right"), n.ChildByFieldName("operator")
		if left == nil || right == nil || op == nil {
			return nil
		}
		if (op.Kind() == "||" && !passes) || (op.Kind() == "&&" && passes) {
			return append(pollutionContainsTests(m, left, name, passes), pollutionContainsTests(m, right, name, passes)...)
		}
		// indexOf(name) compared with -1 or 0 states whether the name occurs.
		literal, bound := contains(left, "indexOf"), compactPollutionText(right, m.src)
		if literal == "" {
			return nil
		}
		occurs := containsString([]string{"!==-1", "!=-1", ">-1", ">=0"}, op.Kind()+bound)
		absent := containsString([]string{"===-1", "==-1", "<0"}, op.Kind()+bound)
		if occurs && !passes || absent && passes {
			return []string{literal}
		}
	}
	return nil
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
	if n.Kind() == "call_expression" {
		if own, ok := pollutionOwnMethod(m, n, key, target); ok && (passes || !own) {
			return nil, own, true
		}
		return pollutionHelperPredicate(m, n, key, target, passes, stringKey)
	}
	return nil, false, false
}

// pollutionOwnMethod reads `object.hasOwnProperty(key)`. On the target it is an
// own-property test. On any other object it says nothing about the lookup.
func pollutionOwnMethod(m *sourceModule, n *sitter.Node, key, target string) (own, ok bool) {
	fn, args := n.ChildByFieldName("function"), n.ChildByFieldName("arguments")
	if fn == nil || fn.Kind() != "member_expression" || args == nil || args.NamedChildCount() != 1 || args.NamedChild(0).Utf8Text(m.src) != key {
		return false, false
	}
	if p := fn.ChildByFieldName("property"); p == nil || p.Utf8Text(m.src) != "hasOwnProperty" {
		return false, false
	}
	object := pollutionIdentifier(fn.ChildByFieldName("object"), m.src)
	return object == target, object != ""
}

// pollutionHelperPredicate reads a key test written as a one-line function of
// this module, such as `function isValidKey(key) { return key !== '__proto__' }`
// or a wrapper around hasOwnProperty. The helper's single returned expression is
// read with the call's arguments in place of its parameters. A helper that
// calls another function is not read.
func pollutionHelperPredicate(m *sourceModule, call *sitter.Node, key, target string, passes, stringKey bool) ([]string, bool, bool) {
	fn, args := call.ChildByFieldName("function"), call.ChildByFieldName("arguments")
	if fn == nil || fn.Kind() != "identifier" || args == nil {
		return nil, false, false
	}
	name := fn.Utf8Text(m.src)
	helper := m.funcs[name]
	if helper == nil || m.cachedShadowed(call, name) || pollutionBindingWritten(m, fn) {
		return nil, false, false
	}
	params, ok := functionParameters(helper, m.src)
	test := helper.ChildByFieldName("body")
	if test != nil && test.Kind() == "statement_block" {
		if test.NamedChildCount() != 1 || test.NamedChild(0).Kind() != "return_statement" || test.NamedChild(0).NamedChildCount() != 1 {
			return nil, false, false
		}
		test = test.NamedChild(0).NamedChild(0)
	}
	if !ok || test == nil || pollutionCallsFunction(test, m.src) {
		return nil, false, false
	}
	// No parameter can be named like this, so an absent target never matches.
	keyParam, targetParam := "", "\x00"
	for i, p := range params {
		switch compactPollutionText(pollutionUnwrap(pollutionArg(args, i)), m.src) {
		case key:
			keyParam = p.name
		case target:
			targetParam = p.name
		}
	}
	if keyParam == "" {
		return nil, false, false
	}
	return pollutionKeyPredicate(m, test, keyParam, targetParam, passes, stringKey)
}

// pollutionCallsFunction reports a call to a plain identifier, which could be
// another helper. Member calls such as Object.prototype.hasOwnProperty.call
// are read by the predicate code itself.
func pollutionCallsFunction(n *sitter.Node, src []byte) bool {
	if n.Kind() == "call_expression" {
		if fn := n.ChildByFieldName("function"); fn != nil && fn.Kind() == "identifier" {
			return true
		}
	}
	for i := uint(0); i < n.NamedChildCount(); i++ {
		if pollutionCallsFunction(n.NamedChild(i), src) {
			return true
		}
	}
	return false
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
	if pollutionTypeofString(n, key, m.src) != "" {
		// A type test restricts the shape of the key and blocks no name.
		return nil, false, true
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
