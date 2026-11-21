package langjs

import (
	"slices"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/parse"
)

func (f *flow) pollutionAssignment(site, lhs *sitter.Node) {
	if f.client != nil || f.pollutionRead || f.set == nil || lhs == nil || lhs.Kind() != "subscript_expression" {
		return
	}
	f.pollutionInlineAssignment(site, lhs)
	lookup := unwrapTS(lhs.ChildByFieldName("object"))
	if lookup == nil || lookup.Kind() != "subscript_expression" {
		return
	}
	key, target := lookup.ChildByFieldName("index"), unwrapTS(lookup.ChildByFieldName("object"))
	if key == nil || target == nil || target.Kind() == "subscript_expression" || pollutionLiteral(key) || f.pollutionLookupWritten(lookup) {
		return
	}
	v := f.pollutionReadValue(key)
	if !pollutionRequest([]value{v}) {
		return
	}
	guard := pollutionPartitionGuard(f.module, nil, key.Utf8Text(f.module.src), target.Utf8Text(f.module.src), false, site)
	if pollutionNullTarget(f.module, site, target) {
		guard.kind = "null_prototype_root"
		if target.Kind() == "call_expression" {
			guard.kind, guard.blocked = "null_prototype", allPrototypeKeys()
		}
		guard.evidence = append(guard.evidence, f.module.evidence("key_guard", target))
	}
	facts := &analysis.PollutionFacts{Operation: analysis.PollutionNested, KeyOperand: "computed_keys", KeyLevels: 2}
	f.recordPollution(site, 0, []pollutionOperand{{node: key, value: v}}, facts, []analysis.Evidence{f.module.evidence("sink_binding", lhs)}, guard)
}

func (f *flow) pollutionReadValue(n *sitter.Node) value {
	// A computed lhs is not otherwise evaluated as a new value by the shared
	// flow. Evaluate it in isolation so observing its key changes no other claim.
	probe := *f
	probe.pollutionRead = true
	probe.env = copyValues(f.env)
	probe.facts, probe.helpers, probe.conditions = nil, nil, nil
	probe.context, probe.gaps, probe.uses, probe.returns, probe.heapWrites = nil, nil, nil, nil, nil
	return probe.eval(n)
}

// The direct-write rule has no heap model for a receiver slot that an earlier
// statement replaced. Its current identity must come from an unchanged lookup.
// A write that only fills an absent slot leaves an inherited one in place, so
// the lookup can still yield the prototype and the rule applies.
func (f *flow) pollutionLookupWritten(lookup *sitter.Node) bool {
	slot := compactPollutionText(lookup, f.module.src)
	for _, writes := range [][]analysis.Gap{f.gaps, f.heapWrites} {
		for _, g := range writes {
			if g.Kind != "unsupported_write" || g.At.File != f.module.file || g.At.EndByte > int(lookup.StartByte()) {
				continue
			}
			n := parse.NodeAt(f.module.tree.RootNode(), g.At.StartByte, g.At.EndByte)
			if n == nil {
				continue
			}
			left := n.ChildByFieldName("left")
			if left != nil && compactPollutionText(left, f.module.src) == slot && !pollutionFillsAbsentSlot(f.module, n, lookup) {
				return true
			}
		}
	}
	return false
}

// pollutionFillsAbsentSlot reports a write that happens only while the slot
// has no value: `slot = slot || {}`, `slot ||= {}`, `slot ??= {}`, or an
// assignment that is the whole body of `if (!slot)` and its equivalents. An
// inherited slot such as __proto__ already has a value and is left unchanged.
// An own-property test is different: it replaces an inherited slot.
func pollutionFillsAbsentSlot(m *sourceModule, write, lookup *sitter.Node) bool {
	src := m.src
	slot := compactPollutionText(lookup, src)
	switch write.Kind() {
	case "augmented_assignment_expression":
		op := write.ChildByFieldName("operator")
		return op != nil && (op.Utf8Text(src) == "||=" || op.Utf8Text(src) == "??=")
	case "assignment_expression":
		if right := pollutionUnwrap(write.ChildByFieldName("right")); right != nil && right.Kind() == "binary_expression" {
			op := right.ChildByFieldName("operator")
			if op != nil && (op.Kind() == "||" || op.Kind() == "??") && compactPollutionText(pollutionUnwrap(right.ChildByFieldName("left")), src) == slot {
				return true
			}
		}
	default:
		return false
	}
	// The assignment is the only statement of an if without an else.
	body := write.Parent()
	if body == nil || body.Kind() != "expression_statement" {
		return false
	}
	branch := body.Parent()
	if branch != nil && branch.Kind() == "statement_block" {
		for i := uint(0); i < branch.NamedChildCount(); i++ {
			if c := branch.NamedChild(i); c.Kind() != "comment" && !sameNode(c, body) {
				return false
			}
		}
		body, branch = branch, branch.Parent()
	}
	if branch == nil || branch.Kind() != "if_statement" || branch.ChildByFieldName("alternative") != nil || !sameNode(branch.ChildByFieldName("consequence"), body) {
		return false
	}
	return pollutionAbsentTest(pollutionUnwrap(branch.ChildByFieldName("condition")), lookup, src)
}

// pollutionAbsentTest matches a test that an inherited object fails: `!slot`,
// a comparison of the slot with undefined or null, `typeof slot ===
// 'undefined'`, and `!(key in object)`.
func pollutionAbsentTest(cond, lookup *sitter.Node, src []byte) bool {
	if cond == nil {
		return false
	}
	slot := compactPollutionText(lookup, src)
	switch cond.Kind() {
	case "unary_expression":
		op, arg := cond.ChildByFieldName("operator"), pollutionUnwrap(cond.ChildByFieldName("argument"))
		if op == nil || op.Kind() != "!" || arg == nil {
			return false
		}
		if compactPollutionText(arg, src) == slot {
			return true
		}
		if in := arg.ChildByFieldName("operator"); arg.Kind() == "binary_expression" && in != nil && in.Kind() == "in" {
			return compactPollutionText(arg.ChildByFieldName("left"), src) == compactPollutionText(lookup.ChildByFieldName("index"), src) &&
				compactPollutionText(arg.ChildByFieldName("right"), src) == compactPollutionText(lookup.ChildByFieldName("object"), src)
		}
	case "binary_expression":
		op := cond.ChildByFieldName("operator")
		if op == nil || op.Kind() != "==" && op.Kind() != "===" {
			return false
		}
		left, right := compactPollutionText(pollutionUnwrap(cond.ChildByFieldName("left")), src), compactPollutionText(cond.ChildByFieldName("right"), src)
		if right == slot {
			left, right = right, left
		}
		return left == slot && (right == "undefined" || right == "null") ||
			left == "typeof"+slot && (right == "'undefined'" || right == "\"undefined\"")
	}
	return false
}

func pollutionLiteral(n *sitter.Node) bool {
	n = unwrapTS(n)
	if n == nil {
		return false
	}
	switch n.Kind() {
	case "string", "number", "true", "false", "null", "undefined", "regex":
		return true
	case "template_string":
		return n.NamedChildCount() == 1 && n.NamedChild(0).Kind() == "string_fragment"
	}
	return false
}

// sourcePollutionWrites analyzes a function once, independent of its callers.
func (s *moduleSet) sourcePollutionWrites(m *sourceModule, callee *sitter.Node) []pollutionWrite {
	if s.pollutionWrites == nil {
		s.pollutionWrites = make(map[uintptr][]pollutionWrite)
	}
	if writes, ok := s.pollutionWrites[callee.Id()]; ok {
		return writes
	}
	s.pollutionWrites[callee.Id()] = nil
	params, ok := functionParameters(callee, m.src)
	body := callee.ChildByFieldName("body")
	if !ok || len(params) < 1 || body == nil || body.Kind() != "statement_block" {
		return nil
	}
	var writes []pollutionWrite
	collect := func(w pollutionWrite) {
		for i := range writes {
			prior := &writes[i]
			if prior.operation != w.operation || prior.operand != w.operand || prior.source != w.source || prior.target != w.target ||
				prior.rootPath != w.rootPath || !sameNode(prior.rootDecl, w.rootDecl) {
				continue
			}
			prior.guard = intersectPollutionGuards(prior.guard, w.guard)
			for _, b := range w.branches {
				if !slices.ContainsFunc(prior.branches, func(prior pollutionBranch) bool { return prior.condition.Id() == b.condition.Id() }) {
					prior.branches = append(prior.branches, b)
				}
			}
			for _, site := range w.sites {
				if !slices.ContainsFunc(prior.sites, func(prior *sitter.Node) bool { return prior.Id() == site.Id() }) {
					prior.sites = append(prior.sites, site)
				}
			}
			return
		}
		writes = append(writes, w)
	}
	pollutionWalk(body, func(n *sitter.Node) {
		if loop := pollutionKeyLoop(m, n); loop.body != nil {
			for _, w := range s.pollutionMergeLoop(m, callee, params, loop) {
				collect(w)
			}
			// Unflatten: each key of the source is itself a path that is walked.
			pollutionWalk(loop.body, func(inner *sitter.Node) {
				for _, w := range pollutionPathWalks(m, loop.body, inner, params, &loop) {
					collect(w)
				}
			})
		}
		for _, w := range pollutionPathWalks(m, body, n, params, nil) {
			collect(w)
		}
	})
	for _, w := range s.pollutionRecursiveWalk(m, callee, params) {
		collect(w)
	}
	s.pollutionWrites[callee.Id()] = writes
	return writes
}

// pollutionPathWalks reads one node as a walk over path parts: a loop or a
// reduce call. scope bounds the search for the final write.
func pollutionPathWalks(m *sourceModule, scope, n *sitter.Node, params []boundParam, keys *pollutionLoop) []pollutionWrite {
	switch n.Kind() {
	case "for_statement", "for_in_statement", "while_statement":
		return pollutionPathLoop(m, scope, n, params, keys)
	case "call_expression":
		return append(pollutionReduceWalk(m, scope, n, params, keys), pollutionForEachWalk(m, scope, n, params, keys)...)
	}
	return nil
}

type pollutionLoop struct {
	body        *sitter.Node
	source, key string
	value       string
	// accumulator is the first callback parameter of a reduce over the keys and
	// start the object it begins as. While every return hands the accumulator
	// back, the two name one object.
	accumulator, start string
}

// names lists the identifiers that denote a parameter inside the loop body.
func (l pollutionLoop) names(parameter string) []string {
	if l.accumulator != "" && l.start == parameter {
		return []string{parameter, l.accumulator}
	}
	return []string{parameter}
}

func pollutionKeyLoop(m *sourceModule, n *sitter.Node) pollutionLoop {
	src := m.src
	if n.Kind() == "for_in_statement" {
		lhs, rhs, op := n.ChildByFieldName("left"), n.ChildByFieldName("right"), n.ChildByFieldName("operator")
		if lhs == nil || rhs == nil || op == nil {
			return pollutionLoop{}
		}
		if op.Kind() == "in" && rhs.Kind() == "identifier" && lhs.Kind() == "identifier" {
			return pollutionLoop{body: n.ChildByFieldName("body"), source: rhs.Utf8Text(src), key: lhs.Utf8Text(src)}
		}
		if op.Kind() == "of" {
			return pollutionObjectKeyLoop(m, unwrapTS(rhs), lhs, n.ChildByFieldName("body"))
		}
	}
	if n.Kind() != "call_expression" {
		return pollutionLoop{}
	}
	fn, args := n.ChildByFieldName("function"), n.ChildByFieldName("arguments")
	if fn == nil || fn.Kind() != "member_expression" || args == nil || args.NamedChildCount() < 1 {
		return pollutionLoop{}
	}
	prop := fn.ChildByFieldName("property")
	callback := args.NamedChild(0)
	if prop == nil || !isFunction(callback) {
		return pollutionLoop{}
	}
	keys, list := unwrapTS(fn.ChildByFieldName("object")), pollutionCallbackParameters(callback)
	switch prop.Utf8Text(src) {
	case "forEach", "map":
		// The callback receives each key; a map used for its effects is a forEach.
		if args.NamedChildCount() != 1 || len(list) != 1 {
			return pollutionLoop{}
		}
		return pollutionObjectKeyLoop(m, keys, list[0], callback.ChildByFieldName("body"))
	case "reduce":
		// reduce((accumulator, key) => { …; return accumulator }, start)
		start := pollutionIdentifier(pollutionArg(args, 1), src)
		if args.NamedChildCount() != 2 || len(list) != 2 || start == "" {
			return pollutionLoop{}
		}
		accumulator := pollutionIdentifier(list[0], src)
		loop := pollutionObjectKeyLoop(m, keys, list[1], callback.ChildByFieldName("body"))
		if loop.body == nil || accumulator == "" || !pollutionReturnsOnly(loop.body, accumulator, src) {
			return pollutionLoop{}
		}
		loop.accumulator, loop.start = accumulator, start
		return loop
	}
	return pollutionLoop{}
}

// pollutionCallbackParameters lists the binding patterns of a callback. A
// TypeScript parameter is a wrapper around its pattern, typed or not.
func pollutionCallbackParameters(callback *sitter.Node) []*sitter.Node {
	if single := callback.ChildByFieldName("parameter"); single != nil {
		return []*sitter.Node{single}
	}
	list := callback.ChildByFieldName("parameters")
	var out []*sitter.Node
	for i := uint(0); list != nil && i < list.NamedChildCount(); i++ {
		p := list.NamedChild(i)
		if p.Kind() == "required_parameter" || p.Kind() == "optional_parameter" {
			p = p.ChildByFieldName("pattern")
		}
		if p == nil {
			return nil
		}
		out = append(out, p)
	}
	return out
}

// pollutionReturnsOnly reports a block whose every return hands back name.
func pollutionReturnsOnly(body *sitter.Node, name string, src []byte) bool {
	if body.Kind() != "statement_block" {
		return false
	}
	returns, only := 0, true
	pollutionWalk(body, func(n *sitter.Node) {
		if n.Kind() == "return_statement" {
			returns++
			only = only && n.NamedChildCount() == 1 && pollutionIdentifier(n.NamedChild(0), src) == name
		}
	})
	return returns > 0 && only
}

// pollutionKeyEnumerators are the built-ins whose result lists the keys of their
// single argument. Each is accepted only where the global is not shadowed.
var pollutionKeyEnumerators = map[string]struct {
	root, member string
	entries      bool
}{
	"Object.keys":                {root: "Object", member: "keys"},
	"Object.entries":             {root: "Object", member: "entries", entries: true},
	"Object.getOwnPropertyNames": {root: "Object", member: "getOwnPropertyNames"},
	"Reflect.ownKeys":            {root: "Reflect", member: "ownKeys"},
}

func pollutionObjectKeyLoop(m *sourceModule, iter, key, body *sitter.Node) pollutionLoop {
	if iter == nil || iter.Kind() != "call_expression" || key == nil || body == nil {
		return pollutionLoop{}
	}
	fn, args := iter.ChildByFieldName("function"), iter.ChildByFieldName("arguments")
	if fn == nil || args == nil || args.NamedChildCount() != 1 || args.NamedChild(0).Kind() != "identifier" {
		return pollutionLoop{}
	}
	enumerator, ok := pollutionKeyEnumerators[fn.Utf8Text(m.src)]
	if !ok || !pollutionBuiltin(m, iter, enumerator.root, enumerator.member) {
		return pollutionLoop{}
	}
	result := pollutionLoop{source: args.NamedChild(0).Utf8Text(m.src), body: body}
	if !enumerator.entries {
		result.key = pollutionIdentifier(key, m.src)
	} else if key.Kind() == "array_pattern" && key.NamedChildCount() == 2 {
		result.key = pollutionIdentifier(key.NamedChild(0), m.src)
		result.value = pollutionIdentifier(key.NamedChild(1), m.src)
	}
	if result.key == "" {
		return pollutionLoop{}
	}
	return result
}

func (s *moduleSet) pollutionMergeLoop(m *sourceModule, callee *sitter.Node, params []boundParam, loop pollutionLoop) []pollutionWrite {
	source := pollutionParameter(params, loop.source)
	if source < 0 {
		return nil
	}
	type writeSite struct {
		assignments []*sitter.Node
		recursions  []*sitter.Node
	}
	sites := make([]writeSite, len(params))
	aliases := pollutionLoopAliases(m, loop)
	pollutionWalk(loop.body, func(n *sitter.Node) {
		switch n.Kind() {
		case "assignment_expression":
			lhs := n.ChildByFieldName("left")
			for i, p := range params {
				if i == source {
					continue
				}
				for _, name := range loop.names(p.name) {
					if pollutionSubscript(lhs, name, loop.key, m.src) {
						sites[i].assignments = append(sites[i].assignments, n)
					}
				}
			}
		case "call_expression":
			args := n.ChildByFieldName("arguments")
			for i, p := range params {
				if i == source {
					continue
				}
				for _, name := range loop.names(p.name) {
					if aliases.recursiveOperands(m, n, args, i, source, name) && s.pollutionRecurses(m, callee, n, i, source) {
						sites[i].recursions = append(sites[i].recursions, n)
						break
					}
				}
			}
		}
	})
	// Each recursion is guarded by the tests on any name of its target object.
	guardAt := func(call *sitter.Node, parameter string) pollutionGuard {
		var guard pollutionGuard
		for _, name := range loop.names(parameter) {
			guard = unitePollutionGuards(guard, pollutionPartitionGuard(m, loop.body, loop.key, name, true, call))
		}
		return guard
	}
	var writes []pollutionWrite
	for i, pair := range sites {
		if len(pair.assignments) > 0 && len(pair.recursions) > 0 {
			guard := guardAt(pair.recursions[0], params[i].name)
			for _, call := range pair.recursions[1:] {
				guard = intersectPollutionGuards(guard, guardAt(call, params[i].name))
			}
			w := pollutionWrite{operation: analysis.PollutionMerge, operand: "source", source: source, target: i, sites: pair.assignments, guard: guard}
			for _, call := range pair.recursions {
				w.branches = append(w.branches, pollutionOptionGates(m, loop, call, params, source, i)...)
			}
			writes = append(writes, w)
		}
	}
	return writes
}

func (s *moduleSet) pollutionRecurses(m *sourceModule, original, call *sitter.Node, target, source int) bool {
	owner, targetFn := s.resolveCall(m, call)
	if targetFn == nil || pollutionBindingWritten(m, call.ChildByFieldName("function")) {
		return false
	}
	if owner == m && targetFn.Id() == original.Id() {
		return true
	}
	params, ok := functionParameters(targetFn, owner.src)
	body := targetFn.ChildByFieldName("body")
	if !ok || len(params) <= max(target, source) || body == nil {
		return false
	}
	// One helper is supported when it forwards both parameters unchanged in an
	// unconditional return (or as its sole expression).
	n := body
	if n.Kind() == "statement_block" {
		if n.NamedChildCount() != 1 {
			return false
		}
		n = n.NamedChild(0)
		if (n.Kind() != "return_statement" && n.Kind() != "expression_statement") || n.NamedChildCount() != 1 {
			return false
		}
		n = n.NamedChild(0)
	}
	if n.Kind() != "call_expression" || pollutionBindingWritten(owner, n.ChildByFieldName("function")) {
		return false
	}
	resolved, callee := s.resolveCall(owner, n)
	args := n.ChildByFieldName("arguments")
	return resolved == m && callee != nil && callee.Id() == original.Id() &&
		pollutionIdentifier(pollutionArg(args, target), owner.src) == params[target].name &&
		pollutionIdentifier(pollutionArg(args, source), owner.src) == params[source].name
}

func pollutionWalk(n *sitter.Node, visit func(*sitter.Node)) {
	if n == nil || isFunction(n) || n.Kind() == "function_declaration" || n.Kind() == "method_definition" || n.Kind() == "generator_function_declaration" {
		return
	}
	visit(n)
	for i := uint(0); i < n.NamedChildCount(); i++ {
		pollutionWalk(n.NamedChild(i), visit)
	}
}

func pollutionParameter(params []boundParam, name string) int {
	for i, p := range params {
		if p.name == name {
			return i
		}
	}
	return -1
}

func pollutionSubscript(n *sitter.Node, object, key string, src []byte) bool {
	n = unwrapTS(n)
	return n != nil && n.Kind() == "subscript_expression" &&
		pollutionIdentifier(n.ChildByFieldName("object"), src) == object &&
		pollutionIdentifier(n.ChildByFieldName("index"), src) == key
}

func pollutionIdentifier(n *sitter.Node, src []byte) string {
	n = unwrapTS(n)
	if n != nil && n.Kind() == "identifier" {
		return n.Utf8Text(src)
	}
	return ""
}

func pollutionArg(args *sitter.Node, position int) *sitter.Node {
	if args == nil || position < 0 {
		return nil
	}
	for i := uint(0); i < args.NamedChildCount(); i++ {
		n := args.NamedChild(i)
		if n.Kind() == "comment" {
			continue
		}
		if position == 0 {
			return n
		}
		position--
	}
	return nil
}

func pollutionAPI(n *sitter.Node, name string, src []byte) (*sitter.Node, bool) {
	if n != nil && n.Kind() == "call_expression" {
		fn := n.ChildByFieldName("function")
		if fn != nil && fn.Utf8Text(src) == name {
			return n.ChildByFieldName("arguments"), true
		}
	}
	return nil, false
}
