package langjs

import (
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
)

// pollutionPathLoop reads a loop that steps a cursor through the parts of a
// path. keys is the enclosing key loop when the path may be one of its keys.
func pollutionPathLoop(m *sourceModule, body, loop *sitter.Node, params []boundParam, keys *pollutionLoop) []pollutionWrite {
	loopBody := loop.ChildByFieldName("body")
	if loopBody == nil {
		return nil
	}
	var writes []pollutionWrite
	pollutionWalk(loopBody, func(n *sitter.Node) {
		if n.Kind() != "assignment_expression" {
			return
		}
		left := unwrapTS(n.ChildByFieldName("left"))
		cursor := pollutionIdentifier(left, m.src)
		lookup := unwrapTS(n.ChildByFieldName("right"))
		if cursor == "" || lookup == nil || lookup.Kind() != "subscript_expression" || pollutionIdentifier(lookup.ChildByFieldName("object"), m.src) != cursor {
			return
		}
		part := lookup.ChildByFieldName("index")
		parts, key := pollutionPathParts(m, loop, part)
		if parts == "" {
			return
		}
		w, ok := pollutionPathWrite(m, loop, parts, pollutionCursorStart(m, loop, left, params), params, keys)
		if !ok {
			return
		}
		if final := pollutionPathFinal(m, body, loop, cursor, key, parts); final != nil {
			w.sites = []*sitter.Node{final}
			guard := pollutionWalkGuard(m, loop, loopBody, key, cursor, parts, w, params, keys, n)
			w.guard = pollutionRootGuard(m, loop, w, guard)
			writes = append(writes, w)
		}
	})
	return writes
}

// pollutionPathWrite resolves the operand that supplies the parts and the object
// the walk starts from. start is that object's identifier. A walk over a
// parameter's own path needs a parameter target. A walk over the keys of a
// source may also start from a local object.
func pollutionPathWrite(m *sourceModule, at *sitter.Node, parts string, start *sitter.Node, params []boundParam, keys *pollutionLoop) (pollutionWrite, bool) {
	source, operand := pollutionPartsSource(m, at, parts, params, keys)
	w := pollutionWrite{operation: analysis.PollutionWalk, operand: operand, source: source, target: -1}
	w.untyped = pollutionParameter(params, parts) >= 0
	if (keys != nil) != (operand == "source_keys") || source < 0 || start == nil || start.Kind() != "identifier" {
		return w, false
	}
	name := start.Utf8Text(m.src)
	if w.target = pollutionParameter(params, name); w.target < 0 && keys != nil && localInitializer(m, at, name) != nil {
		w.root = start
	}
	return w, w.target != source && (w.target >= 0 || w.root != nil)
}

// pollutionCursorStart names the object a loop cursor starts from: the cursor
// itself when it is a parameter, otherwise the identifier it is declared with.
func pollutionCursorStart(m *sourceModule, loop, cursor *sitter.Node, params []boundParam) *sitter.Node {
	if pollutionParameter(params, cursor.Utf8Text(m.src)) >= 0 {
		return cursor
	}
	return unwrapTS(localInitializer(m, loop, cursor.Utf8Text(m.src)))
}

// pollutionWalkGuard reads the key guards before one lookup of a walk: the
// tests on the part inside the step and the deny-list tests on the whole path
// before the walk. The elements of an array the caller passes are untyped, and
// a nested array such as ['__proto__'] passes a string comparison and still
// names the key. There a literal comparison counts only after a typeof test,
// and a test on the whole array is not read.
func pollutionWalkGuard(m *sourceModule, walk, step *sitter.Node, key, cursor, parts string, w pollutionWrite, params []boundParam, keys *pollutionLoop, site *sitter.Node) pollutionGuard {
	guard := pollutionPartitionGuard(m, step, key, cursor, !w.untyped || pollutionStringChecked(m, step, key, cursor, site), site)
	if w.untyped {
		return guard
	}
	return unitePollutionGuards(guard, pollutionWholePathGuard(m, walk, pollutionPathNames(parts, w, params, keys)))
}

// A local root made by Object.create(null) covers only the first lookup.
func pollutionRootGuard(m *sourceModule, at *sitter.Node, w pollutionWrite, guard pollutionGuard) pollutionGuard {
	if w.root != nil && guard.kind == "" && pollutionNullTarget(m, at, w.root) {
		return pollutionGuard{kind: "null_prototype_root", evidence: []analysis.Evidence{m.evidence("key_guard", w.root)}}
	}
	return guard
}

func pollutionPathParts(m *sourceModule, loop, part *sitter.Node) (parts, key string) {
	if part == nil {
		return "", ""
	}
	src := m.src
	key = part.Utf8Text(src)
	if loop.Kind() == "for_in_statement" {
		op, left, right := loop.ChildByFieldName("operator"), loop.ChildByFieldName("left"), loop.ChildByFieldName("right")
		if op == nil || op.Kind() != "of" || pollutionIdentifier(left, src) != key {
			return "", ""
		}
		if right != nil && right.Kind() == "call_expression" {
			fn, args := right.ChildByFieldName("function"), right.ChildByFieldName("arguments")
			if fn != nil && args != nil && fn.Kind() == "member_expression" && compactPollutionText(args, src) == "(0,-1)" {
				if p := fn.ChildByFieldName("property"); p != nil && p.Utf8Text(src) == "slice" {
					right = fn.ChildByFieldName("object")
				}
			}
		}
		return pollutionIdentifier(right, src), key
	}
	if part.Kind() == "identifier" {
		part = localInitializer(m, part, key)
	}
	if loop.Kind() == "while_statement" {
		return pollutionConsumedParts(m, loop, part), key
	}
	if part == nil || part.Kind() != "subscript_expression" {
		return "", ""
	}
	parts = pollutionIdentifier(part.ChildByFieldName("object"), src)
	index := pollutionIdentifier(part.ChildByFieldName("index"), src)
	if parts == "" || index == "" {
		return "", ""
	}
	// Require the loop to index the same split array in forward order.
	start, test, step := loop.ChildByFieldName("initializer"), loop.ChildByFieldName("condition"), loop.ChildByFieldName("increment")
	if start == nil || test == nil || step == nil {
		return "", ""
	}
	startText, testText, stepText := compactPollutionText(start, src), compactPollutionText(test, src), compactPollutionText(step, src)
	if !containsString([]string{"let" + index + "=0;", "var" + index + "=0;", index + "=0"}, startText) ||
		!containsString([]string{index + "<" + parts + ".length", index + "<" + parts + ".length-1"}, testText) ||
		!containsString([]string{index + "++", "++" + index, index + "+=1"}, stepText) {
		return "", ""
	}
	return parts, key
}

// pollutionReduceWalk reads `parts.reduce((cursor, part) => cursor[part], target)`
// whose result later receives the final indexed assignment.
func pollutionReduceWalk(m *sourceModule, scope, call *sitter.Node, params []boundParam, keys *pollutionLoop) []pollutionWrite {
	fn, args := call.ChildByFieldName("function"), call.ChildByFieldName("arguments")
	if fn == nil || fn.Kind() != "member_expression" || args == nil || args.NamedChildCount() != 2 {
		return nil
	}
	prop, callback, start := fn.ChildByFieldName("property"), args.NamedChild(0), unwrapTS(args.NamedChild(1))
	if prop == nil || prop.Utf8Text(m.src) != "reduce" || !isFunction(callback) || start.Kind() != "identifier" {
		return nil
	}
	steps, ok := functionParameters(callback, m.src)
	walked := unwrapTS(fn.ChildByFieldName("object"))
	if !ok || len(steps) < 2 || walked == nil {
		return nil
	}
	if walked.Kind() == "call_expression" {
		// parts.slice(0, -1) leaves the last part for the final write.
		slice, sliceArgs := walked.ChildByFieldName("function"), walked.ChildByFieldName("arguments")
		if slice == nil || slice.Kind() != "member_expression" || compactPollutionText(sliceArgs, m.src) != "(0,-1)" {
			return nil
		}
		if p := slice.ChildByFieldName("property"); p == nil || p.Utf8Text(m.src) != "slice" {
			return nil
		}
		walked = unwrapTS(slice.ChildByFieldName("object"))
	}
	parts, cursor, part := pollutionIdentifier(walked, m.src), steps[0].name, steps[1].name
	if parts == "" {
		return nil
	}
	step := callback.ChildByFieldName("body")
	lookups := pollutionReduceLookups(step, cursor, part, m.src)
	if len(lookups) == 0 {
		return nil
	}
	// The walk result is a declared local, or is indexed in place.
	holder, statement := "", call
	if p := call.Parent(); p != nil && p.Kind() == "variable_declarator" && sameNode(p.ChildByFieldName("value"), call) {
		holder, statement = pollutionIdentifier(p.ChildByFieldName("name"), m.src), p
	}
	w, ok := pollutionPathWrite(m, call, parts, start, params, keys)
	if !ok {
		return nil
	}
	final := pollutionReduceFinal(m, scope, call, statement, holder, parts)
	if final == nil {
		return nil
	}
	guard := pollutionWalkGuard(m, statement, step, part, cursor, parts, w, params, keys, lookups[0])
	for _, lookup := range lookups[1:] {
		guard = intersectPollutionGuards(guard, pollutionWalkGuard(m, statement, step, part, cursor, parts, w, params, keys, lookup))
	}
	w.sites, w.guard = []*sitter.Node{final}, pollutionRootGuard(m, call, w, guard)
	return []pollutionWrite{w}
}

// pollutionReduceLookups lists where the callback returns the next lookup on
// its accumulator: its expression body, or each such return of its block.
func pollutionReduceLookups(step *sitter.Node, cursor, part string, src []byte) []*sitter.Node {
	var lookups []*sitter.Node
	if step == nil {
		return nil
	}
	if step.Kind() != "statement_block" {
		if pollutionLookup(step, cursor, part, src) {
			lookups = append(lookups, step)
		}
		return lookups
	}
	pollutionWalk(step, func(n *sitter.Node) {
		if n.Kind() == "return_statement" && n.NamedChildCount() == 1 && pollutionLookup(n.NamedChild(0), cursor, part, src) {
			lookups = append(lookups, n)
		}
	})
	return lookups
}

// pollutionLookup matches cursor[part], also as the left side of a default
// such as `cursor[part] || {}` or of an assignment that creates the slot.
func pollutionLookup(n *sitter.Node, cursor, part string, src []byte) bool {
	n = pollutionUnwrap(n)
	if n == nil {
		return false
	}
	switch n.Kind() {
	case "binary_expression":
		if op := n.ChildByFieldName("operator"); op == nil || op.Kind() != "||" && op.Kind() != "??" {
			return false
		}
		return pollutionLookup(n.ChildByFieldName("left"), cursor, part, src)
	case "assignment_expression":
		return pollutionLookup(n.ChildByFieldName("left"), cursor, part, src)
	}
	return pollutionSubscript(n, cursor, part, src)
}

func pollutionReduceFinal(m *sourceModule, scope, call, statement *sitter.Node, holder, parts string) *sitter.Node {
	if holder != "" {
		if bindingReassigned(m, holder) {
			return nil
		}
		return pollutionPathFinal(m, scope, statement, holder, "", parts)
	}
	// parts.reduce(...)[last] = value
	lookup := call.Parent()
	if lookup == nil || lookup.Kind() != "subscript_expression" || !sameNode(lookup.ChildByFieldName("object"), call) {
		return nil
	}
	write := lookup.Parent()
	if write == nil || write.Kind() != "assignment_expression" || !sameNode(write.ChildByFieldName("left"), lookup) || !pollutionLastPart(m, lookup.ChildByFieldName("index"), parts, false) {
		return nil
	}
	return write
}

// pollutionLastPart matches the final part of the walked array. After a loop
// that consumed the earlier parts, the remaining first part is also the last.
func pollutionLastPart(m *sourceModule, index *sitter.Node, parts string, consumed bool) bool {
	if index == nil {
		return false
	}
	if index.Kind() == "identifier" {
		index = localInitializer(m, index, index.Utf8Text(m.src))
	}
	text := compactPollutionText(index, m.src)
	return text == parts+"["+parts+".length-1]" || text == parts+".pop()" ||
		consumed && (text == parts+"[0]" || text == parts+".shift()")
}

func pollutionPathFinal(m *sourceModule, body, loop *sitter.Node, cursor, key, parts string) *sitter.Node {
	var write *sitter.Node
	pollutionWalk(body, func(n *sitter.Node) {
		if write != nil || n.Kind() != "assignment_expression" || n.StartByte() < loop.StartByte() {
			return
		}
		lhs := n.ChildByFieldName("left")
		if lhs == nil || lhs.Kind() != "subscript_expression" || pollutionIdentifier(lhs.ChildByFieldName("object"), m.src) != cursor {
			return
		}
		index := lhs.ChildByFieldName("index")
		if index == nil {
			return
		}
		if n.EndByte() <= loop.EndByte() {
			if index.Utf8Text(m.src) == key && pollutionFinalIteration(n, loop, parts, m.src) {
				write = n
			}
			return
		}
		if pollutionLastPart(m, index, parts, loop.Kind() == "while_statement") {
			write = n
		}
	})
	return write
}

func pollutionFinalIteration(site, loop *sitter.Node, parts string, src []byte) bool {
	cond := loop.ChildByFieldName("condition")
	if cond == nil || cond.Kind() != "binary_expression" {
		return false
	}
	i := pollutionIdentifier(cond.ChildByFieldName("left"), src)
	if i == "" {
		return false
	}
	for n := site.Parent(); n != nil && n.Id() != loop.Id(); n = n.Parent() {
		if n.Kind() != "if_statement" {
			continue
		}
		branch := n.ChildByFieldName("consequence")
		if branch == nil || site.StartByte() < branch.StartByte() || site.EndByte() > branch.EndByte() {
			continue
		}
		test := compactPollutionText(unwrapTS(n.ChildByFieldName("condition")), src)
		if containsString([]string{i + "==" + parts + ".length-1", i + "===" + parts + ".length-1"}, test) {
			return true
		}
	}
	return false
}

func compactPollutionText(n *sitter.Node, src []byte) string {
	if n == nil {
		return ""
	}
	return strings.Join(strings.Fields(n.Utf8Text(src)), "")
}
