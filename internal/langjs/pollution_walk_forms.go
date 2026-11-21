package langjs

import (
	"slices"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
)

// pollutionSlicedParts names the array a walk reads: the identifier itself, or
// the object of `parts.slice(0, -1)`, which leaves the last part for the write.
func pollutionSlicedParts(m *sourceModule, walked *sitter.Node) string {
	walked = unwrapTS(walked)
	if walked != nil && walked.Kind() == "call_expression" {
		slice, args := walked.ChildByFieldName("function"), walked.ChildByFieldName("arguments")
		if slice == nil || slice.Kind() != "member_expression" || compactPollutionText(args, m.src) != "(0,-1)" {
			return ""
		}
		if p := slice.ChildByFieldName("property"); p == nil || p.Utf8Text(m.src) != "slice" {
			return ""
		}
		walked = unwrapTS(slice.ChildByFieldName("object"))
	}
	return pollutionIdentifier(walked, m.src)
}

// pollutionForEachWalk reads a walk whose step is the body of a forEach over
// the parts: `parts.slice(0, -1).forEach(function (part) { cursor = cursor[part] })`
// followed by the final indexed assignment through the cursor.
func pollutionForEachWalk(m *sourceModule, scope, call *sitter.Node, params []boundParam, keys *pollutionLoop) []pollutionWrite {
	fn, args := call.ChildByFieldName("function"), call.ChildByFieldName("arguments")
	if fn == nil || fn.Kind() != "member_expression" || args == nil || args.NamedChildCount() != 1 {
		return nil
	}
	prop, callback := fn.ChildByFieldName("property"), args.NamedChild(0)
	if prop == nil || prop.Utf8Text(m.src) != "forEach" || !isFunction(callback) {
		return nil
	}
	steps, body := pollutionCallbackParameters(callback), callback.ChildByFieldName("body")
	parts := pollutionSlicedParts(m, fn.ChildByFieldName("object"))
	if len(steps) == 0 || body == nil || parts == "" {
		return nil
	}
	part := pollutionIdentifier(steps[0], m.src)
	if part == "" {
		return nil
	}
	var writes []pollutionWrite
	pollutionWalk(body, func(n *sitter.Node) {
		if n.Kind() != "assignment_expression" {
			return
		}
		left := unwrapTS(n.ChildByFieldName("left"))
		cursor := pollutionIdentifier(left, m.src)
		if cursor == "" || !pollutionSubscript(n.ChildByFieldName("right"), cursor, part, m.src) {
			return
		}
		w, ok := pollutionPathWrite(m, call, parts, pollutionCursorStart(m, call, left, params), params, keys)
		if !ok {
			return
		}
		if final := pollutionPathFinal(m, scope, call, cursor, part, parts); final != nil {
			w.sites = []*sitter.Node{final}
			w.guard = pollutionRootGuard(m, call, w, pollutionWalkGuard(m, call, body, part, cursor, parts, w, params, keys, n))
			writes = append(writes, w)
		}
	})
	return writes
}

// pollutionRecursiveWalk reads a function that walks a path by calling itself
// on the next object: `f(obj[key], path, value, index + 1)` with
// `key = path[index]`, or `f(obj[key], path.slice(1), value)` with
// `key = path[0]`, together with a write `obj[key] = …` in the same function
// or through a helper that performs it.
func (s *moduleSet) pollutionRecursiveWalk(m *sourceModule, callee *sitter.Node, params []boundParam) []pollutionWrite {
	body := callee.ChildByFieldName("body")
	var writes []pollutionWrite
	pollutionWalk(body, func(call *sitter.Node) {
		if call.Kind() != "call_expression" || pollutionBindingWritten(m, call.ChildByFieldName("function")) {
			return
		}
		if owner, target := s.resolveCall(m, call); owner != m || target == nil || target.Id() != callee.Id() {
			return
		}
		args := call.ChildByFieldName("arguments")
		for t, object := range params {
			next := pollutionUnwrap(pollutionArg(args, t))
			if next == nil || next.Kind() != "subscript_expression" || pollutionIdentifier(next.ChildByFieldName("object"), m.src) != object.name {
				continue
			}
			key := unwrapTS(next.ChildByFieldName("index"))
			p := pollutionPathPart(m, call, key, params)
			if p < 0 || p == t || !pollutionPathPassedOn(m, pollutionArg(args, p), params[p].name) {
				continue
			}
			keyText := compactPollutionText(key, m.src)
			sites := s.pollutionSlotWrites(m, body, object.name, keyText)
			if len(sites) == 0 {
				continue
			}
			// The parts of a caller's array are untyped, so a comparison counts only after a type test.
			guard := pollutionPartitionGuard(m, body, keyText, object.name, pollutionStringChecked(m, body, keyText, object.name, call), call)
			if unread := pollutionUnreadKeyCalls(m, body, call, key); len(unread) > 0 {
				guard.unknown = true
				if guard.kind == "" {
					guard.kind = "unknown"
				}
				guard.evidence = append(guard.evidence, unread...)
			}
			writes = append(writes, pollutionWrite{operation: analysis.PollutionWalk, operand: "path", source: p, target: t, sites: sites, guard: guard, untyped: true})
		}
	})
	return writes
}

// pollutionPathPart returns the parameter that `key` is one part of: key is
// `path[0]` or `path[index]`, written in place or held in an unchanged local.
func pollutionPathPart(m *sourceModule, at, key *sitter.Node, params []boundParam) int {
	if key == nil {
		return -1
	}
	if key.Kind() == "identifier" {
		name := key.Utf8Text(m.src)
		if pollutionParameter(params, name) >= 0 {
			return -1
		}
		key = unwrapTS(localInitializer(m, at, name))
	}
	if key == nil || key.Kind() != "subscript_expression" {
		return -1
	}
	index := unwrapTS(key.ChildByFieldName("index"))
	if index == nil || index.Kind() != "identifier" && index.Kind() != "number" {
		return -1
	}
	return pollutionParameter(params, pollutionIdentifier(key.ChildByFieldName("object"), m.src))
}

// The recursion hands the path on unchanged or without its first part.
func pollutionPathPassedOn(m *sourceModule, arg *sitter.Node, path string) bool {
	arg = pollutionUnwrap(arg)
	if arg == nil {
		return false
	}
	text := compactPollutionText(arg, m.src)
	return text == path || text == path+".slice(1)"
}

// pollutionSlotWrites lists the assignments to object[key] in the body, and the
// calls to a helper that makes that assignment from its parameters.
func (s *moduleSet) pollutionSlotWrites(m *sourceModule, body *sitter.Node, object, key string) []*sitter.Node {
	var sites []*sitter.Node
	pollutionWalk(body, func(n *sitter.Node) {
		switch n.Kind() {
		case "assignment_expression":
			left := unwrapTS(n.ChildByFieldName("left"))
			if left != nil && left.Kind() == "subscript_expression" && pollutionIdentifier(left.ChildByFieldName("object"), m.src) == object &&
				compactPollutionText(unwrapTS(left.ChildByFieldName("index")), m.src) == key {
				sites = append(sites, n)
			}
		case "call_expression":
			owner, helper := s.resolveCall(m, n)
			if helper == nil || pollutionBindingWritten(m, n.ChildByFieldName("function")) {
				return
			}
			helperParams, ok := functionParameters(helper, owner.src)
			args := n.ChildByFieldName("arguments")
			if !ok {
				return
			}
			o, k := -1, -1
			for i := range helperParams {
				switch compactPollutionText(pollutionUnwrap(pollutionArg(args, i)), m.src) {
				case object:
					o = i
				case key:
					k = i
				}
			}
			if o < 0 || k < 0 {
				return
			}
			pollutionWalk(helper.ChildByFieldName("body"), func(w *sitter.Node) {
				if w.Kind() == "assignment_expression" && pollutionSubscript(w.ChildByFieldName("left"), helperParams[o].name, helperParams[k].name, owner.src) &&
					!slices.ContainsFunc(sites, func(prior *sitter.Node) bool { return prior.Id() == n.Id() }) {
					sites = append(sites, n)
				}
			})
		}
	})
	return sites
}

// pollutionUnreadKeyCalls lists the calls before the recursion that take the
// key, such as an assertion. What such a call accepts is not read.
func pollutionUnreadKeyCalls(m *sourceModule, body, recursion, key *sitter.Node) []analysis.Evidence {
	if key == nil || key.Kind() != "identifier" {
		return nil
	}
	name := key.Utf8Text(m.src)
	var unread []analysis.Evidence
	pollutionWalk(body, func(n *sitter.Node) {
		if n.Kind() != "call_expression" || n.EndByte() > recursion.StartByte() {
			return
		}
		if args := n.ChildByFieldName("arguments"); args != nil && pollutionMentions(args, name, m.src) {
			if p := n.Parent(); p == nil || p.Kind() == "expression_statement" {
				unread = append(unread, m.evidence("key_guard", n))
			}
		}
	})
	return unread
}
