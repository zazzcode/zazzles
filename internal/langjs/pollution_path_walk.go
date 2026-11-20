package langjs

import (
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
)

func pollutionPathLoop(m *sourceModule, body, loop *sitter.Node, params []boundParam) []pollutionWrite {
	loopBody := loop.ChildByFieldName("body")
	if loopBody == nil || loopBody.Kind() != "statement_block" {
		return nil
	}
	var writes []pollutionWrite
	pollutionWalk(loopBody, func(n *sitter.Node) {
		if n.Kind() != "assignment_expression" {
			return
		}
		cursor := pollutionIdentifier(n.ChildByFieldName("left"), m.src)
		lookup := unwrapTS(n.ChildByFieldName("right"))
		if cursor == "" || lookup == nil || lookup.Kind() != "subscript_expression" || pollutionIdentifier(lookup.ChildByFieldName("object"), m.src) != cursor {
			return
		}
		part := lookup.ChildByFieldName("index")
		parts, key := pollutionPathParts(m, loop, part)
		if parts == "" {
			return
		}
		source := pollutionSplitSource(m, loop, parts, params)
		target := pollutionParameter(params, cursor)
		if target < 0 {
			target = pollutionParameter(params, pollutionIdentifier(localInitializer(m, loop, cursor), m.src))
		}
		if source < 0 || target < 0 || target == source {
			return
		}
		final := pollutionPathFinal(m, body, loop, cursor, key, parts)
		if final != nil {
			guard := pollutionPartitionGuard(m, loopBody, key, cursor, true, n)
			writes = append(writes, pollutionWrite{operation: analysis.PollutionWalk, operand: "path", source: source, target: target, sites: []*sitter.Node{final}, guard: guard})
		}
	})
	return writes
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

func pollutionSplitSource(m *sourceModule, loop *sitter.Node, parts string, params []boundParam) int {
	split := unwrapTS(localInitializer(m, loop, parts))
	if split == nil || split.Kind() != "call_expression" || split.EndByte() > loop.StartByte() || bindingReassigned(m, parts) {
		return -1
	}
	fn, args := split.ChildByFieldName("function"), split.ChildByFieldName("arguments")
	if fn == nil || fn.Kind() != "member_expression" || args == nil || args.NamedChildCount() != 1 {
		return -1
	}
	prop := fn.ChildByFieldName("property")
	sep, literal := stringLiteral(args.NamedChild(0), m.src)
	if prop == nil || prop.Utf8Text(m.src) != "split" || !literal || sep == "" {
		return -1
	}
	return pollutionParameter(params, pollutionIdentifier(fn.ChildByFieldName("object"), m.src))
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
		if index.Kind() == "identifier" {
			index = localInitializer(m, index, index.Utf8Text(m.src))
		}
		if text := compactPollutionText(index, m.src); text == parts+"["+parts+".length-1]" || text == parts+".pop()" {
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
