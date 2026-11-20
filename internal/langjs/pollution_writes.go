package langjs

import (
	"slices"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/parse"
)

func (f *flow) pollutionAssignment(site, lhs *sitter.Node) {
	if f.client != nil || f.pollutionRead || f.set == nil || lhs == nil || lhs.Kind() != "subscript_expression" {
		return
	}
	lookup := unwrapTS(lhs.ChildByFieldName("object"))
	if lookup == nil || lookup.Kind() != "subscript_expression" {
		return
	}
	key, target := lookup.ChildByFieldName("index"), unwrapTS(lookup.ChildByFieldName("object"))
	if key == nil || target == nil || target.Kind() == "subscript_expression" || pollutionLiteral(key) || f.pollutionLookupWritten(lookup) {
		return
	}
	// A computed lhs is not otherwise evaluated as a new value by the shared
	// flow. Evaluate it in isolation so observing its key changes no other claim.
	probe := *f
	probe.pollutionRead = true
	probe.env = copyValues(f.env)
	probe.facts, probe.helpers, probe.conditions = nil, nil, nil
	probe.context, probe.gaps, probe.uses, probe.returns, probe.heapWrites = nil, nil, nil, nil, nil
	v := probe.eval(key)
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
	f.recordPollution(site, 0, []pollutionOperand{{key, v}}, facts, []analysis.Evidence{f.module.evidence("sink_binding", lhs)}, guard)
}

// The direct-write rule has no heap model for a receiver slot reassigned on an
// earlier branch. Its current identity must come from an unchanged lookup.
func (f *flow) pollutionLookupWritten(lookup *sitter.Node) bool {
	for _, g := range f.gaps {
		if g.Kind != "unsupported_write" || g.At.File != f.module.file || g.At.EndByte > int(lookup.StartByte()) {
			continue
		}
		n := parse.NodeAt(f.module.tree.RootNode(), g.At.StartByte, g.At.EndByte)
		if n != nil {
			left := n.ChildByFieldName("left")
			if left != nil && compactPollutionText(left, f.module.src) == compactPollutionText(lookup, f.module.src) {
				return true
			}
		}
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
	if !ok || len(params) < 2 || body == nil || body.Kind() != "statement_block" {
		return nil
	}
	var writes []pollutionWrite
	collect := func(w pollutionWrite) {
		for i := range writes {
			prior := &writes[i]
			if prior.operation != w.operation || prior.source != w.source || prior.target != w.target {
				continue
			}
			prior.guard = intersectPollutionGuards(prior.guard, w.guard)
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
		}
		if n.Kind() == "for_statement" || n.Kind() == "for_in_statement" {
			for _, w := range pollutionPathLoop(m, body, n, params) {
				collect(w)
			}
		}
	})
	s.pollutionWrites[callee.Id()] = writes
	return writes
}

type pollutionLoop struct {
	body        *sitter.Node
	source, key string
	value       string
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
			return pollutionObjectKeyLoop(m, rhs, lhs, n.ChildByFieldName("body"))
		}
	}
	if n.Kind() != "call_expression" {
		return pollutionLoop{}
	}
	fn, args := n.ChildByFieldName("function"), n.ChildByFieldName("arguments")
	if fn == nil || fn.Kind() != "member_expression" || args == nil || args.NamedChildCount() != 1 {
		return pollutionLoop{}
	}
	prop := fn.ChildByFieldName("property")
	callback := args.NamedChild(0)
	if prop == nil || prop.Utf8Text(src) != "forEach" || !isFunction(callback) {
		return pollutionLoop{}
	}
	parameter := callback.ChildByFieldName("parameter")
	if list := callback.ChildByFieldName("parameters"); list != nil && list.NamedChildCount() == 1 {
		parameter = list.NamedChild(0)
	}
	return pollutionObjectKeyLoop(m, fn.ChildByFieldName("object"), parameter, callback.ChildByFieldName("body"))
}

func pollutionObjectKeyLoop(m *sourceModule, iter, key, body *sitter.Node) pollutionLoop {
	if iter == nil || iter.Kind() != "call_expression" || key == nil || body == nil {
		return pollutionLoop{}
	}
	fn, args := iter.ChildByFieldName("function"), iter.ChildByFieldName("arguments")
	if fn == nil || args == nil || args.NamedChildCount() != 1 || args.NamedChild(0).Kind() != "identifier" {
		return pollutionLoop{}
	}
	result := pollutionLoop{source: args.NamedChild(0).Utf8Text(m.src), body: body}
	switch fn.Utf8Text(m.src) {
	case "Object.keys":
		if !pollutionBuiltin(m, iter, "Object", "keys") {
			return pollutionLoop{}
		}
		result.key = pollutionIdentifier(key, m.src)
	case "Object.entries":
		if !pollutionBuiltin(m, iter, "Object", "entries") {
			return pollutionLoop{}
		}
		if key.Kind() == "array_pattern" && key.NamedChildCount() == 2 {
			result.key = pollutionIdentifier(key.NamedChild(0), m.src)
			result.value = pollutionIdentifier(key.NamedChild(1), m.src)
		}
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
	pollutionWalk(loop.body, func(n *sitter.Node) {
		switch n.Kind() {
		case "assignment_expression":
			lhs := n.ChildByFieldName("left")
			for i, p := range params {
				if i != source && pollutionSubscript(lhs, p.name, loop.key, m.src) {
					sites[i].assignments = append(sites[i].assignments, n)
				}
			}
		case "call_expression":
			args := n.ChildByFieldName("arguments")
			for i, p := range params {
				if i != source && pollutionRecursiveOperands(args, i, source, p.name, loop, m.src) &&
					s.pollutionRecurses(m, callee, n, i, source) {
					sites[i].recursions = append(sites[i].recursions, n)
				}
			}
		}
	})
	var writes []pollutionWrite
	for i, pair := range sites {
		if len(pair.assignments) > 0 && len(pair.recursions) > 0 {
			guard := pollutionPartitionGuard(m, loop.body, loop.key, params[i].name, true, pair.recursions[0])
			for _, call := range pair.recursions[1:] {
				guard = intersectPollutionGuards(guard, pollutionPartitionGuard(m, loop.body, loop.key, params[i].name, true, call))
			}
			writes = append(writes, pollutionWrite{operation: analysis.PollutionMerge, operand: "source", source: source, target: i, sites: pair.assignments, guard: guard})
		}
	}
	return writes
}

func pollutionRecursiveOperands(args *sitter.Node, targetAt, sourceAt int, target string, loop pollutionLoop, src []byte) bool {
	t, s := pollutionArg(args, targetAt), pollutionArg(args, sourceAt)
	return pollutionSubscript(t, target, loop.key, src) &&
		(pollutionSubscript(s, loop.source, loop.key, src) || loop.value != "" && pollutionIdentifier(s, src) == loop.value)
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
