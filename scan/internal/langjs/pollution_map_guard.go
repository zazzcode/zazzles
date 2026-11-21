package langjs

import (
	"slices"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

// A Map tests exact membership. Only an untouched literal key set proves
// which keys it excludes; keys loaded at runtime still need review.
func (s *moduleSet) pollutionMapGuard(m *sourceModule, cond *sitter.Node, names []string, holds bool, operand *sitter.Node) (pollutionGuard, bool) {
	n := pollutionUnwrap(cond)
	if n == nil {
		return pollutionGuard{}, false
	}
	if n.Kind() == "unary_expression" {
		if op := n.ChildByFieldName("operator"); op != nil && op.Kind() == "!" {
			holds = !holds
			n = pollutionUnwrap(n.ChildByFieldName("argument"))
		}
	}
	receiver, key := pollutionMapCall(m, n, "has")
	direct := holds && receiver != nil && slices.Contains(names, compactPollutionText(key, m.src))
	owner := m
	if !direct {
		call := pollutionMapResultCall(m, n, holds)
		if call == nil || !pollutionOperandCall(m, call, names) || pollutionBindingWritten(m, call.ChildByFieldName("function")) {
			return pollutionGuard{}, false
		}
		owner, receiver = s.pollutionMapLookupHelper(m, call)
	}
	if receiver == nil {
		return pollutionGuard{}, false
	}
	binding, init := pollutionStartBinding(owner, receiver)
	if binding == nil || init == nil || !pollutionMapMethodsStable(owner, receiver, binding) {
		return pollutionGuard{}, false
	}
	mapOwner, allocation := s.pollutionMapAllocation(owner, init)
	if allocation == nil {
		return pollutionGuard{}, false
	}
	g := pollutionGuard{kind: "map_membership", unknown: true,
		evidence: []analysis.Evidence{m.evidence("key_guard", cond), mapOwner.evidence("key_guard", allocation)}}
	if direct && sameNode(init, allocation) && operand != nil &&
		compactPollutionText(pollutionUnwrap(operand), m.src) == compactPollutionText(key, m.src) &&
		sameNode(enclosingFunction(cond), enclosingFunction(operand)) &&
		isConstDeclaration(m, binding) && pollutionReadOnlyCollection(m, binding.ChildByFieldName("name"), "has", "get") {
		base, path := pollutionStartPath(key, m.src)
		use, _ := pollutionStartPath(operand, m.src)
		if base != nil && use != nil && pollutionMapClosedKeys(m, allocation) {
			decl, _ := pollutionStartBinding(m, base)
			usedDecl, _ := pollutionStartBinding(m, use)
			if decl != nil && sameNode(decl, usedDecl) && pollutionStartStableBetween(m, base, path, decl, cond.EndByte(), operand.StartByte()) {
				g.blocked, g.unknown = allPrototypeKeys(), false
			}
		}
	}
	return g, true
}

func pollutionMapCall(m *sourceModule, call *sitter.Node, method string) (receiver, key *sitter.Node) {
	call = pollutionUnwrap(call)
	if call == nil || call.Kind() != "call_expression" {
		return nil, nil
	}
	fn, args := call.ChildByFieldName("function"), call.ChildByFieldName("arguments")
	if fn == nil || fn.Kind() != "member_expression" || fn.ChildByFieldName("optional_chain") != nil ||
		compactPollutionText(fn.ChildByFieldName("property"), m.src) != method || args == nil || args.NamedChildCount() != 1 {
		return nil, nil
	}
	receiver = pollutionUnwrap(fn.ChildByFieldName("object"))
	if pollutionIdentifier(receiver, m.src) == "" {
		return nil, nil
	}
	return receiver, pollutionUnwrap(args.NamedChild(0))
}

// Match a rejected null result, either initialized in the declaration or
// assigned once before the test, for example inside a try block.
func pollutionMapResultCall(m *sourceModule, test *sitter.Node, holds bool) *sitter.Node {
	if test == nil || test.Kind() != "binary_expression" {
		return nil
	}
	op := compactPollutionText(test.ChildByFieldName("operator"), m.src)
	if !(holds && (op == "!=" || op == "!==") || !holds && (op == "==" || op == "===")) {
		return nil
	}
	ref := pollutionUnwrap(test.ChildByFieldName("left"))
	if compactPollutionText(test.ChildByFieldName("right"), m.src) != "null" || pollutionIdentifier(ref, m.src) == "" {
		return nil
	}
	init := localInitializer(m, ref, ref.Utf8Text(m.src))
	if init == nil {
		fn := enclosingFunction(test)
		if fn == nil {
			return nil
		}
		var assignments int
		pollutionWalk(fn.ChildByFieldName("body"), func(n *sitter.Node) {
			if n.Kind() == "assignment_expression" && n.EndByte() < test.StartByte() &&
				pollutionIdentifier(n.ChildByFieldName("left"), m.src) == ref.Utf8Text(m.src) {
				assignments++
				init = n.ChildByFieldName("right")
			}
		})
		if assignments != 1 {
			return nil
		}
	}
	return pollutionUnawait(init)
}

// Read a forwarding lookup: if (map.has(key)) return map.get(key) ?? null;
// return null. Both calls must use the same receiver and parameter.
func (s *moduleSet) pollutionMapLookupHelper(m *sourceModule, call *sitter.Node) (*sourceModule, *sitter.Node) {
	owner, fn := s.resolveCall(m, call)
	if fn == nil {
		return nil, nil
	}
	params, ok := functionParameters(fn, owner.src)
	body := fn.ChildByFieldName("body")
	if !ok || len(params) != 1 || body == nil || body.Kind() != "statement_block" || body.NamedChildCount() != 3 {
		return nil, nil
	}
	test, absent := body.NamedChild(1), pollutionReturnValue(body.NamedChild(2))
	if test.Kind() != "if_statement" || test.ChildByFieldName("alternative") != nil || absent == nil || absent.Kind() != "null" {
		return nil, nil
	}
	receiver, key := pollutionMapCall(owner, test.ChildByFieldName("condition"), "has")
	if receiver == nil || pollutionIdentifier(key, owner.src) != params[0].name {
		return nil, nil
	}
	value := pollutionReturnValue(test.ChildByFieldName("consequence"))
	if value != nil && value.Kind() == "binary_expression" && compactPollutionText(value.ChildByFieldName("operator"), owner.src) == "??" &&
		compactPollutionText(value.ChildByFieldName("right"), owner.src) == "null" {
		value = value.ChildByFieldName("left")
	} else {
		return nil, nil
	}
	got, key := pollutionMapCall(owner, value, "get")
	if got == nil || got.Utf8Text(owner.src) != receiver.Utf8Text(owner.src) || pollutionIdentifier(key, owner.src) != params[0].name {
		return nil, nil
	}
	return owner, receiver
}

func pollutionReturnValue(n *sitter.Node) *sitter.Node {
	if n != nil && n.Kind() == "statement_block" && n.NamedChildCount() == 1 {
		n = n.NamedChild(0)
	}
	if n == nil || n.Kind() != "return_statement" || n.NamedChildCount() != 1 {
		return nil
	}
	return pollutionUnwrap(n.NamedChild(0))
}

func pollutionUnawait(n *sitter.Node) *sitter.Node {
	n = pollutionUnwrap(n)
	if n != nil && n.Kind() == "await_expression" && n.NamedChildCount() == 1 {
		return pollutionUnwrap(n.NamedChild(0))
	}
	return n
}

func pollutionNewMap(m *sourceModule, n *sitter.Node) bool {
	return n != nil && n.Kind() == "new_expression" && pollutionIdentifier(n.ChildByFieldName("constructor"), m.src) == "Map" &&
		pollutionBuiltin(m, n, "Map", "prototype.has") && pollutionBuiltin(m, n, "Map", "prototype.get")
}

func pollutionMapMethodsStable(m *sourceModule, ref, binding *sitter.Node) bool {
	for _, method := range []string{"has", "get"} {
		if pollutionStartReassigned(m, ref, binding, []string{method}, nil) {
			return false
		}
	}
	return true
}

// Also recognize a getter of a lazily allocated Map. The getter must return
// the same binding on every return, and every assignment to it must be a Map.
func (s *moduleSet) pollutionMapAllocation(m *sourceModule, init *sitter.Node) (*sourceModule, *sitter.Node) {
	init = pollutionUnawait(init)
	if pollutionNewMap(m, init) {
		return m, init
	}
	if init == nil || init.Kind() != "call_expression" || pollutionBindingWritten(m, init.ChildByFieldName("function")) {
		return nil, nil
	}
	owner, fn := s.resolveCall(m, init)
	if fn == nil {
		return nil, nil
	}
	body := fn.ChildByFieldName("body")
	if body == nil || body.Kind() != "statement_block" || body.NamedChildCount() == 0 {
		return nil, nil
	}
	ref := pollutionReturnValue(body.NamedChild(body.NamedChildCount() - 1))
	name := pollutionIdentifier(ref, owner.src)
	if name == "" {
		return nil, nil
	}
	binding, initial := pollutionStartBinding(owner, ref)
	if binding == nil || initial == nil || initial.Kind() != "null" {
		return nil, nil
	}
	valid := true
	pollutionWalk(body, func(n *sitter.Node) {
		if n.Kind() == "return_statement" && pollutionIdentifier(pollutionReturnValue(n), owner.src) != name {
			valid = false
		}
	})
	var allocation *sitter.Node
	for _, target := range owner.bindingWrites().targets {
		if pollutionReplacesStart(owner, target, name, binding, nil) {
			write := target.Parent()
			value := pollutionUnwrap(write.ChildByFieldName("right"))
			if write.Kind() != "assignment_expression" || !pollutionNewMap(owner, value) {
				return nil, nil
			}
			allocation = value
		} else if pollutionReplacesStart(owner, target, name, binding, []string{"has"}) ||
			pollutionReplacesStart(owner, target, name, binding, []string{"get"}) {
			return nil, nil
		}
	}
	if !valid {
		return nil, nil
	}
	return owner, allocation
}

func pollutionMapClosedKeys(m *sourceModule, allocation *sitter.Node) bool {
	args := allocation.ChildByFieldName("arguments")
	if args == nil || args.NamedChildCount() == 0 {
		return true
	}
	list := pollutionUnwrap(args.NamedChild(0))
	if args.NamedChildCount() != 1 || list == nil || list.Kind() != "array" {
		return false
	}
	for i := uint(0); i < list.NamedChildCount(); i++ {
		entry := pollutionUnwrap(list.NamedChild(i))
		if entry.Kind() != "array" || entry.NamedChildCount() != 2 {
			return false
		}
		key, ok := stringLiteral(pollutionUnwrap(entry.NamedChild(0)), m.src)
		if !ok || strings.ContainsRune(key, '\\') || slices.Contains(allPrototypeKeys(), key) {
			return false
		}
	}
	return true
}
