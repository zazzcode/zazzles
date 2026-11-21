package langjs

import (
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
)

// pollutionWalkStart finds the declaration and initializer behind a walk start.
// A fixed member chain retains its full path for deduplication and uses the
// root declaration as evidence.
func pollutionWalkStart(m *sourceModule, at, start *sitter.Node) (decl, init *sitter.Node, path string) {
	base, members := pollutionStartPath(start, m.src)
	if base == nil {
		return nil, nil, ""
	}
	decl, init = pollutionStartBinding(m, base)
	if decl == nil || init != nil && init.EndByte() > at.StartByte() && sameNode(enclosingFunction(init), enclosingFunction(at)) ||
		pollutionStartReassigned(m, base, decl, members, nil) {
		return nil, nil, ""
	}
	for _, member := range members {
		init = pollutionPropertyInit(init, member, m.src)
	}
	return decl, pollutionUnwrap(init), strings.Join(append([]string{base.Utf8Text(m.src)}, members...), "\x00")
}

func pollutionStartBinding(m *sourceModule, ref *sitter.Node) (decl, init *sitter.Node) {
	name := ref.Utf8Text(m.src)
	init = localInitializer(m, ref, name)
	for fn := enclosingFunction(ref); fn != nil; fn = enclosingFunction(fn) {
		if init != nil && sameNode(enclosingFunction(init), fn) {
			break
		}
		params, _ := functionParameters(fn, m.src)
		if i := pollutionParameter(params, name); i >= 0 {
			return params[i].node, nil
		}
	}
	if init != nil && init.Parent().Kind() == "variable_declarator" {
		return init.Parent(), init
	}
	if imp, ok := m.imports[name]; ok && !m.cachedShadowed(ref, name) {
		return imp.declaration, nil
	}
	return nil, nil
}

// A loop cursor can change at its recognized step. Any other change along
// the walk makes the final receiver ambiguous.
func pollutionCursorStable(m *sourceModule, walk, step, final *sitter.Node) bool {
	left := unwrapTS(step.ChildByFieldName("left"))
	decl, init := pollutionStartBinding(m, left)
	if decl == nil {
		return false
	}
	receiver := unwrapTS(final.ChildByFieldName("left").ChildByFieldName("object"))
	finalDecl, _ := pollutionStartBinding(m, receiver)
	if !sameNode(decl, finalDecl) {
		return false
	}
	// The cursor declaration must be visible where traversal starts, too.
	if init != nil && (init.EndByte() > walk.StartByte() || !sameNode(enclosingFunction(init), enclosingFunction(walk))) {
		return false
	}
	last := max(walk.EndByte(), final.EndByte())
	for _, target := range m.bindingWrites().targets {
		if !sameNode(target, left) && target.StartByte() >= decl.EndByte() && target.StartByte() < last &&
			pollutionReplacesStart(m, target, left.Utf8Text(m.src), decl, nil) {
			return false
		}
	}
	return true
}

func pollutionStartStableBetween(m *sourceModule, base *sitter.Node, path []string, decl *sitter.Node, from, to uint) bool {
	for _, target := range m.bindingWrites().targets {
		if target.StartByte() >= from && target.StartByte() < to && pollutionReplacesStart(m, target, base.Utf8Text(m.src), decl, path) {
			return false
		}
	}
	return true
}

// pollutionStartPath separates a binding from its fixed property names.
func pollutionStartPath(n *sitter.Node, src []byte) (*sitter.Node, []string) {
	n = pollutionUnwrap(n)
	if n == nil {
		return nil, nil
	}
	if n.Kind() == "identifier" {
		return n, nil
	}
	if n.ChildByFieldName("optional_chain") != nil {
		return nil, nil
	}
	var member string
	switch n.Kind() {
	case "member_expression":
		p := n.ChildByFieldName("property")
		if p == nil || p.Kind() != "property_identifier" {
			return nil, nil
		}
		member = p.Utf8Text(src)
	case "subscript_expression":
		var ok bool
		member, ok = stringLiteral(pollutionUnwrap(n.ChildByFieldName("index")), src)
		if !ok || strings.ContainsRune(member, '\\') {
			return nil, nil
		}
	default:
		return nil, nil
	}
	base, prefix := pollutionStartPath(n.ChildByFieldName("object"), src)
	return base, append(prefix, member)
}

// Only an explicit field value in an object literal proves a property's initializer.
func pollutionPropertyInit(init *sitter.Node, member string, src []byte) *sitter.Node {
	init = pollutionUnwrap(init)
	if init == nil || init.Kind() != "object" {
		return nil
	}
	for i := init.NamedChildCount(); i > 0; i-- {
		item := init.NamedChild(i - 1)
		if item.Kind() == "comment" {
			continue
		}
		if item.Kind() != "pair" {
			return nil
		}
		key := item.ChildByFieldName("key")
		if key == nil || key.Kind() == "computed_property_name" {
			return nil
		}
		name, quoted := stringLiteral(key, src)
		if !quoted {
			name = key.Utf8Text(src)
		}
		if name == member {
			return item.ChildByFieldName("value")
		}
	}
	return nil
}

// Check module-wide writes to the binding or any prefix of its member chain.
// A dynamic property assignment can replace any member at that level.
func pollutionStartReassigned(m *sourceModule, base, decl *sitter.Node, path []string, stepTarget *sitter.Node) bool {
	name := base.Utf8Text(m.src)
	for _, target := range m.bindingWrites().targets {
		if !sameNode(target, stepTarget) && pollutionReplacesStart(m, target, name, decl, path) {
			return true
		}
	}
	return false
}

func pollutionReplacesStart(m *sourceModule, target *sitter.Node, name string, decl *sitter.Node, path []string) bool {
	target = pollutionUnwrap(target)
	if target == nil {
		return false
	}
	matches := func(ref *sitter.Node) bool {
		if ref == nil || ref.Utf8Text(m.src) != name {
			return false
		}
		binding, _ := pollutionStartBinding(m, ref)
		return sameNode(binding, decl)
	}
	switch target.Kind() {
	case "identifier", "shorthand_property_identifier_pattern":
		return matches(target)
	case "member_expression", "subscript_expression":
		var chain []*sitter.Node
		for target != nil && (target.Kind() == "member_expression" || target.Kind() == "subscript_expression") {
			chain = append(chain, target)
			target = pollutionUnwrap(target.ChildByFieldName("object"))
		}
		if len(chain) > len(path) || target == nil || target.Kind() != "identifier" || !matches(target) {
			return false
		}
		for i := range chain {
			n := chain[len(chain)-1-i]
			if n.Kind() == "member_expression" {
				if compactPollutionText(n.ChildByFieldName("property"), m.src) != path[i] {
					return false
				}
			} else if index, ok := stringLiteral(pollutionUnwrap(n.ChildByFieldName("index")), m.src); ok && !strings.ContainsRune(index, '\\') && index != path[i] {
				return false
			}
		}
		return true
	case "assignment_pattern":
		return pollutionReplacesStart(m, target.ChildByFieldName("left"), name, decl, path)
	case "pair_pattern":
		return pollutionReplacesStart(m, target.ChildByFieldName("value"), name, decl, path)
	case "array_pattern", "object_pattern", "rest_pattern":
		for i := uint(0); i < target.NamedChildCount(); i++ {
			if pollutionReplacesStart(m, target.NamedChild(i), name, decl, path) {
				return true
			}
		}
	}
	return false
}
