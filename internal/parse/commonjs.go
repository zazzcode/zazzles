package parse

import (
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
)

// requireBinding recognizes only the unshadowed CommonJS loader with a literal
// module argument. No source is executed to discover imports or exports.
func requireBinding(m *sourceModule, n *sitter.Node) (string, string, bool) {
	member := "*"
	if n != nil && n.Kind() == "member_expression" {
		p := n.ChildByFieldName("property")
		if p == nil {
			return "", "", false
		}
		member = p.Utf8Text(m.src)
		n = n.ChildByFieldName("object")
	}
	if n == nil || n.Kind() != "call_expression" || topLevelBinding(m, "require") {
		return "", "", false
	}
	fn, args := n.ChildByFieldName("function"), n.ChildByFieldName("arguments")
	if fn == nil || fn.Utf8Text(m.src) != "require" || args == nil || args.NamedChildCount() != 1 {
		return "", "", false
	}
	path, ok := stringLiteral(args.NamedChild(0), m.src)
	return path, member, ok
}

func (m *sourceModule) readRequire(name string, v, declaration *sitter.Node) {
	path, member, ok := requireBinding(m, v)
	if !ok || bindingReassigned(m, name) {
		return
	}
	m.imports[name] = importBinding{path, member, declaration}
	if path == "express" && (member == "*" || member == "Router") {
		m.express[name] = true
	}
}

// readRequireDestructuring records `const { createLogger, Sequelize: S } = require('mod')`
// into imports the same way ESM named imports do. Specialized child_process/fs maps stay
// on readCommandDestructuring / readFSDestructuring.
func (m *sourceModule) readRequireDestructuring(pattern, v, declaration *sitter.Node) {
	path, member, ok := requireBinding(m, v)
	if !ok || member != "*" {
		return
	}
	for i := uint(0); i < pattern.NamedChildCount(); i++ {
		c := pattern.NamedChild(i)
		local, name := "", ""
		switch c.Kind() {
		case "shorthand_property_identifier_pattern":
			local = c.Utf8Text(m.src)
			name = local
		case "pair_pattern":
			key, value := c.ChildByFieldName("key"), c.ChildByFieldName("value")
			if key != nil && value != nil && value.Kind() == "identifier" {
				local, name = value.Utf8Text(m.src), key.Utf8Text(m.src)
			}
		}
		if local != "" && !bindingReassigned(m, local) {
			m.imports[local] = importBinding{path, name, declaration}
		}
	}
}

func (m *sourceModule) readCommonJSExport(n *sitter.Node) {
	if n.Kind() != "expression_statement" || n.NamedChildCount() != 1 {
		return
	}
	a := n.NamedChild(0)
	if a.Kind() != "assignment_expression" {
		return
	}
	left, right := a.ChildByFieldName("left"), a.ChildByFieldName("right")
	if left == nil || right == nil {
		return
	}
	name := left.Utf8Text(m.src)
	key := ""
	switch {
	case strings.HasPrefix(name, "exports.") && !topLevelBinding(m, "exports"):
		key = strings.TrimPrefix(name, "exports.")
	case strings.HasPrefix(name, "module.exports.") && !topLevelBinding(m, "module"):
		key = strings.TrimPrefix(name, "module.exports.")
	case name == "module.exports" && !topLevelBinding(m, "module"):
		key = "default"
	}
	if key == "" {
		return
	}
	delete(m.exports, key)
	if key == "default" {
		m.exports = map[string]*sitter.Node{}
	}
	if isFunction(right) || right.Kind() == "object" {
		m.exports[key] = right
	} else if right.Kind() == "identifier" {
		root := m.tree.RootNode()
		for i := uint(0); i < root.NamedChildCount(); i++ {
			candidate := root.NamedChild(i)
			id := candidate.ChildByFieldName("name")
			if candidate.Kind() == "function_declaration" && id != nil && id.Utf8Text(m.src) == right.Utf8Text(m.src) {
				m.exports[key] = candidate
			}
		}
	}
}

func topLevelBinding(m *sourceModule, name string) bool {
	if _, ok := m.imports[name]; ok {
		return true
	}
	if topVariable(m, name) != nil {
		return true
	}
	root := m.tree.RootNode()
	for i := uint(0); i < root.NamedChildCount(); i++ {
		n := root.NamedChild(i)
		if id := n.ChildByFieldName("name"); n.Kind() == "function_declaration" && id != nil && id.Utf8Text(m.src) == name {
			return true
		}
	}
	return false
}

func bindingReassigned(m *sourceModule, name string) bool {
	return m.bindingWrites().assigned[name]
}

// readDefaultDestructuring records `const { endpoint } = http` where `http` is a
// default import (ESM interop with a CommonJS `module.exports = { ... }`). The
// binding resolves only through that module's exported object, never through a
// same-named ESM export.
func (m *sourceModule) readDefaultDestructuring(pattern, v, declaration *sitter.Node) {
	if v.Kind() != "identifier" {
		return
	}
	imp, ok := m.imports[v.Utf8Text(m.src)]
	if !ok || imp.name != "default" || bindingReassigned(m, v.Utf8Text(m.src)) {
		return
	}
	for i := uint(0); i < pattern.NamedChildCount(); i++ {
		c := pattern.NamedChild(i)
		local, name := "", ""
		switch c.Kind() {
		case "shorthand_property_identifier_pattern":
			local = c.Utf8Text(m.src)
			name = local
		case "pair_pattern":
			key, value := c.ChildByFieldName("key"), c.ChildByFieldName("value")
			if key != nil && value != nil && value.Kind() == "identifier" {
				local, name = value.Utf8Text(m.src), key.Utf8Text(m.src)
			}
		}
		if local != "" && !bindingReassigned(m, local) {
			m.imports[local] = importBinding{imp.module, "default." + name, declaration}
		}
	}
}

// exportedMember resolves a property of a module's exported object literal
// (`module.exports = { endpoint }` or `export default { endpoint }`) to its
// function: an inline function, or a top-level function or const function the
// shorthand or identifier names.
func exportedMember(target *sourceModule, key string) *sitter.Node {
	obj := target.exports["default"]
	if obj == nil || obj.Kind() != "object" {
		return nil
	}
	v := property(obj, key, target.src)
	if v == nil {
		return nil
	}
	if isFunction(v) {
		return v
	}
	if v.Kind() == "shorthand_property_identifier" || v.Kind() == "identifier" {
		if fn := target.funcs[v.Utf8Text(target.src)]; fn != nil {
			return fn
		}
	}
	return nil
}
