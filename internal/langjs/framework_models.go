package langjs

import (
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
)

func property(n *sitter.Node, key string, src []byte) *sitter.Node {
	if n == nil {
		return nil
	}
	for i := uint(0); i < n.NamedChildCount(); i++ {
		p := n.NamedChild(i)
		k := p.ChildByFieldName("key")
		if k != nil && k.Utf8Text(src) == key {
			return p.ChildByFieldName("value")
		}
		if p.Kind() == "shorthand_property_identifier" && p.Utf8Text(src) == key {
			return p
		}
	}
	return nil
}

func variable(m *sourceModule, name string) *sitter.Node {
	var found *sitter.Node
	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		if found != nil {
			return
		}
		if n.Kind() == "variable_declarator" {
			id := n.ChildByFieldName("name")
			if id != nil && id.Kind() == "identifier" && id.Utf8Text(m.src) == name {
				found = n.ChildByFieldName("value")
				return
			}
		}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			visit(n.NamedChild(i))
		}
	}
	visit(m.tree.RootNode())
	return found
}

func sequelizeBinding(m *sourceModule, name string, depth int) []analysis.Evidence {
	if depth > 3 {
		return nil
	}
	v := topVariable(m, name)
	if v == nil {
		return nil
	}
	var ctor *sitter.Node
	if v.Kind() == "new_expression" {
		ctor = v
	}
	if v.Kind() == "call_expression" {
		fn := v.ChildByFieldName("function")
		if fn != nil {
			factory := m.funcs[fn.Utf8Text(m.src)]
			if factory != nil {
				body := factory.ChildByFieldName("body")
				if body != nil {
					for i := uint(0); i < body.NamedChildCount(); i++ {
						statement := body.NamedChild(i)
						if statement.Kind() == "return_statement" && statement.NamedChildCount() == 1 && statement.NamedChild(0).Kind() == "new_expression" {
							if ctor != nil {
								return nil
							}
							ctor = statement.NamedChild(0)
						}
					}
				}
			}
		}
	}
	if ctor == nil {
		return nil
	}
	id := ctor.ChildByFieldName("constructor")
	if id == nil {
		return nil
	}
	imp, ok := m.imports[id.Utf8Text(m.src)]
	if !ok || imp.module != "sequelize" || imp.name != "Sequelize" {
		return nil
	}
	// Include the provenance actually checked, not just a constructor name that
	// could refer to any local class. Preserve the receiver assignment as well.
	assignment := v
	if p := v.Parent(); p != nil && p.Kind() == "variable_declarator" {
		assignment = p
	}
	out := []analysis.Evidence{m.evidence("sink_binding", imp.declaration), m.evidence("sink_binding", assignment)}
	if ctor.StartByte() != v.StartByte() || ctor.EndByte() != v.EndByte() {
		out = append(out, m.evidence("sink_binding", ctor))
	}
	return out
}

func literalTemplate(n *sitter.Node, m *sourceModule, values map[string]string) (string, bool) {
	if text, ok := stringLiteral(n, m.src); ok {
		return text, true
	}
	if n == nil || n.Kind() != "template_string" {
		return "", false
	}
	var out strings.Builder
	for i := uint(0); i < n.NamedChildCount(); i++ {
		c := n.NamedChild(i)
		switch c.Kind() {
		case "string_fragment":
			out.WriteString(c.Utf8Text(m.src))
		case "template_substitution":
			if c.NamedChildCount() != 1 {
				return "", false
			}
			v, ok := values[c.NamedChild(0).Utf8Text(m.src)]
			if !ok {
				return "", false
			}
			out.WriteString(v)
		default:
			return "", false
		}
	}
	return out.String(), true
}

func (s *moduleSet) persistenceEvidence(m *sourceModule, path string) ([]analysis.Evidence, []analysis.Evidence) {
	if m == nil {
		return nil, nil
	}
	var mapping, models []analysis.Evidence
	walkCalls(m.tree.RootNode(), func(call *sitter.Node) {
		fn := call.ChildByFieldName("function")
		if fn == nil || fn.Kind() != "member_expression" {
			return
		}
		obj := fn.ChildByFieldName("object")
		prop := fn.ChildByFieldName("property")
		if obj == nil || prop == nil || prop.Utf8Text(m.src) != "resource" {
			return
		}
		imp, ok := m.imports[obj.Utf8Text(m.src)]
		if !ok || imp.module != "finale-rest" {
			return
		}
		args := call.ChildByFieldName("arguments")
		if args == nil || args.NamedChildCount() != 1 {
			return
		}
		config := args.NamedChild(0)
		endpoints := property(config, "endpoints", m.src)
		model := property(config, "model", m.src)
		if endpoints == nil || endpoints.Kind() != "array" || endpoints.NamedChildCount() == 0 || model == nil {
			return
		}
		if literal, ok := literalTemplate(endpoints.NamedChild(0), m, nil); ok && literal == path {
			mapping = append(mapping, m.evidence("persistence_mapping", call))
			models = s.modelContext(m, model.Utf8Text(m.src))
			return
		}
		for p := call.Parent(); p != nil; p = p.Parent() {
			if p.Kind() != "for_in_statement" {
				continue
			}
			right := p.ChildByFieldName("right")
			if right == nil {
				return
			}
			table := variable(m, right.Utf8Text(m.src))
			if table == nil || table.Kind() != "array" {
				return
			}
			for i := uint(0); i < table.NamedChildCount(); i++ {
				row := table.NamedChild(i)
				values := map[string]string{}
				for j := uint(0); j < row.NamedChildCount(); j++ {
					pair := row.NamedChild(j)
					key := pair.ChildByFieldName("key")
					v := pair.ChildByFieldName("value")
					if key != nil && v != nil {
						if str, ok := stringLiteral(v, m.src); ok {
							values[key.Utf8Text(m.src)] = str
						}
					}
				}
				literal, ok := literalTemplate(endpoints.NamedChild(0), m, values)
				if !ok || literal != path {
					continue
				}
				ref := property(row, model.Utf8Text(m.src), m.src)
				if ref == nil {
					return
				}
				mapping = append(mapping, m.evidence("persistence_mapping", row), m.evidence("persistence_mapping", p))
				models = s.modelContext(m, ref.Utf8Text(m.src))
				return
			}
			return
		}
	})
	return mapping, models
}

func (s *moduleSet) modelContext(m *sourceModule, name string) []analysis.Evidence {
	imp, ok := m.imports[name]
	if !ok {
		return nil
	}
	target := s.importModule(m, imp.module)
	if target == nil || target.tree.RootNode().HasError() || !exportedName(target, imp.name) {
		return nil
	}
	// Include the entire model declaration: field validators alone omit setters/hooks.
	out := []analysis.Evidence{target.evidence("model_constraints", target.tree.RootNode())}
	s.includeHelpers(target, target.tree.RootNode(), &out, map[string]bool{}, 0)
	return out
}

func topVariable(m *sourceModule, name string) *sitter.Node {
	root := m.tree.RootNode()
	for i := uint(0); i < root.NamedChildCount(); i++ {
		n := root.NamedChild(i)
		if n.Kind() == "export_statement" {
			n = n.ChildByFieldName("declaration")
		}
		if n == nil || (n.Kind() != "lexical_declaration" && n.Kind() != "variable_declaration") {
			continue
		}
		for j := uint(0); j < n.NamedChildCount(); j++ {
			d := n.NamedChild(j)
			id := d.ChildByFieldName("name")
			if id != nil && id.Utf8Text(m.src) == name {
				return d.ChildByFieldName("value")
			}
		}
	}
	return nil
}

func exportedName(m *sourceModule, name string) bool {
	if m.exports[name] != nil {
		return true
	}
	root := m.tree.RootNode()
	for i := uint(0); i < root.NamedChildCount(); i++ {
		n := root.NamedChild(i)
		if n.Kind() != "export_statement" {
			continue
		}
		decl := n.ChildByFieldName("declaration")
		if decl != nil {
			if decl.Kind() == "lexical_declaration" || decl.Kind() == "variable_declaration" {
				for j := uint(0); j < decl.NamedChildCount(); j++ {
					d := decl.NamedChild(j)
					id := d.ChildByFieldName("name")
					if id != nil && id.Utf8Text(m.src) == name {
						return true
					}
				}
			}
			id := decl.ChildByFieldName("name")
			if id != nil && id.Utf8Text(m.src) == name {
				return true
			}
		}
		for j := uint(0); j < n.NamedChildCount(); j++ {
			clause := n.NamedChild(j)
			if clause.Kind() != "export_clause" {
				continue
			}
			for k := uint(0); k < clause.NamedChildCount(); k++ {
				spec := clause.NamedChild(k)
				id := spec.ChildByFieldName("alias")
				if id == nil {
					id = spec.ChildByFieldName("name")
				}
				if id != nil && id.Utf8Text(m.src) == name {
					return true
				}
			}
		}
	}
	return false
}
