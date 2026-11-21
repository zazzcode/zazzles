package langjs

import (
	sitter "github.com/tree-sitter/go-tree-sitter"
)

// zodDataFieldReads attaches field projections to a Pages Router safeParse
// result. For `const parsed = Schema.safeParse(x)` it finds each key read as
// `parsed.data.key` in the enclosing function and, when that key is read at
// exactly one place, records a field_projection transfer at that read so the
// validated field keeps its own source evidence. Keys read more than once, a
// reassigned or redeclared result binding, and every other member stay as
// plain property reads. It never marks a value safe.
func (f *flow) zodDataFieldReads(call *sitter.Node, out value) value {
	if f.web != nil || len(out.deps) == 0 {
		return out
	}
	parent := call.Parent()
	if parent != nil && parent.Kind() == "await_expression" {
		parent = parent.Parent()
	}
	if parent == nil || parent.Kind() != "variable_declarator" {
		return out
	}
	id := parent.ChildByFieldName("name")
	if id == nil || id.Kind() != "identifier" {
		return out
	}
	name := id.Utf8Text(f.module.src)
	fn := enclosingFunction(parent)
	if fn == nil || bindingReassigned(f.module, name) {
		return out
	}
	src := f.module.src
	reads := map[string][]*sitter.Node{}
	declared := 0
	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		switch n.Kind() {
		case "variable_declarator":
			if nm := n.ChildByFieldName("name"); nm != nil && nm.Kind() == "identifier" && nm.Utf8Text(src) == name {
				declared++
			}
		case "member_expression":
			obj, prop := n.ChildByFieldName("object"), n.ChildByFieldName("property")
			if obj != nil && prop != nil && prop.Kind() == "property_identifier" && obj.Kind() == "member_expression" {
				base, data := obj.ChildByFieldName("object"), obj.ChildByFieldName("property")
				if base != nil && data != nil && base.Kind() == "identifier" && base.Utf8Text(src) == name && data.Utf8Text(src) == "data" {
					reads[prop.Utf8Text(src)] = append(reads[prop.Utf8Text(src)], prop)
				}
			}
		case "formal_parameters", "required_parameter", "optional_parameter":
			if n.Kind() != "formal_parameters" {
				if p := n.ChildByFieldName("pattern"); p != nil && p.Kind() == "identifier" && p.Utf8Text(src) == name {
					declared++
				}
			}
		}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			visit(n.NamedChild(i))
		}
	}
	visit(fn)
	if declared != 1 {
		return out
	}
	fields := map[string]value{}
	for key, nodes := range reads {
		if len(nodes) == 1 {
			fields[key] = f.transfer(out, "field_projection", nodes[0])
		}
	}
	if len(fields) == 0 {
		return out
	}
	data := out
	data.fields = fields
	out.fields = map[string]value{"data": data}
	return out
}
