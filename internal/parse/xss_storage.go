package parse

import (
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
)

type storageWrite struct {
	route string
	value value
	sink  analysis.Evidence
}

func (f *flow) storedProperty(n *sitter.Node) (value, bool) {
	obj, prop := n.ChildByFieldName("object"), n.ChildByFieldName("property")
	if obj == nil || prop == nil {
		return value{}, false
	}
	var v value
	if obj.Kind() == "identifier" {
		v = f.env[obj.Utf8Text(f.module.src)]
	} else if obj.Kind() == "member_expression" || obj.Kind() == "subscript_expression" {
		v, _ = f.storedProperty(obj)
	}
	field := prop.Utf8Text(f.module.src)
	if selected, ok := v.fields[field]; ok {
		return selected, true
	}
	if v.model == "" || v.read == nil {
		return value{}, false
	}
	if field == "length" {
		return value{}, false
	}
	if field == "dataValues" {
		return v, true // Sequelize's plain row view has the same columns.
	}
	source := f.module.evidence("storage_read", n)
	return value{deps: []analysis.Dependency{{StorageKey: v.model + "." + field, Source: source, Transfers: []analysis.Evidence{*v.read}}}}, true
}

func (f *flow) assignStoredField(left *sitter.Node, v value) {
	if left == nil || left.Kind() != "member_expression" {
		return
	}
	obj, prop := left.ChildByFieldName("object"), left.ChildByFieldName("property")
	if obj == nil || prop == nil || obj.Kind() != "identifier" {
		return
	}
	name := obj.Utf8Text(f.module.src)
	instance := f.env[name]
	if instance.model == "" {
		return
	}
	fields := map[string]value{}
	for key, old := range instance.fields {
		fields[key] = old
	}
	fields[prop.Utf8Text(f.module.src)] = v
	instance.fields = fields
	f.env[name] = instance
}

func (f *flow) xssConstructor(n *sitter.Node) (value, bool) {
	ctor, args := n.ChildByFieldName("constructor"), n.ChildByFieldName("arguments")
	if ctor == nil || args == nil || args.NamedChildCount() != 1 {
		return value{}, false
	}
	if ctor.Utf8Text(f.module.src) == "String" && !moduleBinds(f.module, "String") {
		return f.transfer(f.eval(args.NamedChild(0)), "string_conversion", n), true
	}
	model := f.set.modelIdentity(f.module, ctor.Utf8Text(f.module.src), 0)
	if model == "" || shadowed(n, ctor.Utf8Text(f.module.src), f.module.src) {
		return value{}, false
	}
	v := f.eval(args.NamedChild(0))
	v.model = model
	return v, true
}

func (f *flow) modelCallValue(call, fn *sitter.Node, receiver value) (value, bool) {
	if fn.Kind() != "member_expression" {
		return value{}, false
	}
	obj, prop := fn.ChildByFieldName("object"), fn.ChildByFieldName("property")
	if obj == nil || prop == nil {
		return value{}, false
	}
	if obj.Kind() == "identifier" {
		if v, ok := f.env[obj.Utf8Text(f.module.src)]; ok && v.model != "" {
			receiver = v
		} else {
			if shadowed(call, obj.Utf8Text(f.module.src), f.module.src) {
				return value{}, false
			}
			receiver.model = f.set.modelIdentity(f.module, obj.Utf8Text(f.module.src), 0)
		}
	}
	if receiver.model == "" {
		return value{}, false
	}
	f.context = append(f.context, f.set.modelEvidence[receiver.model]...)
	switch prop.Utf8Text(f.module.src) {
	case "find", "findOne", "findByPk", "findById", "findAll":
		e := f.module.evidence("storage_query", call)
		return value{model: receiver.model, read: &e}, true
	case "exec", "sort", "then", "forEach", "map", "save", "create", "update", "updateOne":
		return receiver, true
	}
	return value{}, false
}

// modelCallback follows a storage callback and returns the values it returned.
func (f *flow) modelCallback(fn *sitter.Node, v value, method string) value {
	if f.depth >= 4 {
		f.gaps = append(f.gaps, f.gap("callback_limit", "storage callback nesting exceeds four levels", fn))
		return value{}
	}
	params, ok := functionParameters(fn, f.module.src)
	if !ok {
		// `.then(([rows]) => ...)`: a raw Sequelize query resolves to [rows, metadata].
		first := firstArrayParameter(fn, f.module.src)
		if first == nil {
			return value{}
		}
		params = []boundParam{*first}
	}
	child := *f
	child.env = copyValues(f.env)
	child.uses, child.returns = nil, nil
	child.depth++
	child.context = append(append([]analysis.Evidence{}, f.context...), f.module.evidence("storage_callback", fn))
	index := 1
	if strings.HasSuffix(method, ".then") || strings.HasSuffix(method, ".forEach") || strings.HasSuffix(method, ".map") {
		index = 0
	}
	for i, p := range params {
		child.env[p.name] = value{}
		if i == index {
			child.env[p.name] = v
		}
		if p.name == child.request {
			child.request = ""
		}
		if p.name == child.response {
			child.response = ""
		}
	}
	child.statements(fn.ChildByFieldName("body"))
	f.uses = append(f.uses, child.uses...)
	var out value
	for _, r := range child.returns {
		out = combine(out, r)
	}
	return out
}

func firstArrayParameter(fn *sitter.Node, src []byte) *boundParam {
	params := fn.ChildByFieldName("parameters")
	if params == nil || params.NamedChildCount() != 1 {
		return nil
	}
	p := params.NamedChild(0)
	if p.Kind() == "required_parameter" {
		p = p.ChildByFieldName("pattern")
	}
	if p == nil || p.Kind() != "array_pattern" || p.NamedChildCount() == 0 || p.NamedChild(0).Kind() != "identifier" {
		return nil
	}
	return &boundParam{name: p.NamedChild(0).Utf8Text(src), node: p.NamedChild(0)}
}

func (f *flow) recordStorageWrite(call, fn, args *sitter.Node, values []value, receiver value) {
	prop := fn.ChildByFieldName("property")
	if prop == nil {
		return
	}
	fields := receiver.fields
	switch prop.Utf8Text(f.module.src) {
	case "save":
	case "create", "update", "updateOne":
		if len(values) == 0 {
			return
		}
		fields = values[0].fields
	default:
		return
	}
	if f.set.storageWrites == nil {
		f.set.storageWrites = map[string][]storageWrite{}
	}
	for field, v := range fields {
		if len(v.deps) == 0 {
			continue
		}
		key := receiver.model + "." + field
		v = f.applyModelSetter(receiver.model, field, v)
		f.set.storageWrites[key] = append(f.set.storageWrites[key], storageWrite{f.entry.ID, v, f.module.evidence("storage_write", call)})
	}
}

func (s *moduleSet) modelIdentity(m *sourceModule, name string, depth int) string {
	if depth > 3 || strings.Contains(name, ".") || bindingReassigned(m, name) {
		return ""
	}
	if imp, ok := m.imports[name]; ok && strings.HasPrefix(imp.module, ".") {
		if target := s.importModule(m, imp.module); target != nil && exportedName(target, imp.name) {
			local := imp.name
			root := target.tree.RootNode()
			for i := uint(0); i < root.NamedChildCount(); i++ {
				n := root.NamedChild(i)
				if n.Kind() != "export_statement" {
					continue
				}
				for j := uint(0); j < n.NamedChildCount(); j++ {
					clause := n.NamedChild(j)
					if clause.Kind() != "export_clause" {
						continue
					}
					for k := uint(0); k < clause.NamedChildCount(); k++ {
						spec := clause.NamedChild(k)
						id, alias := spec.ChildByFieldName("name"), spec.ChildByFieldName("alias")
						if id != nil && alias != nil && alias.Utf8Text(target.src) == local {
							local = id.Utf8Text(target.src)
						}
					}
				}
			}
			return s.modelIdentity(target, local, depth+1)
		}
	}
	if v := topVariable(m, name); v != nil && v.Kind() == "call_expression" {
		fn, args := v.ChildByFieldName("function"), v.ChildByFieldName("arguments")
		if fn != nil && fn.Kind() == "member_expression" && args != nil && args.NamedChildCount() > 0 {
			obj, prop := fn.ChildByFieldName("object"), fn.ChildByFieldName("property")
			if obj != nil && prop != nil && prop.Utf8Text(m.src) == "model" {
				imp := m.imports[obj.Utf8Text(m.src)]
				if imp.module == "mongoose" {
					if label, ok := stringLiteral(args.NamedChild(0), m.src); ok {
						key := "mongoose:" + label
						s.rememberModel(key, []analysis.Evidence{m.evidence("storage_model_binding", v), m.evidence("storage_library_binding", imp.declaration)})
						return key
					}
				}
			}
		}
	}
	root := m.tree.RootNode()
	for i := uint(0); i < root.NamedChildCount(); i++ {
		n := root.NamedChild(i)
		if n.Kind() == "export_statement" {
			n = n.ChildByFieldName("declaration")
		}
		if n == nil || n.Kind() != "class_declaration" {
			continue
		}
		id := n.ChildByFieldName("name")
		if id == nil || id.Utf8Text(m.src) != name {
			continue
		}
		for j := uint(0); j < n.NamedChildCount(); j++ {
			heritage := n.NamedChild(j)
			if heritage.Kind() != "class_heritage" {
				continue
			}
			for local, imp := range m.imports {
				base := strings.TrimSpace(heritage.Utf8Text(m.src))
				if imp.module == "sequelize" && imp.name == "Model" && (base == "extends "+local || strings.HasPrefix(base, "extends "+local+"<")) {
					key := "sequelize:" + m.file + ":" + name
					s.rememberModel(key, []analysis.Evidence{m.evidence("storage_model_binding", n), m.evidence("storage_library_binding", imp.declaration)})
					return key
				}
			}
		}
	}
	return ""
}

func (s *moduleSet) rememberModel(key string, evidence []analysis.Evidence) {
	if s.modelEvidence == nil {
		s.modelEvidence = map[string][]analysis.Evidence{}
	}
	s.modelEvidence[key] = evidence
}
