package parse

import (
	"regexp"
	"sort"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
)

// sequelizeAttributes returns the Model.init attribute object of a model key.
func (s *moduleSet) sequelizeAttributes(key string) (*sourceModule, *sitter.Node) {
	parts := strings.SplitN(key, ":", 3)
	if len(parts) != 3 || parts[0] != "sequelize" {
		return nil, nil
	}
	m, err := s.load(parts[1])
	if err != nil {
		return nil, nil
	}
	var attributes *sitter.Node
	walkCalls(m.tree.RootNode(), func(call *sitter.Node) {
		if class, config := modelInit(m, call); class == parts[2] && attributes == nil {
			attributes = config
		}
	})
	return m, attributes
}

// applyModelSetter runs a Sequelize attribute setter on a written value. The stored
// value is what the setter passes to setDataValue, so its branches and sanitizers
// stay on the path instead of the field reading as a raw copy of the request.
func (f *flow) applyModelSetter(key, field string, v value) value {
	m, attributes := f.set.sequelizeAttributes(key)
	if attributes == nil {
		return v
	}
	definition := property(attributes, field, m.src)
	if definition == nil || definition.Kind() != "object" {
		return v
	}
	var setter *sitter.Node
	for i := uint(0); i < definition.NamedChildCount(); i++ {
		c := definition.NamedChild(i)
		if name := c.ChildByFieldName("name"); c.Kind() == "method_definition" && name != nil && name.Utf8Text(m.src) == "set" {
			setter = c
		}
	}
	if setter == nil {
		return v
	}
	params, ok := functionParameters(setter, m.src)
	if !ok || len(params) != 1 {
		return v
	}
	stored := value{}
	child := flow{module: m, set: f.set, entry: f.entry, invocation: f.invocation, env: map[string]value{}, depth: 1,
		helpers: &helperExpansion{budget: 16, stack: map[string]bool{}}, setterValue: &stored}
	child.env[params[0].name] = child.transfer(v, "model_setter", params[0].node)
	child.statements(setter.ChildByFieldName("body"))
	if len(stored.deps) == 0 {
		return v
	}
	return stored
}

// restResource is a finale-rest model resource: POST stores request body attributes
// through the model and GET returns the rows, minus excludeAttributes.
type restResource struct {
	model   string
	paths   []string
	exclude map[string]bool
	module  *sourceModule
	call    *sitter.Node
}

func (s *moduleSet) registerRESTResources() {
	var files []string
	for file := range s.allowed {
		files = append(files, file)
	}
	sort.Strings(files)
	for _, file := range files {
		m, err := s.load(file)
		if err != nil || !strings.Contains(string(m.src), "finale-rest") {
			continue
		}
		walkCalls(m.tree.RootNode(), func(call *sitter.Node) {
			s.restResources = append(s.restResources, s.finaleCall(m, call)...)
		})
	}
	for _, r := range s.restResources {
		s.registerRESTWrites(r)
	}
}

func (s *moduleSet) finaleCall(m *sourceModule, call *sitter.Node) []restResource {
	fn, args := call.ChildByFieldName("function"), call.ChildByFieldName("arguments")
	if fn == nil || args == nil || fn.Kind() != "member_expression" || args.NamedChildCount() != 1 {
		return nil
	}
	obj, prop := fn.ChildByFieldName("object"), fn.ChildByFieldName("property")
	if obj == nil || prop == nil || prop.Utf8Text(m.src) != "resource" || m.imports[obj.Utf8Text(m.src)].module != "finale-rest" {
		return nil
	}
	config := args.NamedChild(0)
	model := property(config, "model", m.src)
	if model == nil {
		return nil
	}
	if model.Kind() != "shorthand_property_identifier" {
		if key := s.modelIdentity(m, model.Utf8Text(m.src), 0); key != "" {
			return []restResource{{key, finalePaths(m, config, nil), finaleExclude(m, property(config, "excludeAttributes", m.src)), m, call}}
		}
		return nil
	}
	// for (const { name, model } of [{ name: 'User', model: UserModel }, ...]) finale.resource(...)
	loop := call
	for loop != nil && loop.Kind() != "for_in_statement" {
		loop = loop.Parent()
	}
	if loop == nil || loop.ChildByFieldName("right") == nil {
		return nil
	}
	table := loop.ChildByFieldName("right")
	if table.Kind() == "identifier" {
		scope := loop
		for scope.Parent() != nil && !isFunction(scope) && scope.Kind() != "function_declaration" {
			scope = scope.Parent()
		}
		table = singleDeclaration(table.Utf8Text(m.src), scope, m.src)
	}
	if table == nil || table.Kind() != "array" {
		return nil
	}
	var out []restResource
	for i := uint(0); i < table.NamedChildCount(); i++ {
		row := table.NamedChild(i)
		rowModel := property(row, "model", m.src)
		if row.Kind() != "object" || rowModel == nil {
			continue
		}
		if key := s.modelIdentity(m, rowModel.Utf8Text(m.src), 0); key != "" {
			out = append(out, restResource{key, finalePaths(m, config, row), finaleExclude(m, property(row, "exclude", m.src)), m, call})
		}
	}
	return out
}

// finalePaths reads literal endpoints, substituting ${field} from a literal table row.
func finalePaths(m *sourceModule, config, row *sitter.Node) []string {
	endpoints := property(config, "endpoints", m.src)
	if endpoints == nil || endpoints.Kind() != "array" {
		return nil
	}
	var paths []string
	for i := uint(0); i < endpoints.NamedChildCount(); i++ {
		e := endpoints.NamedChild(i)
		if text, ok := stringLiteral(e, m.src); ok {
			paths = append(paths, text)
			continue
		}
		if e.Kind() != "template_string" {
			continue
		}
		var b strings.Builder
		complete := true
		for j := uint(0); j < e.NamedChildCount(); j++ {
			part := e.NamedChild(j)
			if part.Kind() == "string_fragment" {
				b.WriteString(part.Utf8Text(m.src))
			} else if part.Kind() == "template_substitution" && part.NamedChildCount() == 1 {
				literal, ok := stringLiteral(property(row, part.NamedChild(0).Utf8Text(m.src), m.src), m.src)
				complete = complete && ok
				b.WriteString(literal)
			}
		}
		if complete {
			paths = append(paths, b.String())
		}
	}
	return paths
}

func finaleExclude(m *sourceModule, list *sitter.Node) map[string]bool {
	out := map[string]bool{}
	if list == nil || list.Kind() != "array" {
		return out
	}
	for i := uint(0); i < list.NamedChildCount(); i++ {
		if text, ok := stringLiteral(list.NamedChild(i), m.src); ok {
			out[text] = true
		}
	}
	return out
}

var stringColumnType = regexp.MustCompile(`DataTypes\.(STRING|TEXT|CHAR)`)

// registerRESTWrites treats each string attribute as written by the collection POST,
// unless that POST is registered with a denying handler in the same module.
func (s *moduleSet) registerRESTWrites(r restResource) {
	m, attributes := s.sequelizeAttributes(r.model)
	if attributes == nil || len(r.paths) == 0 {
		return
	}
	path := r.paths[0]
	denied := regexp.MustCompile(`\.post\(\s*['"` + "`" + `]` + regexp.QuoteMeta(path) + `/?['"` + "`" + `]\s*,[^\n]*denyAll\(`)
	if denied.Match(r.module.src) {
		return
	}
	f := flow{module: r.module, set: s, env: map[string]value{}}
	if s.storageWrites == nil {
		s.storageWrites = map[string][]storageWrite{}
	}
	for i := uint(0); i < attributes.NamedChildCount(); i++ {
		pair := attributes.NamedChild(i)
		key, definition := pair.ChildByFieldName("key"), pair.ChildByFieldName("value")
		if key == nil || definition == nil {
			continue
		}
		columnType := definition
		if definition.Kind() == "object" {
			columnType = property(definition, "type", m.src)
		}
		if columnType == nil || !stringColumnType.MatchString(columnType.Utf8Text(m.src)) {
			continue
		}
		field := key.Utf8Text(m.src)
		source := r.module.evidence("input_source", r.call)
		transfer := r.module.evidence("rest_body_field", r.call)
		transfer.Text = "POST " + path + " body." + field
		v := f.applyModelSetter(r.model, field, value{deps: []analysis.Dependency{{Source: source, Transfers: []analysis.Evidence{transfer}}}})
		writeKey := r.model + "." + field
		s.storageWrites[writeKey] = append(s.storageWrites[writeKey], storageWrite{"", v, r.module.evidence("storage_write", r.call)})
	}
}

// fieldOrigins resolves a response path in a value. When the path reaches a storage
// row, the remaining segment is a column and its origins are that column's writes.
func (s *moduleSet) fieldOrigins(v value, path string) []analysis.Dependency {
	segments := strings.Split(strings.ReplaceAll(path, "[]", ".[]"), ".")
	for _, segment := range segments {
		if segment == "" {
			continue
		}
		if next, ok := v.fields[segment]; ok {
			v = next
			continue
		}
		if v.model == "" {
			return nil
		}
		if segment == "[]" {
			continue
		}
		return s.columnOrigins(v.model + "." + segment)
	}
	var out []analysis.Dependency
	for _, d := range v.deps {
		if d.StorageKey != "" {
			out = append(out, s.columnOrigins(d.StorageKey)...)
		} else {
			out = append(out, d)
		}
	}
	return out
}

func (s *moduleSet) columnOrigins(key string) []analysis.Dependency {
	var out []analysis.Dependency
	for _, w := range s.storageWrites[key] {
		for _, d := range w.value.deps {
			d.Transfers = append(append([]analysis.Evidence{}, d.Transfers...), w.sink)
			out = append(out, d)
		}
	}
	return out
}

// restOrigins resolves a GET of a finale resource; responses wrap rows in `data`.
func (s *moduleSet) restOrigins(path, field string) ([]analysis.Dependency, bool) {
	for _, r := range s.restResources {
		for _, p := range r.paths {
			if !routePatternMatch(p, path) {
				continue
			}
			column := strings.TrimPrefix(strings.TrimPrefix(field, "data"), "[]")
			column = strings.TrimPrefix(column, ".")
			if column == "" || strings.ContainsAny(column, ".[") || r.exclude[column] {
				return nil, true
			}
			return s.columnOrigins(r.model + "." + column), true
		}
	}
	return nil, false
}
