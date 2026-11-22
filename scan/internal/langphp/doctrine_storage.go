package langphp

import (
	"path"
	"slices"
	"strings"
	"unicode"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

const doctrineORM = `Doctrine\ORM\Mapping\`

func symfonyProperties(decl *phpClassDecl) map[string]*sitter.Node {
	properties := map[string]*sitter.Node{}
	body := phpField(decl.node, "body")
	for i := uint(0); body != nil && i < body.NamedChildCount(); i++ {
		member := body.NamedChild(i)
		if member.Kind() != "property_declaration" {
			continue
		}
		for j := uint(0); j < member.NamedChildCount(); j++ {
			element := member.NamedChild(j)
			if element.Kind() == "property_element" {
				properties[phpVarName(decl.module, phpField(element, "name"))] = member
			}
		}
	}
	return properties
}

// doctrineScalarProperty reports an entity property whose declared type is
// int, float or bool (nullable or not).
func doctrineScalarProperty(m *phpModule, property *sitter.Node) bool {
	switch strings.TrimPrefix(strings.ToLower(phpText(m, phpField(property, "type"))), "?") {
	case "int", "float", "bool":
		return true
	}
	return false
}

func (f *phpFlow) symfonyEntity(decl *phpClassDecl, origin *sitter.Node) (phpValue, bool) {
	return f.symfonyEntityDepth(decl, origin, 0)
}

func (f *phpFlow) symfonyEntityDepth(decl *phpClassDecl, origin *sitter.Node, depth int) (phpValue, bool) {
	if !f.doctrineEntityDecl(decl) {
		return phpValue{}, false
	}
	m := decl.module
	f.set.objects++
	object := phpValue{binding: "php_class", class: decl.fqn, classDecl: decl, objectID: f.set.objects, props: map[string]phpValue{}}
	fields := f.doctrineFieldKeys(decl)
	naming := f.doctrineNaming()
	if !doctrineKnownNaming(naming) {
		gap := f.gap("doctrine_naming_unresolved", "Unknown Doctrine naming strategy", origin)
		object.gaps = []analysis.Gap{gap}
		f.gaps = append(f.gaps, gap)
	}
	properties := symfonyProperties(decl)
	for _, field := range sortedTwigFields(properties) {
		property := properties[field]
		if depth < 3 {
			if association, ok := f.doctrineAssociation(decl, property, origin, depth); ok {
				object.props[field] = association
				continue
			}
		}
		key := fields[field]
		if key == "" && (len(object.gaps) == 0 || f.symfonyAttribute(m, property, doctrineORM+"Column") == nil) {
			continue
		}
		if doctrineScalarProperty(m, property) && key != "" {
			// PHP enforces the declared int, float or bool type on every
			// write, so the field never holds text content.
			source := m.evidence("storage_source", property)
			object.props[field] = phpNumeric(phpValue{gaps: object.gaps, deps: []phpDep{{dep: analysis.Dependency{Source: source, StorageKey: key}}}}, analysis.CommandValueNumber, source)
			continue
		}
		source := m.evidence("storage_source", property)
		object.props[field] = phpValue{gaps: object.gaps, deps: []phpDep{{dep: analysis.Dependency{Source: source, StorageKey: key}, protection: "raw"}}}
	}
	f.doctrineObject(object, true)
	return object, true
}

func doctrineMappedName(f *phpFlow, m *phpModule, declaration *sitter.Node, mapping, fallback, naming string) string {
	if attr := f.symfonyAttribute(m, declaration, doctrineORM+mapping); attr != nil {
		if name := symfonyAttributeString(m, attr, "name"); name != "" {
			return name
		}
	}
	if !strings.Contains(naming, ".underscore") {
		return fallback
	}
	var result strings.Builder
	var previous rune
	numberAware := strings.HasSuffix(naming, ".underscore_number_aware")
	for _, r := range fallback {
		if unicode.IsUpper(r) && (unicode.IsLower(previous) || numberAware && unicode.IsDigit(previous)) {
			result.WriteByte('_')
		}
		result.WriteRune(unicode.ToLower(r))
		previous = r
	}
	return result.String()
}

type doctrineObject struct {
	managed bool
	fields  map[string]string
	writes  map[string][]phpWrite
	authz   *phpAuthz
}

type doctrineStorage struct {
	objects map[int]*doctrineObject
	census  map[string][]analysis.StoredWrite
	fields  map[*phpClassDecl]map[string]string
	repos   map[*phpClassDecl]string
}

func newDoctrineStorage() doctrineStorage {
	return doctrineStorage{
		objects: map[int]*doctrineObject{}, census: map[string][]analysis.StoredWrite{},
		fields: map[*phpClassDecl]map[string]string{}, repos: map[*phpClassDecl]string{},
	}
}

func (f *phpFlow) doctrineTrackObject(v phpValue, at *sitter.Node) {
	if f.symfony != nil && v.classDecl != nil {
		f.doctrineObject(v, false)
	}
}

func (f *phpFlow) doctrineObject(v phpValue, managed bool) *doctrineObject {
	if f.symfony == nil || v.classDecl == nil || v.objectID == 0 {
		return nil
	}
	if prior := f.set.doctrine.objects[v.objectID]; prior != nil {
		prior.managed = prior.managed || managed
		return prior
	}
	fields := f.doctrineFieldKeys(v.classDecl)
	if len(fields) == 0 {
		return nil
	}
	obj := &doctrineObject{managed: managed, fields: fields, writes: map[string][]phpWrite{}}
	f.set.doctrine.objects[v.objectID] = obj
	return obj
}

func (f *phpFlow) doctrinePropertyWrite(object phpValue, left, name *sitter.Node, v phpValue) {
	obj := f.doctrineObject(object, false)
	if obj == nil {
		return
	}
	if name.Kind() == "name" {
		if key := obj.fields[phpText(f.module, name)]; key != "" {
			f.doctrineWrite(obj, key, v, f.module.evidence("storage_write", left))
			f.noteAuthzProperty(object, key, v, left)
			f.noteSecretStore(object, key, v, left)
			f.noteDigestStore(key, v, left)
		}
		return
	}
	if phpVarName(f.module, phpField(left, "object")) != "this" || !slices.ContainsFunc(v.deps, func(d phpDep) bool {
		return d.dep.Source.Kind == "input_source" && (phpRequestContainer(d.container) ||
			((d.container == "request" || d.container == "query" || d.container == "any") && d.key == ""))
	}) {
		return
	}
	at := f.module.evidence("storage_write_wildcard", left)
	for _, name := range sortedTwigFields(obj.fields) {
		f.doctrineWrite(obj, obj.fields[name], v, at)
	}
}

func (f *phpFlow) doctrineWrite(object *doctrineObject, key string, v phpValue, at analysis.Evidence) {
	v = phpTransfer(v, at)
	object.writes[key] = append(object.writes[key], phpWrite{value: v, entry: f.entry.ID, evidence: at})
}

func (f *phpFlow) doctrineStorageCall(n *sitter.Node, receiver phpValue, method string, values []phpValue) (phpValue, bool) {
	if f.symfony == nil {
		return phpValue{}, false
	}
	switch strings.ToLower(receiver.class) {
	case "doctrine\\orm\\entitymanagerinterface", "doctrine\\orm\\entitymanager":
		switch method {
		case "persist":
			if len(values) > 0 {
				f.doctrineObject(values[0], true)
			}
			return phpValue{}, true
		case "flush":
			return phpValue{}, true
		case "remove":
			if len(values) > 0 {
				f.noteAuthzDelete(values[0], n)
			}
			return phpValue{}, true
		}
	}
	return phpValue{}, false
}

func (f *phpFlow) doctrineRepositoryEntity(decl *phpClassDecl) string {
	if decl == nil {
		return ""
	}
	if found, ok := f.set.doctrine.repos[decl]; ok {
		return found
	}
	f.set.doctrine.repos[decl] = ""
	index := f.set.classIndex()
	_, ctor, m, _ := index.method(decl, "__construct")
	var found string
	phpWalk(phpField(ctor, "body"), func(n *sitter.Node) {
		if n.Kind() != "scoped_call_expression" || !strings.EqualFold(phpText(m, phpField(n, "scope")), "parent") || phpText(m, phpField(n, "name")) != "__construct" {
			return
		}
		args := phpArgs(n)
		if len(args) > 1 {
			found = doctrineClassConstant(index, m, args[1])
		}
	})
	if found == "" {
		for _, name := range sortedTwigFields(index.byName) {
			for _, entity := range index.byName[name] {
				if f.set.symfonyProjectOf(entity.module.file) != f.symfony {
					continue
				}
				attr := f.symfonyAttribute(entity.module, entity.node, doctrineORM+"Entity")
				args := phpField(attr, "parameters")
				for i := uint(0); args != nil && i < args.NamedChildCount(); i++ {
					arg := args.NamedChild(i)
					if phpText(entity.module, phpField(arg, "name")) == "repositoryClass" && arg.NamedChildCount() > 0 &&
						strings.EqualFold(doctrineClassConstant(index, entity.module, arg.NamedChild(arg.NamedChildCount()-1)), decl.fqn) {
						if found != "" && found != entity.fqn {
							return ""
						}
						found = entity.fqn
					}
				}
			}
		}
	}
	f.set.doctrine.repos[decl] = found
	return found
}

func doctrineClassConstant(index *phpClassIndex, m *phpModule, n *sitter.Node) string {
	if n == nil || n.Kind() != "class_constant_access_expression" || n.NamedChildCount() != 2 || !strings.EqualFold(phpText(m, n.NamedChild(1)), "class") {
		return ""
	}
	return index.qualify(m, phpText(m, n.NamedChild(0)), n.StartByte())
}

func (f *phpFlow) doctrineFinder(n *sitter.Node, receiver phpValue, method string, values []phpValue) (phpValue, bool) {
	many := false
	// The callers pass the lower-cased name; the lookup keeps the declared
	// case so a magic finder names its field as the entity declares it.
	declared := phpText(f.module, phpField(n, "name"))
	if !strings.EqualFold(declared, method) {
		declared = method
	}
	method = strings.ToLower(method)
	switch method {
	case "findall", "findby":
		many = true
	case "find", "findoneby":
	case "count":
	default:
		switch {
		case strings.HasPrefix(method, "findoneby") && len(method) > len("findoneby"):
		case strings.HasPrefix(method, "findby") && len(method) > len("findby"):
			many = true
		default:
			return phpValue{}, false
		}
	}
	entity := ""
	criteria := values
	switch strings.ToLower(receiver.class) {
	case "doctrine\\orm\\entitymanagerinterface", "doctrine\\orm\\entitymanager":
		if method != "find" {
			return phpValue{}, false
		}
		args := phpArgs(n)
		if len(args) > 0 {
			entity = doctrineClassConstant(f.set.classIndex(), f.module, args[0])
		}
		// EntityManager::find(Class::class, $id): the identifier is argument 2.
		criteria = values[min(1, len(values)):]
	default:
		switch {
		case receiver.classDecl != nil && f.doctrineRepository(receiver.classDecl):
			entity = f.doctrineRepositoryEntity(receiver.classDecl)
		case receiver.binding == "doctrine_repository":
			entity = receiver.class
		default:
			return phpValue{}, false
		}
	}
	f.noteEnumerationLookup(n, entity, declared, criteria)
	if method == "count" {
		return phpValue{}, true
	}
	object := f.doctrineResultEntity(n, entity, many)
	return f.noteFinderSubject(n, object, method, values), true
}

func (f *phpFlow) doctrineResultEntity(n *sitter.Node, class string, many bool) phpValue {
	if decl := f.symfonyClass(class); decl != nil {
		if object, ok := f.symfonyEntity(decl, n); ok {
			return object
		}
	}
	gap := f.gap("php_call_unresolved", "Doctrine result entity could not be resolved", n)
	return phpValue{unknown: true, gaps: []analysis.Gap{gap}}
}

func (f *phpFlow) doctrineFieldKeys(decl *phpClassDecl) map[string]string {
	if fields, ok := f.set.doctrine.fields[decl]; ok {
		return fields
	}
	m := decl.module
	if !f.doctrineEntityDecl(decl) {
		return nil
	}
	naming := f.doctrineNaming()
	if !doctrineKnownNaming(naming) {
		return nil
	}
	table := doctrineMappedName(f, m, decl.node, "Table", phpText(m, phpField(decl.node, "name")), naming)
	fields := map[string]string{}
	for field, node := range symfonyProperties(decl) {
		if f.symfonyAttribute(m, node, doctrineORM+"Column") == nil {
			continue
		}
		column := doctrineMappedName(f, m, node, "Column", field, naming)
		fields[field] = "php-sql:" + table + "." + column
	}
	f.set.doctrine.fields[decl] = fields
	return fields
}

func (f *phpFlow) doctrineEntityDecl(decl *phpClassDecl) bool {
	if f.symfonyAttribute(decl.module, decl.node, doctrineORM+"Entity") != nil {
		return true
	}
	comment := decl.node.PrevNamedSibling()
	if comment == nil || comment.Kind() != "comment" {
		return false
	}
	scope := f.set.classIndex().scopeAt(decl.module, decl.node.StartByte())
	for alias, target := range scope.uses {
		if strings.EqualFold(target, strings.TrimSuffix(doctrineORM, `\`)) &&
			strings.Contains(strings.ToLower(phpText(decl.module, comment)), "@"+strings.ToLower(alias)+`\entity`) {
			return true
		}
	}
	return false
}

func (f *phpFlow) doctrineNaming() string {
	config := f.symfony.configs[path.Join(f.symfony.root, "config/packages/doctrine.yaml")]
	return symfonyYAMLString(symfonyYAMLValue(symfonyYAMLValue(symfonyYAMLValue(config.value, "doctrine"), "orm"), "naming_strategy"))
}

func doctrineKnownNaming(name string) bool {
	switch name {
	case "", "doctrine.orm.naming_strategy.default", "doctrine.orm.naming_strategy.underscore", "doctrine.orm.naming_strategy.underscore_number_aware":
		return true
	}
	return false
}

func (f *phpFlow) doctrineAssociation(object *phpClassDecl, property *sitter.Node, origin *sitter.Node, depth int) (phpValue, bool) {
	m := object.module
	for _, kind := range []string{"ManyToOne", "OneToOne", "OneToMany", "ManyToMany"} {
		attr := f.symfonyAttribute(m, property, doctrineORM+kind)
		if attr == nil {
			continue
		}
		args := phpField(attr, "parameters")
		target := ""
		index := f.set.classIndex()
		for i := uint(0); args != nil && i < args.NamedChildCount(); i++ {
			arg := args.NamedChild(i)
			if phpText(m, phpField(arg, "name")) == "targetEntity" && arg.NamedChildCount() > 0 {
				val := arg.NamedChild(arg.NamedChildCount() - 1)
				target = doctrineClassConstant(index, m, val)
				if target == "" {
					target, _ = phpStringLiteral(m, val)
				}
			}
		}
		if target == "" {
			typ := phpField(property, "type")
			if typ != nil {
				target = index.qualify(m, strings.TrimPrefix(phpText(m, typ), "?"), typ.StartByte())
			}
		}
		if decl := f.symfonyClass(target); decl != nil {
			return f.symfonyEntityDepth(decl, origin, depth+1)
		}
	}
	return phpValue{}, false
}
