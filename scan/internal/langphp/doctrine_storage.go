package langphp

import (
	"maps"
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

func (f *phpFlow) symfonyEntity(decl *phpClassDecl, origin *sitter.Node) (phpValue, bool) {
	m := decl.module
	if f.symfonyAttribute(m, decl.node, doctrineORM+"Entity") == nil {
		return phpValue{}, false
	}
	f.set.objects++
	object := phpValue{binding: "php_class", class: decl.fqn, classDecl: decl, objectID: f.set.objects, props: map[string]phpValue{}}
	config := f.symfony.configs[path.Join(f.symfony.root, "config/packages/doctrine.yaml")]
	naming := symfonyYAMLString(symfonyYAMLValue(symfonyYAMLValue(symfonyYAMLValue(config.value, "doctrine"), "orm"), "naming_strategy"))
	if naming != "" && naming != "doctrine.orm.naming_strategy.default" && naming != "doctrine.orm.naming_strategy.underscore" && naming != "doctrine.orm.naming_strategy.underscore_number_aware" {
		object.gaps = []analysis.Gap{f.gap("doctrine_naming_unresolved", "Unknown Doctrine naming strategy", origin)}
		return object, true
	}
	table := doctrineMappedName(f, m, decl.node, "Table", phpText(m, phpField(decl.node, "name")), naming)
	properties := symfonyProperties(decl)
	for _, field := range slices.Sorted(maps.Keys(properties)) {
		declaration := properties[field]
		if f.symfonyAttribute(m, declaration, doctrineORM+"Column") == nil {
			continue
		}
		column := doctrineMappedName(f, m, declaration, "Column", field, naming)
		source := m.evidence("storage_source", declaration)
		object.props[field] = phpValue{deps: []phpDep{{dep: analysis.Dependency{
			Source: source, StorageKey: "php-sql:" + table + "." + column,
		}, protection: "raw"}}}
	}
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
	for i, r := range fallback {
		if i > 0 && unicode.IsUpper(r) {
			result.WriteByte('_')
		}
		result.WriteRune(unicode.ToLower(r))
	}
	return result.String()
}
