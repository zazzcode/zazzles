package langphp

import (
	"path"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"gopkg.in/yaml.v3"
)

func (f *phpFlow) symfonyClass(class string) *phpClassDecl {
	var target *phpClassDecl
	for _, decl := range f.set.classIndex().byName[strings.ToLower(class)] {
		if f.set.symfonyProjectOf(decl.module.file) != f.symfony {
			continue
		}
		if target != nil {
			return nil
		}
		target = decl
	}
	return target
}

func (f *phpFlow) autowireSymfony(class string, at *sitter.Node) phpValue {
	inputs := f.set.projectInputsFor(f.module.file)
	seen := map[string]bool{}
	for {
		service, ok := inputs.services[class]
		if !ok || seen[class] {
			break
		}
		seen[class] = true
		if service.alias != "" {
			class = service.alias
		} else {
			class = service.class
			break
		}
	}
	decl := f.symfonyClass(class)
	if decl == nil || decl.kind == "interface" {
		decl = f.symfonyImplementation(class)
	}
	if decl != nil && decl.kind == "class" && firstChildOfKind(decl.node, "abstract_modifier") == nil {
		return f.symfonyServiceObject(decl, at)
	}
	return phpValue{class: class, binding: "symfony_opaque", unknown: true}
}

func (f *phpFlow) symfonyImplementation(contract string) *phpClassDecl {
	index := f.set.classIndex()
	var found *phpClassDecl
	for _, classes := range index.byName {
		for _, decl := range classes {
			if decl.kind != "class" || f.set.symfonyProjectOf(decl.module.file) != f.symfony ||
				firstChildOfKind(decl.node, "abstract_modifier") != nil {
				continue
			}
			interfaces := firstChildOfKind(decl.node, "class_interface_clause")
			for i := uint(0); interfaces != nil && i < interfaces.NamedChildCount(); i++ {
				name := interfaces.NamedChild(i)
				if !strings.EqualFold(index.qualify(decl.module, phpText(decl.module, name), name.StartByte()), contract) {
					continue
				}
				if found != nil && found != decl {
					return nil
				}
				found = decl
			}
		}
	}
	return found
}

func (f *phpFlow) symfonyServiceObject(decl *phpClassDecl, at *sitter.Node) phpValue {
	key := strings.ToLower(decl.fqn)
	if value, ok := f.services[key]; ok {
		return value
	}
	f.set.objects++
	v := phpValue{binding: "php_class", class: decl.fqn, classDecl: decl, objectID: f.set.objects, props: map[string]phpValue{}}
	f.services[key] = v
	if f.depth >= phpHelperDepthLimit || *f.work >= phpHelperWorkLimit {
		v.propsUnknown = true
		v.gaps = []analysis.Gap{f.gap("work_limit", "Symfony constructor expansion limit", at)}
		f.services[key] = v
		return v
	}
	owner, ctor, module, _ := f.set.classIndex().method(decl, "__construct")
	if ctor == nil {
		return v
	}
	source := f.clone()
	source.module = module
	source.depth++
	params := phpField(ctor, "parameters")
	var values []phpValue
	for i := uint(0); params != nil && i < params.NamedChildCount(); i++ {
		p := params.NamedChild(i)
		if !strings.HasSuffix(p.Kind(), "_parameter") {
			continue
		}
		name := phpVarName(module, phpField(p, "name"))
		if value, ok := f.symfonyServiceArgument(decl.fqn, name); ok {
			values = append(values, value)
		} else {
			values = append(values, source.symfonyParameter("", p, false))
		}
	}
	f.boundHelper(at, &phpBoundCallable{module: module, fn: ctor, object: &v, class: owner}, values)
	f.services[key] = v
	return v
}

func (f *phpFlow) symfonyServiceArgument(class, name string) (phpValue, bool) {
	config := f.symfony.configs[path.Join(f.symfony.root, "config/services.yaml")]
	services := symfonyYAMLValue(config.value, "services")
	service := symfonyYAMLValue(services, class)
	key := "$" + name
	for _, group := range []*yaml.Node{
		symfonyYAMLValue(service, "arguments"), symfonyYAMLValue(service, "bind"),
		symfonyYAMLValue(symfonyYAMLValue(services, "_defaults"), "bind"),
	} {
		param := symfonyYAMLValue(group, key)
		if param == nil || param.Kind != yaml.ScalarNode {
			continue
		}
		evidence := symfonyYAMLOrigin(config.source, param)
		evidence.Kind = "configuration_binding"
		// Configuration values are evidence of a binding, never secret values.
		evidence.Text, evidence.ModelText = "", ""
		value := param.Value
		if strings.Contains(value, "%env(") {
			return phpValue{configuration: true, unknown: true, evidence: []analysis.Evidence{evidence}}, true
		}
		if strings.HasPrefix(value, "%") && strings.HasSuffix(value, "%") {
			result, ok := f.symfony.parameter(strings.Trim(value, "%"))
			if !ok {
				continue
			}
			if result.configuration {
				return phpValue{configuration: true, unknown: true, evidence: []analysis.Evidence{evidence}}, true
			}
			value = result.literal
		}
		return phpValue{constant: true, literals: []phpLiteral{{text: value}}, evidence: []analysis.Evidence{evidence}}, true
	}
	return phpValue{}, false
}
