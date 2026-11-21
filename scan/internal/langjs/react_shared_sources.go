package langjs

import (
	sitter "github.com/tree-sitter/go-tree-sitter"
)

func (s *moduleSet) zustandHook(m *sourceModule, fn *sitter.Node) bool {
	if fn.Kind() != "identifier" {
		return false
	}
	name := fn.Utf8Text(m.src)
	target := m
	if imp, ok := m.imports[name]; ok {
		target = s.importModule(m, imp.module)
		name = imp.name
	}
	if target == nil {
		return false
	}
	init := unwrapTS(topVariable(target, name))
	if init == nil || init.Kind() != "call_expression" {
		return false
	}
	factory := init.ChildByFieldName("function")
	if factory == nil || factory.Kind() != "identifier" {
		return false
	}
	imp, ok := target.imports[factory.Utf8Text(target.src)]
	return ok && (imp.module == "zustand" || imp.module == "zustand/traditional") && (imp.name == "create" || imp.name == "createWithEqualityFn" || imp.name == "default")
}
