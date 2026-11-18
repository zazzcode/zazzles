package langjs

import (
	"regexp"
	"sort"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
	"github.com/zazzcode/zazzles/internal/parse"
)

// mongooseQueryContext follows only the selected registration's direct static
// module wiring. An unrelated same-name schema elsewhere is not model evidence.
func (s *moduleSet) mongooseQueryContext(use *analysis.CandidateUse) {
	if use.APIModel == nil || use.APIModel.Library != "mongoose" {
		return
	}
	use.Completeness.Required = append(use.Completeness.Required, "model_schema")
	m := s.modules[use.Sink.Span.File]
	if m == nil {
		return
	}
	call := parse.NodeAt(m.tree.RootNode(), use.Sink.Span.StartByte, use.Sink.Span.EndByte)
	if call == nil {
		return
	}
	fn := call.ChildByFieldName("function")
	if fn == nil {
		return
	}
	obj := fn.ChildByFieldName("object")
	if obj == nil {
		return
	}
	id := s.modelIdentity(m, obj.Utf8Text(m.src), 0)
	if !strings.HasPrefix(id, "mongoose:") {
		return
	}
	label := strings.TrimPrefix(id, "mongoose:")
	modules, wiring := s.mongooseContextModules(use, m)
	if len(modules) > 24 {
		use.Completeness.Blockers = append(use.Completeness.Blockers, analysis.Gap{Kind: "mongoose_schema_context_limit", Detail: "Direct model-wiring context exceeds24 modules", At: use.Sink.Span})
		return
	}
	definitions := mongooseSchemaDefinitions(modules, label, use)
	if len(definitions) != 1 {
		if len(definitions) > 1 {
			use.Completeness.Blockers = append(use.Completeness.Blockers, analysis.Gap{Kind: "mongoose_schema_ambiguous", Detail: "Multiple reachable registrations of the selected default model name", At: use.Sink.Span})
		}
		return
	}
	for _, e := range append(wiring, definitions[0]...) {
		use.Context = append(use.Context, e)
		use.Completeness.Evidence[e.Kind] = append(use.Completeness.Evidence[e.Kind], e)
	}
	if version, evidence := s.mongooseDeclaredVersion(m.file); version != "" {
		use.Context = append(use.Context, evidence)
		use.Completeness.Evidence[evidence.Kind] = append(use.Completeness.Evidence[evidence.Kind], evidence)
		if version == "4.2.4" {
			use.APIModel = analysispacks.NoSQLContract("mongoose-model-query-v2")
		}
	}
}

func contractWrittenBefore(m *sourceModule, name string, site *sitter.Node) bool {
	found := false
	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		if found || n.StartByte() >= site.StartByte() {
			return
		}
		if n.Kind() == "assignment_expression" || n.Kind() == "augmented_assignment_expression" {
			if left := n.ChildByFieldName("left"); left != nil {
				v := left.Utf8Text(m.src)
				found = v == name || strings.HasPrefix(v, name+".") || strings.HasPrefix(v, name+"[")
			}
		}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			visit(n.NamedChild(i))
		}
	}
	visit(m.tree.RootNode())
	return found
}

var mongooseManifestPin = regexp.MustCompile(`"mongoose"\s*:\s*"([0-9]+\.[0-9]+\.[0-9]+)"`)

func (s *moduleSet) mongooseDeclaredVersion(file string) (string, analysis.Evidence) {
	declared, manifest := s.declaration(file, "mongoose")
	if declared == "" {
		return "", analysis.Evidence{}
	}
	e, ok := s.readBounded(manifest, maxPackageFileBytes)
	if !ok {
		return "", analysis.Evidence{}
	}
	matches := mongooseManifestPin.FindAllStringSubmatchIndex(e.Text, -1)
	if len(matches) != 1 {
		return "", analysis.Evidence{}
	}
	match := matches[0]
	version := e.Text[match[2]:match[3]]
	if declared != version || s.packageVersion(file, "mongoose") != version {
		return "", analysis.Evidence{}
	}
	return version, parse.TextRange(e, match[0], match[1], "model_dependency_version")
}

// Query hooks and custom schema callbacks can change filters; a declaration alone
// cannot establish their effect. Only the literal/default schema subset is modeled.
func mongooseSchemaBehaviorGaps(m *sourceModule, schema, registration *sitter.Node) []analysis.Gap {
	gaps := []analysis.Gap{}
	add := func(n *sitter.Node) {
		gaps = append(gaps, analysis.Gap{Kind: "mongoose_schema_behavior_unresolved", Detail: "Custom schema callback, hook or mutation may alter query casting/filter behavior", At: parse.Span(m.file, n)})
	}
	var inside func(*sitter.Node)
	inside = func(n *sitter.Node) {
		if isFunction(n) {
			add(n)
			return
		}
		if n != schema && (n.Kind() == "call_expression" || n.Kind() == "spread_element") {
			add(n)
			return
		}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			inside(n.NamedChild(i))
		}
	}
	inside(schema)
	walkCalls(m.tree.RootNode(), func(call *sitter.Node) {
		imp, method, ok := importedContractCall(m, call)
		if ok && imp.module == "mongoose" && (method == "plugin" || method == "set") {
			add(call)
		}
	})
	declaration := schema.Parent()
	if declaration == nil || declaration.Kind() != "variable_declarator" {
		return gaps
	}
	name := declaration.ChildByFieldName("name")
	if name == nil || name.Kind() != "identifier" {
		return gaps
	}
	text := name.Utf8Text(m.src)
	cutoff := m.tree.RootNode().EndByte()
	var writes func(*sitter.Node)
	writes = func(n *sitter.Node) {
		if n.Kind() == "assignment_expression" && n.StartByte() > schema.StartByte() && n.StartByte() < cutoff {
			if left := n.ChildByFieldName("left"); left != nil {
				target := left.Utf8Text(m.src)
				if strings.HasPrefix(target, text+".") || strings.HasPrefix(target, text+"[") {
					add(n)
				}
			}
		}
		if n.Kind() == "assignment_expression" && n.StartByte() > registration.StartByte() {
			left := n.ChildByFieldName("left")
			if left != nil && left.Kind() == "identifier" && left.Utf8Text(m.src) == text && n.StartByte() < cutoff {
				cutoff = n.StartByte()
			}
		}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			writes(n.NamedChild(i))
		}
	}
	writes(m.tree.RootNode())
	walkCalls(m.tree.RootNode(), func(call *sitter.Node) {
		if call.StartByte() < schema.StartByte() || call.StartByte() >= cutoff {
			return
		}
		fn := call.ChildByFieldName("function")
		if fn == nil {
			return
		}
		target := fn.Utf8Text(m.src)
		if strings.HasPrefix(target, text+".") || strings.HasPrefix(target, text+"[") {
			add(call)
		}
		if call.StartByte() != registration.StartByte() {
			if args := call.ChildByFieldName("arguments"); args != nil {
				for i := uint(0); i < args.NamedChildCount(); i++ {
					if a := args.NamedChild(i); a.Kind() == "identifier" && a.Utf8Text(m.src) == text {
						add(call)
					}
				}
			}
		}
	})
	return gaps
}

func (s *moduleSet) mongooseContextModules(use *analysis.CandidateUse, m *sourceModule) (map[string]*sourceModule, []analysis.Evidence) {
	roots := map[string]*sourceModule{m.file: m}
	for _, e := range use.Context {
		if e.Kind == "route_registration" {
			if module := s.modules[e.Span.File]; module != nil {
				roots[module.file] = module
			}
		}
	}
	modules := map[string]*sourceModule{}
	wiring := []analysis.Evidence{}
	keys := []string{}
	for k := range roots {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		parent := roots[key]
		modules[key] = parent
		top := parent.tree.RootNode()
		for i := uint(0); i < top.NamedChildCount(); i++ {
			n := top.NamedChild(i)
			if n.Kind() == "import_statement" {
				if value, ok := stringLiteral(n.ChildByFieldName("source"), parent.src); ok {
					if target := s.importModule(parent, value); target != nil {
						modules[target.file] = target
						wiring = append(wiring, parent.evidence("model_module_binding", n))
					}
				}
			}
			if n.Kind() == "expression_statement" && n.NamedChildCount() == 1 {
				if path, _, ok := requireBinding(parent, n.NamedChild(0)); ok {
					if target := s.importModule(parent, path); target != nil {
						modules[target.file] = target
						wiring = append(wiring, parent.evidence("model_module_binding", n))
					}
				}
			}
			if n.Kind() == "variable_declaration" || n.Kind() == "lexical_declaration" {
				for j := uint(0); j < n.NamedChildCount(); j++ {
					d := n.NamedChild(j)
					if path, _, ok := requireBinding(parent, d.ChildByFieldName("value")); ok {
						if target := s.importModule(parent, path); target != nil {
							modules[target.file] = target
							wiring = append(wiring, parent.evidence("model_module_binding", d))
						}
					}
				}
			}
		}
	}

	return modules, wiring
}

func mongooseSchemaDefinitions(modules map[string]*sourceModule, label string, use *analysis.CandidateUse) [][]analysis.Evidence {
	keys := []string{}
	for key := range modules {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	definitions := [][]analysis.Evidence{}
	for _, key := range keys {
		module := modules[key]
		top := module.tree.RootNode()
		for i := uint(0); i < top.NamedChildCount(); i++ {
			statement := top.NamedChild(i)
			var candidates []*sitter.Node
			if statement.Kind() == "expression_statement" && statement.NamedChildCount() == 1 {
				candidates = append(candidates, statement.NamedChild(0))
			}
			if statement.Kind() == "variable_declaration" || statement.Kind() == "lexical_declaration" {
				for j := uint(0); j < statement.NamedChildCount(); j++ {
					candidates = append(candidates, statement.NamedChild(j).ChildByFieldName("value"))
				}
			}
			for _, registration := range candidates {
				evidence, gaps := mongooseSchemaRegistration(module, registration, label)
				if len(evidence) == 0 {
					continue
				}
				use.Gaps = append(use.Gaps, gaps...)
				use.Completeness.Blockers = append(use.Completeness.Blockers, gaps...)
				definitions = append(definitions, evidence)
			}
		}
	}

	return definitions
}

func mongooseSchemaRegistration(module *sourceModule, registration *sitter.Node, label string) ([]analysis.Evidence, []analysis.Gap) {
	imp, method, ok := importedContractCall(module, registration)
	if !ok || imp.module != "mongoose" || method != "model" {
		return nil, nil
	}
	args := registration.ChildByFieldName("arguments")
	if args == nil || args.NamedChildCount() != 2 {
		return nil, nil
	}
	name, ok := stringLiteral(args.NamedChild(0), module.src)
	if !ok || name != label {
		return nil, nil
	}
	schema := args.NamedChild(1)
	var declaration *sitter.Node
	if schema.Kind() == "identifier" {
		declaration = topVariable(module, schema.Utf8Text(module.src))
		if declaration == nil || declaration.StartByte() > registration.StartByte() || contractWrittenBefore(module, schema.Utf8Text(module.src), registration) {
			return nil, nil
		}
		schema = declaration
	}
	if schema.Kind() != "new_expression" {
		return nil, nil
	}
	constructor := schema.ChildByFieldName("constructor")
	if constructor == nil {
		return nil, nil
	}
	if constructor.Kind() == "identifier" {
		if bindingReassigned(module, constructor.Utf8Text(module.src)) {
			return nil, nil
		}
		constructor = topVariable(module, constructor.Utf8Text(module.src))
	}
	if constructor == nil || constructor.Kind() != "member_expression" {
		return nil, nil
	}
	owner, property := constructor.ChildByFieldName("object"), constructor.ChildByFieldName("property")
	if owner == nil || property == nil || property.Utf8Text(module.src) != "Schema" {
		return nil, nil
	}
	binding := module.imports[owner.Utf8Text(module.src)]
	if binding.module != "mongoose" || (binding.name != "*" && binding.name != "default") || !contractBindingStable(module, owner.Utf8Text(module.src)) {
		return nil, nil
	}
	evidence := []analysis.Evidence{module.evidence("model_schema", schema), module.evidence("model_schema_registration", registration), module.evidence("model_schema_library", binding.declaration)}
	if declaration != nil {
		evidence = append(evidence, module.evidence("model_schema_binding", declaration.Parent()))
	}
	if parent := constructor.Parent(); parent != nil && (parent.StartByte() != schema.StartByte() || parent.EndByte() != schema.EndByte()) {
		evidence = append(evidence, module.evidence("model_schema_constructor", constructor.Parent()))
	}
	return evidence, mongooseSchemaBehaviorGaps(module, schema, registration)
}
