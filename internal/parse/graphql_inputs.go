package parse

import (
	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
)

func graphqlInputs(m *sourceModule, fn *sitter.Node) ([]analysis.InputBinding, []analysis.Gap) {
	params, ok := functionParameters(fn, m.src)
	var checkDefaults func(*sitter.Node)
	checkDefaults = func(n *sitter.Node) {
		if n == nil {
			return
		}
		if n.Kind() == "assignment_pattern" || n.Kind() == "required_parameter" && n.ChildByFieldName("value") != nil {
			ok = false
		}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			checkDefaults(n.NamedChild(i))
		}
	}
	checkDefaults(fn.ChildByFieldName("parameters"))

	if !ok || len(params) > 4 {
		return nil, []analysis.Gap{{Kind: "graphql_parameters_unresolved", Detail: "Resolver requires at most four identifier parameters", At: spanOf(m.file, fn)}}
	}
	var inputs []analysis.InputBinding
	roles := []string{"parent", "args", "context", "info"}
	for i, p := range params {
		origin := "unknown"
		if i == 1 {
			origin = "external"
		}
		inputs = append(inputs, analysis.InputBinding{Role: "graphql." + roles[i], Parameter: p.name, Origin: analysis.InputOrigin{Kind: origin, Evidence: []analysis.Evidence{m.evidence("graphql_input_binding", p.node)}}})
	}
	return inputs, nil
}
func (s *moduleSet) graphqlFlow(out *analysis.AnalysisReport, m *sourceModule, fn *sitter.Node, entry analysis.EntryPoint, ctx analysis.InvocationContext, field graphqlField, handler analysis.Evidence) {
	f := flow{module: m, set: s, registration: m, entry: entry, invocation: ctx, env: map[string]value{}, context: []analysis.Evidence{entry.Location, field.evidence, handler, m.evidence("invoked_callable", fn.ChildByFieldName("body"))}, helpers: &helperExpansion{budget: 24, stack: map[string]bool{}}, facts: newInputFacts()}
	// Seed each formal slot independently. Only args has externally supplied values;
	// parent/context/info retain unknown provenance, never args-shaped source records.
	for _, input := range ctx.Inputs {
		if input.Role == "graphql.args" {
			v := value{fields: map[string]value{}, graphqlArgs: &input.Origin.Evidence[0]}
			for _, name := range field.args {
				v.fields[name] = value{}
			}
			f.env[input.Parameter] = v
			if bindingReassigned(m, input.Parameter) || graphqlArgumentMutation(m, input.Parameter) {
				f.gaps = append(f.gaps, analysis.Gap{Kind: "graphql_input_mutation", Detail: "Resolver argument object is mutated; projection uncertainty retained", At: input.Origin.Evidence[0].Span})
			}
		} else {
			f.env[input.Parameter] = value{gaps: []analysis.Gap{{Kind: "graphql_origin_unknown", Detail: input.Role + " provenance is not established", At: input.Origin.Evidence[0].Span}}}
		}
	}
	// Argument projections are read at their actual source span by graphqlInputValue.
	f.statements(fn.ChildByFieldName("body"))
	f.finishValidation()
	for _, g := range f.gaps {
		out.InvocationContexts[len(out.InvocationContexts)-1].Gaps = append(out.InvocationContexts[len(out.InvocationContexts)-1].Gaps, g)
	}
	for i := range f.uses {
		for j, e := range f.uses[i].Context {
			if e.Kind != "control_statement" {
				continue
			}
			if owner := s.modules[e.Span.File]; owner != nil {
				if node := nodeAt(owner.tree.RootNode(), e.Span.StartByte, e.Span.EndByte); node != nil {
					if condition := node.ChildByFieldName("condition"); condition != nil {
						f.uses[i].Context[j] = owner.evidence("conditional_test", condition)
					}
				}
			}
		}
	}
	promoteInvocationPreconditions(f.uses, f.context)
	out.Uses = append(out.Uses, f.uses...)
}

func (f *flow) graphqlInputValue(n *sitter.Node) (value, bool) {
	if f.entry.Kind != "graphql" || (n.Kind() != "member_expression" && n.Kind() != "subscript_expression") {
		return value{}, false
	}
	obj := n.ChildByFieldName("object")
	if obj == nil || obj.Kind() != "identifier" {
		return value{}, false
	}
	marker, ok := f.env[obj.Utf8Text(f.module.src)]
	if !ok || marker.graphqlArgs == nil {
		return value{}, false
	}
	prop := n.ChildByFieldName("property")
	name := ""
	if prop != nil {
		name = prop.Utf8Text(f.module.src)
	} else {
		name, _ = stringLiteral(n.ChildByFieldName("index"), f.module.src)
	}
	v := value{}
	for _, g := range marker.gaps {
		if g.Kind != "unknown_control_effect" {
			v.gaps = append(v.gaps, g)
		}
	}
	if _, known := marker.fields[name]; !known {
		v.gaps = append(v.gaps, f.gap("graphql_projection_unresolved", "Argument projection is not declared by this schema field", n))
	}
	if graphqlPropertyWrite(f.module, obj.Utf8Text(f.module.src)) {
		v.gaps = append(v.gaps, f.gap("graphql_input_mutation", "Argument object/alias property is mutated", n))
	}
	source := f.module.evidence("input_source", n)
	f.rememberInput(source)
	v.deps = []analysis.Dependency{{Source: source, Transfers: append([]analysis.Evidence{*marker.graphqlArgs}, marker.graphqlTransfers...)}}
	return v, true
}

func graphqlArgumentMutation(m *sourceModule, param string) bool {
	aliases := map[string]bool{param: true}
	for round := 0; round < 16; round++ {
		changed := false
		var visit func(*sitter.Node)
		visit = func(n *sitter.Node) {
			if n.Kind() == "variable_declarator" {
				id, v := n.ChildByFieldName("name"), n.ChildByFieldName("value")
				if id != nil && v != nil && id.Kind() == "identifier" && v.Kind() == "identifier" && aliases[v.Utf8Text(m.src)] && !aliases[id.Utf8Text(m.src)] {
					aliases[id.Utf8Text(m.src)] = true
					changed = true
				}
			}
			for i := uint(0); i < n.NamedChildCount(); i++ {
				visit(n.NamedChild(i))
			}
		}
		visit(m.tree.RootNode())
		if !changed {
			for name := range aliases {
				if graphqlPropertyWrite(m, name) {
					return true
				}
			}
			return false
		}
	}
	return true // Alias expansion bound: do not assume immutability.
}
