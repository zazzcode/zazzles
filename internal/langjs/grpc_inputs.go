package langjs

import (
	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/parse"
)

type grpcInput struct {
	role     string
	fields   []string
	evidence analysis.Evidence
}

func grpcInputs(m *sourceModule, fn *sitter.Node) ([]analysis.InputBinding, []analysis.Gap) {
	params, ok := functionParameters(fn, m.src)
	var defaults func(*sitter.Node)
	defaults = func(n *sitter.Node) {
		if n == nil {
			return
		}
		if n.Kind() == "assignment_pattern" || n.Kind() == "required_parameter" && n.ChildByFieldName("value") != nil {
			ok = false
		}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			defaults(n.NamedChild(i))
		}
	}
	defaults(fn.ChildByFieldName("parameters"))
	if !ok || len(params) > 2 {
		return nil, []analysis.Gap{{Kind: "grpc_parameters_unresolved", Detail: "Unary handler requires at most two identifier parameters without defaults", At: parse.Span(m.file, fn)}}
	}
	if len(params) == 0 {
		return nil, nil
	}
	var inputs []analysis.InputBinding
	for _, role := range []string{"request", "metadata", "context"} {
		origin := "unknown"
		if role == "request" {
			origin = "external"
		}
		inputs = append(inputs, analysis.InputBinding{Role: "grpc." + role, Parameter: params[0].name, Projection: []string{role}, Origin: analysis.InputOrigin{Kind: origin, Evidence: []analysis.Evidence{m.evidence("grpc_input_binding", params[0].node)}}})
	}
	if len(params) == 2 {
		inputs = append(inputs, analysis.InputBinding{Role: "grpc.callback", Parameter: params[1].name, Origin: analysis.InputOrigin{Kind: "unknown", Evidence: []analysis.Evidence{m.evidence("grpc_input_binding", params[1].node)}}})
	}
	return inputs, nil
}
func (s *moduleSet) grpcFlow(out *analysis.AnalysisReport, m *sourceModule, fn *sitter.Node, entry analysis.EntryPoint, ctx analysis.InvocationContext, method grpcMethod, keepCase bool, handler analysis.Evidence) {
	f := flow{module: m, set: s, registration: m, entry: entry, invocation: ctx, env: map[string]value{}, context: []analysis.Evidence{entry.Location, method.evidence, handler, m.evidence("invoked_callable", fn.ChildByFieldName("body"))}, helpers: &helperExpansion{budget: 24, stack: map[string]bool{}}, facts: newInputFacts()}
	f.context = append(f.context, out.Registrations[len(out.Registrations)-1].DerivedFrom...)
	fields := append([]string{}, method.fields...)
	for i, name := range fields {
		if !keepCase {
			fields[i] = grpcFieldName(name)
		}
	}
	for _, input := range ctx.Inputs {
		if input.Role == "grpc.request" {
			f.env[input.Parameter] = value{grpcInput: &grpcInput{role: "call", fields: fields, evidence: input.Origin.Evidence[0]}}
			if bindingReassigned(m, input.Parameter) || graphqlArgumentMutation(m, input.Parameter) {
				f.gaps = append(f.gaps, analysis.Gap{Kind: "grpc_input_mutation", Detail: "Unary call/request object is mutated; projection uncertainty retained", At: input.Origin.Evidence[0].Span})
			}
		} else if input.Role == "grpc.callback" {
			f.env[input.Parameter] = value{gaps: []analysis.Gap{{Kind: "grpc_origin_unknown", Detail: "Callback is not request data", At: input.Origin.Evidence[0].Span}}}
		}
	}
	f.statements(fn.ChildByFieldName("body"))
	f.finishValidation()
	out.InvocationContexts[len(out.InvocationContexts)-1].Gaps = append(out.InvocationContexts[len(out.InvocationContexts)-1].Gaps, f.gaps...)
	// Control statements are condition evidence, never value transfers from sibling registrations.
	for i := range f.uses {
		for j, e := range f.uses[i].Context {
			if e.Kind == "control_statement" {
				if owner := s.modules[e.Span.File]; owner != nil {
					if node := parse.NodeAt(owner.tree.RootNode(), e.Span.StartByte, e.Span.EndByte); node != nil {
						if condition := node.ChildByFieldName("condition"); condition != nil {
							f.uses[i].Context[j] = owner.evidence("conditional_test", condition)
						}
					}
				}
			}
		}
	}
	promoteInvocationPreconditions(f.uses, f.context)
	out.Uses = append(out.Uses, f.uses...)
}
func (f *flow) grpcProjection(n *sitter.Node, base value) (value, bool) {
	if base.grpcInput == nil {
		return value{}, false
	}
	name := ""
	if prop := n.ChildByFieldName("property"); prop != nil {
		name = prop.Utf8Text(f.module.src)
	} else {
		name, _ = stringLiteral(n.ChildByFieldName("index"), f.module.src)
	}
	// The unchanged object marker survives branch merging. Specific mutation,
	// escape and control-context gaps remain; a generic merge warning alone
	// does not change the origin of an immutable request projection.
	filtered := []analysis.Gap{}
	for _, g := range base.gaps {
		if g.Kind != "unknown_control_effect" {
			filtered = append(filtered, g)
		}
	}
	base.gaps = filtered
	marker := base.grpcInput
	if marker.role == "call" {
		if name != "request" {
			return value{gaps: append(append([]analysis.Gap{}, base.gaps...), f.gap("grpc_origin_unknown", "Metadata/context/call properties have no request-field provenance", n))}, true
		}
		copy := *marker
		copy.role = "request"
		base.grpcInput = &copy
		return f.transfer(base, "grpc_request_projection", n), true
	}
	v := value{gaps: append([]analysis.Gap{}, base.gaps...)}
	known := false
	for _, field := range marker.fields {
		known = known || field == name
	}
	if !known {
		v.gaps = append(v.gaps, f.gap("grpc_projection_unresolved", "Request field is not declared by this method's message", n))
	}
	source := f.module.evidence("input_source", n)
	f.rememberInput(source)
	v.deps = []analysis.Dependency{{Source: source, Transfers: append([]analysis.Evidence{marker.evidence}, base.grpcTransfers...)}}
	return v, true
}

// proto-loader 0.8 uses protobufjs 7's field camelCase conversion: keep the
// first byte, and fold only underscore + lowercase pairs in the remainder.
func grpcFieldName(name string) string {
	out := make([]byte, 0, len(name))
	for i := 0; i < len(name); i++ {
		if i > 0 && name[i] == '_' && i+1 < len(name) && name[i+1] >= 'a' && name[i+1] <= 'z' {
			i++
			out = append(out, name[i]-'a'+'A')
		} else {
			out = append(out, name[i])
		}
	}
	return string(out)
}
