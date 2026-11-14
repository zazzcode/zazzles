package analysispacks

import (
	"github.com/zazzcode/zazzles/internal/guidelines"
	"github.com/zazzcode/zazzles/internal/lang"
)

// pathDescriptors creates every path-traversal component. They are separate
// from the shared query-family loops so no existing component descriptor,
// digest or selected request changes when the family is added.
func pathDescriptors() ([]Component, error) {
	f := FamilyForName("path")
	kinds := f.Kinds
	protocols := []string{PathProtocol}
	base := func(id, kind, owner string, applicability []string, material string) Component {
		return Component{ID: id, Version: "1", Kind: kind, Owner: owner, Domains: []string{"security", "filesystem_path"}, Applicability: applicability, Compatibility: protocols, Tests: []string{"TestPathComponentSelection"}, Material: material,
			Limits: []string{"bounded static adapters only; POSIX is a declared assumption, not inferred from the scanner host; symbolic-link and race state is never inferred"}}
	}
	claims := map[string][]map[string]string{}
	for _, q := range PathQuestions() {
		claims[q.Name] = PathChoices(q.Name)
	}
	pack := base(f.Pack, "pack", "internal/analysispacks", kinds, "")
	pack.Dependencies = []Requirement{{f.Claim, "1"}, {f.Evidence, "1"}}
	claim := base(f.Claim, "claim_questions", "internal/analysispacks/path.go", kinds, claimPayload(PathQuestions(), claims))
	evidence := base(f.Evidence, "evidence_obligations", f.PolicyOwner, kinds, "")
	evidence.Dependencies = []Requirement{{flowID(f), "1"}}
	evidence.Required = []string{"input_source", "sink_binding", "invoked_callable", "control_flow", "path_operands"}
	flow := base("flow.path", "compiled_capability", "internal/parse/path_claims.go + internal/parse/path_node.go + internal/parse/python_path.go", kinds, "")
	flow.Tests = []string{"TestPathComponentSelection", "TestPathJSOperands", "TestPathPythonOperands"}
	flow.Limits = append(flow.Limits,
		"supported transfers: direct assignment, string concatenation/templates, verified path join/resolve/normalize and pathlib operations, supported helper parameters and branches; unsupported calls, spreads and *args/**kwargs stay gaps",
		"unknown relevant pre-sink helpers, reassignments, mutable operands, dispatch or guards block the affected witness; unrelated response/output gaps do not")
	out := []Component{pack, claim, evidence, flow}
	for _, language := range f.Languages {
		if language == lang.TypeScript {
			continue // JavaScript and TypeScript share one document and component.
		}
		g, err := guidelines.PathBody(language)
		if err != nil {
			return nil, err
		}
		v := base(languageID(f, language), "language_guidance", "internal/guidelines/path.go:"+g.ID, g.Languages, encoded(g))
		v.Version = g.Version
		out = append(out, v)
	}
	for _, id := range pathContractIDs {
		model := PathContract(id)
		v := base("api."+id, "api_contract", "internal/analysispacks/path.go", []string{model.Library}, encoded(model))
		v.CompiledOwner = pathOwners[id]
		v.Tests = []string{"TestPathComponentSelection", "TestPathBindingsAndOptions"}
		v.Limits = append(v.Limits, "runtime/library version not inferred; only the verified operation and operand contract applies")
		out = append(out, v)
	}
	out = append(out, pathNodeInputComponent())
	return out, nil
}

// pathNodeInputComponent carries the accepted node-input interpretation under a
// path-only identity: widening the shared component's applicability would change
// its digest and with it every existing family's selected request.
func pathNodeInputComponent() Component {
	v := nodeInputComponent()
	v.ID = "source.node-input-path-v1"
	v.Applicability = []string{"path_traversal_candidate"}
	v.Compatibility = []string{PathProtocol}
	v.Tests = []string{"TestPathComponentSelection"}
	return v
}
