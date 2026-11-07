package analysispacks

import (
	"github.com/zazzcode/zazzles/internal/guidelines"
	"github.com/zazzcode/zazzles/internal/lang"
)

// commandDescriptors creates every command component. They are separate from
// the shared query-family loops so no existing component descriptor, digest or
// selected request changes when the family is added.
func commandDescriptors() ([]Component, error) {
	f := FamilyForName("command")
	kinds := f.Kinds
	protocols := []string{CommandProtocol}
	base := func(id, kind, owner string, applicability []string, material string) Component {
		return Component{ID: id, Version: "1", Kind: kind, Owner: owner, Domains: []string{"security", "command_execution"}, Applicability: applicability, Compatibility: protocols, Tests: []string{"TestCommandComponentSelection"}, Material: material,
			Limits: []string{"bounded static adapters only; POSIX is a declared assumption, not inferred from the scanner host"}}
	}
	claims := map[string][]map[string]string{}
	for _, q := range CommandQuestions() {
		claims[q.Name] = CommandChoices(q.Name)
	}
	pack := base(f.Pack, "pack", "internal/analysispacks", kinds, "")
	pack.Dependencies = []Requirement{{f.Claim, "1"}, {f.Evidence, "1"}}
	claim := base(f.Claim, "claim_questions", "internal/analysispacks/command.go", kinds, claimPayload(CommandQuestions(), claims))
	evidence := base(f.Evidence, "evidence_obligations", f.PolicyOwner, kinds, "")
	evidence.Dependencies = []Requirement{{flowID(f), "1"}}
	evidence.Required = []string{"input_source", "sink_binding", "invoked_callable", "control_flow", "command_operands", "execution_configuration"}
	flow := base("flow.command", "compiled_capability", "internal/parse/command_claims.go + internal/parse/command_node.go + internal/parse/python_command.go", kinds, "")
	flow.Tests = []string{"TestCommandComponentSelection", "TestCommandJSOperands", "TestCommandPythonOperands"}
	flow.Limits = append(flow.Limits,
		"supported transfers: direct assignment, string concatenation/templates, regex capture, supported helper parameters and branches; unsupported calls, spreads and *args/**kwargs stay gaps",
		"unknown relevant pre-sink helpers, mutable operands, dispatch or guards block the affected witness; unrelated response/output gaps do not")
	out := []Component{pack, claim, evidence, flow}
	for _, language := range f.Languages {
		id := languageID(f, language)
		if language == lang.TypeScript {
			continue // JavaScript and TypeScript share one document and component.
		}
		g, err := guidelines.CommandBody(language)
		if err != nil {
			return nil, err
		}
		v := base(id, "language_guidance", "internal/guidelines/command.go:"+g.ID, g.Languages, encoded(g))
		v.Version = g.Version
		out = append(out, v)
	}
	for _, id := range commandContractIDs {
		model := CommandContract(id)
		v := base("api."+id, "api_contract", "internal/analysispacks/command.go", []string{model.Library}, encoded(model))
		v.CompiledOwner = commandOwners[id]
		v.Tests = []string{"TestCommandComponentSelection", "TestCommandBindingsAndOptions"}
		v.Limits = append(v.Limits, "runtime/library version not inferred; only the verified operation and operand contract applies")
		out = append(out, v)
	}
	return out, nil
}

// FamilyForName returns the registered family with this name, or nil.
func FamilyForName(name string) *Family {
	for _, f := range Families() {
		if f.Name == name {
			value := f
			return &value
		}
	}
	return nil
}
