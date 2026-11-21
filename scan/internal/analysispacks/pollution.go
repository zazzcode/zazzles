package analysispacks

import (
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/guidelines"
	"github.com/zazzcode/zazzles/scan/internal/lang"
)

const PollutionProtocol = "pollution-components-v1"

const (
	LodashMerge = "lodash-merge-v1"
	LodashSet   = "lodash-set-v1"
)

var pollutionContracts = []string{LodashMerge, LodashSet}

// PollutionRoles are the source evidence obligations for the write claim.
func PollutionRoles() []string {
	return []string{"input_source", "sink_binding", "invoked_callable", "control_flow", "key_operand"}
}

// PollutionContract returns the reviewed operand semantics for a verified Lodash call.
func PollutionContract(id string) *analysis.APIModel {
	switch id {
	case LodashMerge:
		return &analysis.APIModel{ID: id, Library: "lodash", Reference: "https://github.com/lodash/lodash/wiki/Changelog#v41712",
			Semantics: "Reviewed 2026-11-20. merge, mergeWith and defaultsDeep traverse keys in each source object after the target. The mergeWith customizer is separate from the sources. CVE-2018-3721, CVE-2018-16487 and CVE-2019-10744 have operation- and version-specific reach. Use the recorded key listing for the resolved package."}
	case LodashSet:
		return &analysis.APIModel{ID: id, Library: "lodash", Reference: "https://github.com/advisories/GHSA-p6mc-m468-83gw",
			Semantics: "Reviewed 2026-11-20. set and setWith traverse the path after the target. zipObjectDeep traverses each path in its first argument. Assigned values and customizers are separate operands. Use the recorded key listing for the resolved package."}
	}
	return nil
}

// PollutionQuestions defines the questions for the prototype write protocol.
func PollutionQuestions() []Question {
	return []Question{
		{"prototype_key_control", "Can the key operand select a prototype lookup followed by a write on Object.prototype? Judge the supplied source, operand type, and write."},
		{"key_guard_bypass", "Does a recorded key guard leave an inherited route open? Apply the scanner's blocked and open lists at the relevant lookup levels. Use not_applicable when no key guard is present."},
		{"protection_coverage", "Do the recorded controls protect every relevant key-bearing path and lookup level?"},
	}
}

func pollutionQuestionNames() []string {
	names := make([]string, 0, 3)
	for _, q := range PollutionQuestions() {
		names = append(names, q.Name)
	}
	return names
}

// PollutionChoices lists the accepted answers for a prototype write question.
func PollutionChoices(question string) []map[string]string {
	options := func(pairs ...[2]string) []map[string]string {
		choices := make([]map[string]string, 0, len(pairs))
		for _, pair := range pairs {
			choices = append(choices, map[string]string{"value": pair[0], "description": pair[1]})
		}
		return choices
	}
	switch question {
	case "prototype_key_control":
		return options(
			[2]string{"vulnerable", "A request-controlled key reaches a prototype lookup and a later write on a supported path."},
			[2]string{"protected", "Source-backed controls prevent the key operand from reaching the prototype on every path."},
			[2]string{"not_applicable", "The operand cannot select keys for this write."},
			[2]string{"unknown", "The source or its control over a relevant key is unresolved."},
		)
	case "key_guard_bypass":
		return options(
			[2]string{"bypass_identified", "The supplied key guard leaves a viable prototype lookup open on a supported write path."},
			[2]string{"no_bypass", "The supplied controls close every prototype lookup supported by this write."},
			[2]string{"guard_semantics_unknown", "The supplied evidence does not establish how the guard treats relevant keys."},
			[2]string{"not_applicable", "No key guard stands between the operand and this write."},
		)
	case "protection_coverage":
		return options(
			[2]string{"complete", "Every key-bearing path and prototype lookup level has enforcing coverage."},
			[2]string{"incomplete", "At least one supported key path has no effective control."},
			[2]string{"unknown", "Coverage cannot be determined on one or more required paths."},
		)
	}
	return nil
}

func pollutionDescriptors() []Component {
	f := FamFamily(analysis.PollutionKind)
	base := func(id, kind, owner string, applicability []string, material string) Component {
		return Component{ID: id, Kind: kind, Owner: owner, Version: "1", Domains: []string{"security"},
			Applicability: applicability, Compatibility: []string{PollutionProtocol}, Material: material,
			Tests: []string{"TestPollutionLodashWrite", "TestPollutionSourceWrites", "TestPollutionPolicy"}}
	}
	choices := map[string][]map[string]string{}
	for _, q := range PollutionQuestions() {
		choices[q.Name] = PollutionChoices(q.Name)
	}
	pack := base(f.Pack, "pack", "internal/analysispacks", f.Kinds, "")
	pack.Dependencies = []Requirement{{f.Claim, "1"}, {f.Evidence, "1"}}
	claim := base(f.Claim, "claim_questions", "internal/analysispacks", f.Kinds, claimPayload(PollutionQuestions(), choices))
	evidence := base(f.Evidence, "evidence_obligations", f.PolicyOwner, f.Kinds, "")
	evidence.Required = PollutionRoles()
	evidence.Dependencies = []Requirement{{"flow.pollution", "1"}}
	flow := base("flow.pollution", "compiled_capability", "internal/langjs/pollution.go", f.Kinds, "")
	flow.CompiledOwner = "internal/langjs/pollution.go"
	flow.Limits = []string{"server-side application entries and bounded source-visible writes"}
	g := guidelines.PollutionGuidelines()
	language := base(languageID(f, lang.JavaScript), "language_guidance", "internal/guidelines/pollution.go", g.Languages, encoded(g))
	out := []Component{pack, claim, evidence, flow, language}
	for _, entry := range []string{"http", "grpc", "graphql"} {
		c := base("entry.pollution."+entry, "compiled_capability", "internal/langjs", []string{entry}, "")
		c.CompiledOwner = "internal/langjs"
		out = append(out, c)
	}
	for _, id := range pollutionContracts {
		contract := PollutionContract(id)
		c := base("api."+id, "api_contract", "internal/analysispacks/pollution.go", []string{contract.Library}, encoded(contract))
		c.CompiledOwner = "internal/langjs/pollution.go"
		out = append(out, c)
	}
	input := nodeInputComponent()
	input.ID = "source.node-input-pollution-v1"
	input.Applicability = f.Kinds
	input.Compatibility = []string{PollutionProtocol}
	return append(out, input)
}
