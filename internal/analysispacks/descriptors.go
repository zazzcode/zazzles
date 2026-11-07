package analysispacks

import (
	"encoding/json"

	"github.com/zazzcode/zazzles/internal/guidelines"
)

func encoded(v any) string { b, _ := json.Marshal(v); return string(b) }

func claimPayload(questions []Question, choices map[string][]map[string]string) string {
	return encoded(claimMaterial{Questions: questions, Choices: choices})
}

func descriptors() ([]Component, error) {
	sharedLimits := []string{"bounded existing adapters only; no additional discovery or safety guarantees"}
	allKinds := []string{"sql_query_candidate", "nosql_query_candidate", "input_validation_candidate"}
	makeComponent := func(id, kind, owner string, app []string, protocols []string, material string) Component {
		return Component{ID: id, Version: "1", Kind: kind, Owner: owner, Domains: []string{"security", "construction_practice", "validation"}, Applicability: app, Compatibility: protocols, Limits: sharedLimits, Tests: []string{"TestFamilyComponentSelection"}, Material: material}
	}
	out := []Component{}
	claims := map[string]struct {
		questions []Question
		choices   func() map[string][]map[string]string
	}{
		"claim.xss": {XSSQuestions(), func() map[string][]map[string]string {
			choices := map[string][]map[string]string{}
			for _, q := range XSSQuestions() {
				choices[q.Name] = XSSChoices(q.Name)
			}
			return choices
		}},
		"claim.sql": {SQLQuestions(), func() map[string][]map[string]string {
			return map[string][]map[string]string{"validation": PracticeChoices(), "protection": PracticeChoices(), "injection_protection": SQLInjectionChoices()}
		}},
		"claim.nosql": {NoSQLQuestions(), func() map[string][]map[string]string {
			choices := map[string][]map[string]string{"validation": PracticeChoices(), "protection": PracticeChoices(), "injection_protection": InjectionChoices()}
			for _, name := range []string{"all_paths_protected", "source_coverage", "library_coverage", "guard_coverage", "path_coverage"} {
				choices[name] = NoSQLCoverageChoices()
			}
			return choices
		}},
		"claim.validation": {ValidationQuestions(), func() map[string][]map[string]string {
			choices := map[string][]map[string]string{}
			for _, q := range ValidationQuestions() {
				choices[q.Name] = ValidationChoices(q.Name)
			}
			return choices
		}},
	}
	for _, f := range Families() {
		if f.ObservationOnly || f.Name == "command" {
			continue
		}
		protocol := familyProtocol(f.Name)
		claim := claims[f.Claim]
		pack := makeComponent(f.Pack, "pack", "internal/analysispacks", f.Kinds, []string{protocol}, "")
		pack.Dependencies = []Requirement{{f.Claim, "1"}, {f.Evidence, "1"}}
		questions := makeComponent(f.Claim, "claim_questions", "internal/analysispacks", f.Kinds, []string{protocol}, claimPayload(claim.questions, claim.choices()))
		evidence := makeComponent(f.Evidence, "evidence_obligations", f.PolicyOwner, f.Kinds, []string{protocol}, "")
		evidence.Dependencies = []Requirement{{flowID(&f), "1"}}
		switch f.Name {
		case "xss":
			evidence.Required = []string{"render_source", "render_binding", "render_context"}
		case "sql":
			evidence.Required = []string{"input_source", "sink_binding", "invoked_callable", "control_flow"}
		case "nosql":
			evidence.Required = []string{"input_source", "sink_binding", "invoked_callable", "control_flow"}
		case "validation":
			evidence.Required = []string{"input_source", "field_policy", "invoked_callable", "control_flow"}
		}
		out = append(out, pack, questions, evidence)
	}
	// The local flow adapter is a deliberately shared compiled capability: all
	// three families resolve value/transfer facts through the same parse path.
	flow := makeComponent("flow.local", "compiled_capability", "internal/parse/query_evidence.go + internal/parse/python_sql.go", allKinds, []string{SQLProtocol, NoSQLProtocol, ValidationProtocol}, "")
	out = append(out, flow)
	for _, f := range Families() {
		if f.ObservationOnly || f.Name == "command" {
			continue
		}
		seen := map[string]bool{}
		for _, language := range f.Languages {
			id := languageID(&f, language)
			// JavaScript and TypeScript share one guidance document; a single
			// component owns both.
			if seen[id] {
				continue
			}
			seen[id] = true
			g, err := guidelines.FamilyBody(language, f.Name)
			if err != nil {
				// A registered family's language document must contain every
				// required section; embedded configuration is invalid.
				return nil, err
			}
			v := makeComponent(id, "language_guidance", "internal/guidelines/"+g.ID+".md", g.Languages, []string{familyProtocol(f.Name)}, encoded(g))
			v.Version = g.Version
			v.Owner = "internal/guidelines/families.go:" + g.ID + ".md"
			out = append(out, v)
		}
	}
	for _, entry := range []string{"http", "graphql", "grpc"} {
		v := makeComponent("entry."+entry, "compiled_capability", "internal/parse", []string{entry}, []string{SQLProtocol, NoSQLProtocol}, "")
		v.Tests = []string{"TestFamilyComponentSelection", "TestSQLComponentPipelineParity", "TestNoSQLComponentPipelineParity"}
		if entry == "http" {
			v.Tests = append(v.Tests, "TestSQLHTTPComponentAnswers", "TestSQLPythonComponentPipeline", "TestValidationComponentPipelineParity")
		}
		v.Limits = append(v.Limits, "verified registration/dispatch/invocation only; context-specific effects")
		out = append(out, v)
	}
	contractOwners := map[string]string{}
	for _, id := range sqlContractIDs {
		contractOwners[id] = "internal/parse/checks.go"
	}
	for _, id := range sqlContractIDs[1:] {
		contractOwners[id] = "internal/parse/python_sql.go"
	}
	for _, id := range noSQLContractIDs {
		contractOwners[id] = "internal/parse/checks.go + internal/parse/mongoose_query_context.go"
	}
	for _, f := range Families() {
		if f.ObservationOnly || f.Name == "command" {
			continue
		}
		if !f.RequiresAPI {
			continue
		}
		for _, id := range contractIDs(&f) {
			model := familyContract(&f, id)
			v := makeComponent("api."+id, "api_contract", "internal/analysispacks", []string{model.Library}, []string{familyProtocol(f.Name)}, encoded(model))
			v.CompiledOwner = contractOwners[id]
			v.Tests = []string{"TestFamilyComponentSelection"}
			if id == "mongoose-path-id-objectid-v1" {
				v.Required = []string{"selector_path_string"}
				v.Tests = append(v.Tests, "TestMongoosePathIDFacts", "TestMongoosePathIDJudgment")
			}
			if f.Name == "sql" {
				v.Tests = append(v.Tests, "TestSQLComponentPipelineParity")
				if model.Library != "sequelize" {
					v.Tests = append(v.Tests, "TestSQLPythonComponentPipeline")
				}
			} else {
				v.Tests = append(v.Tests, "TestNoSQLComponentPipelineParity")
			}
			v.Limits = append(v.Limits, "library version not inferred; only existing verified operation/operand contract applies")
			out = append(out, v)
		}
	}
	cmd, err := commandDescriptors()
	if err != nil {
		return nil, err
	}
	out = append(out, cmd...)
	out = append(out, xssDescriptors()...)
	out = append(out, outboundDescriptors()...)
	return out, nil
}
