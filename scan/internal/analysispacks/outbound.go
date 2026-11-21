package analysispacks

import (
	"fmt"
	"reflect"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/lang"
)

// OutboundNotAssessed explains the bounded observation eligibility boundary.
const OutboundNotAssessed = "Outbound security assessment is not implemented; this is an observation only."

// ObservationOnly reports whether a registered kind has no security questionnaire.
func ObservationOnly(kind string) bool {
	f := FamFamily(kind)
	return f != nil && f.ObservationOnly
}

// OutboundContract owns the existing Python destination-operand interpretation.
// The compiled adapter must establish module binding and operand roles first.
func OutboundContract(library string) *analysis.APIModel {
	switch library {
	case "requests", "httpx", "urllib":
		return &analysis.APIModel{ID: "python-http-destination-v1", Library: library, Semantics: "The URL/destination operand is separate from request body and response; response data is an independent external source."}
	}
	return nil
}

func outboundRoots(u analysis.CandidateUse, language lang.Language) ([]string, error) {
	if language != lang.Python {
		if u.APIModel != nil {
			return nil, fmt.Errorf("JS/TS outbound shapes have no verified API contract")
		}
		return nil, nil
	}
	if u.APIModel == nil || !reflect.DeepEqual(u.APIModel, OutboundContract(u.APIModel.Library)) {
		return nil, fmt.Errorf("Python outbound observation needs its demonstrated destination contract")
	}
	bound := false
	for _, e := range u.Context {
		bound = bound || e.Kind == "sink_binding"
	}
	if !bound {
		return nil, fmt.Errorf("Python outbound destination binding missing")
	}
	return []string{"api.python-http-destination-v1"}, nil
}

func outboundDescriptors() []Component {
	f := FamFamily("outbound_http_candidate")
	makeItem := func(id, kind, text string, app []string) Component {
		return Component{ID: id, Version: "1", Kind: kind, Domains: []string{"outbound_observation"}, Applicability: app, Compatibility: []string{familyProtocol(f.Name)}, Owner: "internal/analysispacks/outbound.go", Limits: []string{
			OutboundNotAssessed,
			"No SSRF, exfiltration, CORS or CSRF verdict; no target requests, DNS, redirect or deployment-policy analysis",
			"Runtime context follows supported entry/binding evidence; browser HTTP does not establish a server request",
		}, Tests: []string{"TestOutboundComponentSelection", "TestOutboundComponentEvidenceParity"}, Material: text}
	}
	pack := makeItem(f.Pack, "pack", "", f.Kinds)
	pack.Dependencies = []Requirement{{f.Claim, "1"}, {f.Evidence, "1"}}
	evidence := makeItem(f.Evidence, "evidence_obligations", "", f.Kinds)
	evidence.Dependencies = []Requirement{{"flow.outbound", "1"}}
	flow := makeItem("flow.outbound", "compiled_capability", "", f.Kinds)
	flow.CompiledOwner = "internal/parse/flow.go + internal/parse/python_frameworks.go"
	items := []Component{pack, evidence, flow, makeItem(f.Claim, "observation", "Destination, request data and response are separate operands; no security questionnaire.", f.Kinds)}
	js := makeItem("language.outbound.javascript", "language_guidance", "JS/TS fetch/axios-shaped observations are unverified. Argument dependencies are combined, not verified URL slots. Same-name/fake/shadowed calls and package declarations confer no trusted API. Preserve sink_binding_unverified and external_response_unresolved gaps.", []string{"javascript", "typescript"})
	js.Limits = append(js.Limits, js.Material)
	py := makeItem("language.outbound.python", "language_guidance", "Only existing bound requests/httpx function subsets and urllib.request.urlopen; positional/keyword URL and method-first request retain their demonstrated roles. Fixed URL plus body-only data is not destination control. Arbitrary HTTP libraries, sessions, aliases and response continuations are not added.", []string{"python"})
	py.Limits = append(py.Limits, py.Material)
	contract := makeItem("api.python-http-destination-v1", "api_contract", "", []string{"requests", "httpx", "urllib"})
	// Library is source metadata. One component owns shared semantics, not three
	// competing contracts with different receivers.
	contract.Material = encoded(analysis.APIModel{ID: "python-http-destination-v1", Semantics: OutboundContract("requests").Semantics})
	return append(items, js, py, contract)
}

func (c *catalog) validateObservation(f *Family) error {
	if c.components[f.Claim].Kind != "observation" || len(f.QuestionNames) != 0 || c.components[f.Claim].Material == "" {
		return fmt.Errorf("observation family %s must declare observation material without claim questions", f.Name)
	}
	for _, l := range f.Languages {
		if c.components[languageID(f, l)].Material == "" {
			return fmt.Errorf("observation language material missing: %s", l)
		}
	}
	var contract analysis.APIModel
	v := c.components["api.python-http-destination-v1"]
	if err := decode(v.Material, &contract); err != nil {
		return fmt.Errorf("outbound contract: %w", err)
	}
	expected := OutboundContract("requests")
	expected.Library = ""
	if v.Kind != "api_contract" || !reflect.DeepEqual(&contract, expected) {
		return fmt.Errorf("outbound destination contract conflicts with compiled adapter")
	}
	return nil
}
