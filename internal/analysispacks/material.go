package analysispacks

import (
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/guidelines"
)

// Material contains only selected interpretation, never catalog owners or test references.
type Material struct {
	Selection  *analysis.ComponentSelection   `json:"selection"`
	Guidelines guidelines.AnalysisGuidelines  `json:"analysis_guidelines"`
	Contract   *analysis.APIModel             `json:"api_contract"`
	Questions  []Question                     `json:"-"`
	Choices    map[string][]map[string]string `json:"-"`
}

// ForUse validates the supplied static selection against current source facts and
// current embedded bytes before assembling material for a decision request.
func ForUse(use analysis.CandidateUse) (*Material, error) {
	family := FamFamily(use.Kind)
	if family == nil {
		return nil, fmt.Errorf("component selection is not registered for candidate kind %q", use.Kind)
	}
	if use.Components == nil {
		return nil, fmt.Errorf("%s component selection missing", family.Label)
	}
	if use.Components.Failure != "" {
		return nil, fmt.Errorf("%s component coverage: %s", family.Label, use.Components.Failure)
	}
	current, err := Select(use)
	if err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(current, use.Components) {
		return nil, fmt.Errorf("%s component selection is stale or conflicts with candidate facts", family.Label)
	}
	m, err := embedded.material(family, current)
	if err != nil {
		return nil, err
	}
	if family.RequiresAPI {
		if !reflect.DeepEqual(m.Contract, use.APIModel) {
			return nil, fmt.Errorf("selected %s contract conflicts with verified operation model", family.Label)
		}
	} else if family.Name == "xss" {
		m.Contract = XSSContract(use.APIModel.ID, use.APIModel.Library)
		if !reflect.DeepEqual(m.Contract, use.APIModel) {
			return nil, fmt.Errorf("selected XSS rendering contract conflicts with facts")
		}
	} else if family.ObservationOnly {
		if m.Contract != nil {
			m.Contract.Library = use.APIModel.Library
		}
		if !reflect.DeepEqual(m.Contract, use.APIModel) {
			return nil, fmt.Errorf("outbound contract conflicts with facts")
		}
	} else if m.Contract != nil {
		return nil, fmt.Errorf("%s selection must not carry an API contract", family.Label)
	}
	return m, nil
}

func (c *catalog) material(family *Family, s *analysis.ComponentSelection) (*Material, error) {
	if len(s.Components) > MaxComponents {
		return nil, fmt.Errorf("%s component count exceeds limit", family.Label)
	}
	m := &Material{Selection: s}
	size := 0
	var rendering []string
	for _, ref := range s.Components {
		v, ok := c.components[ref.ID]
		if !ok || ref != c.refs[ref.ID] {
			return nil, fmt.Errorf("%s component incompatible: %s", family.Label, ref.ID)
		}
		size += len(v.Material)
		if size > MaxMaterialBytes {
			return nil, fmt.Errorf("%s interpretation material exceeds %d byte limit", family.Label, MaxMaterialBytes)
		}
		switch v.Kind {
		case "rendering_contract", "xss_interpretation", "input_interpretation":
			rendering = append(rendering, v.Material)
		case "claim_questions":
			questions, choices, err := c.claimQuestions(family)
			if err != nil {
				return nil, err
			}
			m.Questions = questions
			m.Choices = choices
		case "language_guidance":
			if family.ObservationOnly {
				continue
			}
			if err := decode(v.Material, &m.Guidelines); err != nil {
				return nil, err
			}
		case "api_contract":
			var contract analysis.APIModel
			if err := decode(v.Material, &contract); err != nil {
				return nil, err
			}
			m.Contract = &contract
		}
	}
	// Required material is defined by the registered question protocol, not a
	// universal count. API contracts belong to query families only.
	if family.ObservationOnly {
		if len(m.Questions) != 0 {
			return nil, fmt.Errorf("observation cannot contain questions")
		}
		return m, nil
	}
	if m.Guidelines.Body == "" || len(m.Questions) != len(family.QuestionNames) {
		return nil, fmt.Errorf("%s required material missing", family.Label)
	}
	if !family.RequiresAPI && m.Contract != nil {
		return nil, fmt.Errorf("%s material must not include an API contract", family.Label)
	}
	if family.RequiresAPI && m.Contract == nil {
		return nil, fmt.Errorf("%s required operation contract missing", family.Label)
	}
	for _, text := range rendering {
		m.Guidelines.Body += "\n\n" + text
	}
	return m, nil
}

func decode(s string, v any) error { return json.Unmarshal([]byte(s), v) }
