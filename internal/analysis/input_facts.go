package analysis

import "fmt"

// InputFacts separates acquisition/transform facts from any downstream sink
// contract or security verdict. Missing runtime types remain explicit unknowns.
type InputFacts struct {
	Version     int              `json:"version"`
	Acquisition string           `json:"acquisition"`
	Framework   string           `json:"framework,omitempty"`
	Binding     Evidence         `json:"binding"`
	Values      []InputValueFact `json:"values"`
	Stages      []InputStage     `json:"stages,omitempty"`
	Controls    []Evidence       `json:"controls,omitempty"`
	Gaps        []Gap            `json:"gaps,omitempty"`
}
type InputValueFact struct {
	Dependency  int        `json:"dependency"`
	Origin      string     `json:"origin"`
	InitialType string     `json:"initial_type"`
	SinkType    string     `json:"sink_type"`
	Source      Evidence   `json:"source"`
	Transfers   []Evidence `json:"transfers,omitempty"`
}

func (f *InputFacts) Validate(deps []Dependency) error {
	if f == nil {
		return nil
	}
	if f.Version != 1 || f.Acquisition == "" || f.Binding.SHA256 == "" || f.Binding.Span.File == "" {
		return fmt.Errorf("invalid input-fact version or framework binding")
	}
	seen := map[int]bool{}
	for _, v := range f.Values {
		if v.Dependency < 0 || v.Dependency >= len(deps) || seen[v.Dependency] {
			return fmt.Errorf("invalid input dependency index")
		}
		seen[v.Dependency] = true
		d := deps[v.Dependency]
		if v.Source != d.Source {
			return fmt.Errorf("input fact source does not match dependency")
		}
		if len(v.Transfers) != len(d.Transfers) {
			return fmt.Errorf("input facts omit or add a transfer")
		}
		for i, e := range v.Transfers {
			if e != d.Transfers[i] {
				return fmt.Errorf("input transfer does not match dependency")
			}
		}
		if v.Origin == "" || !inputType(v.InitialType) || !inputType(v.SinkType) {
			return fmt.Errorf("invalid input origin/type")
		}
	}
	if len(seen) != len(deps) {
		return fmt.Errorf("input facts omit a dependency")
	}
	return nil
}
func inputType(t string) bool {
	switch t {
	case "unknown", "string", "number", "boolean", "object", "array", "null":
		return true
	}
	return false
}

// ScalarInputs reports positive evidence on every current operand, never an
// initial transport type that was subsequently transformed or replaced.
func (f *InputFacts) ScalarInputs() bool {
	if f == nil || len(f.Values) == 0 || len(f.Gaps) > 0 {
		return false
	}
	for _, v := range f.Values {
		switch v.SinkType {
		case "string", "number", "boolean":
		default:
			return false
		}
	}
	return true
}

// InputStage records acquisition-boundary ordering without defining sink safety.
type InputStage struct {
	Name     string   `json:"name"`
	Order    int      `json:"order"`
	Scope    string   `json:"scope"`
	Evidence Evidence `json:"evidence"`
}

// HasValueControls excludes logging/route options and registrations: their
// presence is not positive evidence of value validation or transformation.
func (f *InputFacts) HasValueControls() bool {
	if f == nil {
		return false
	}
	for _, e := range f.Controls {
		switch e.Kind {
		case "http_hook", "http_schema", "middleware_handler":
			return true
		}
	}
	return false
}
