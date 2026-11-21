package analysis

import "testing"

func TestDeserializationFacts(t *testing.T) {
	valid := func() DeserializationFacts {
		return DeserializationFacts{
			Operation: "pickle.loads", ContractID: "python-pickle-v1", Capability: DeserializationCodeExecution,
			Controls: []DeserializationControl{{Kind: DeserializationIntegrity, Context: 0}},
			Paths:    []CommandPath{{Dependency: 0, Operand: "data", Protection: "guarded", Controls: []int{0}}},
		}
	}
	for _, capability := range []string{DeserializationCodeExecution, DeserializationObjectInjection, DeserializationRestrictedTypes, DeserializationUnresolved} {
		t.Run(capability, func(t *testing.T) {
			facts := valid()
			facts.Capability = capability
			if capability == DeserializationUnresolved {
				facts.OptionGap = "loader_unresolved"
			}
			if err := facts.Validate(1, 1); err != nil {
				t.Error(err)
			}
		})
	}
	tests := map[string]func(*DeserializationFacts){
		"missing operation":            func(f *DeserializationFacts) { f.Operation = "" },
		"missing contract":             func(f *DeserializationFacts) { f.ContractID = "" },
		"unknown capability":           func(f *DeserializationFacts) { f.Capability = "plain" },
		"unneeded option gap":          func(f *DeserializationFacts) { f.OptionGap = "version_unknown" },
		"missing option gap":           func(f *DeserializationFacts) { f.Capability = DeserializationUnresolved },
		"invalid option gap":           func(f *DeserializationFacts) { f.Capability, f.OptionGap = DeserializationUnresolved, "bad" },
		"invalid control kind":         func(f *DeserializationFacts) { f.Controls[0].Kind = "checksum" },
		"control outside context":      func(f *DeserializationFacts) { f.Controls[0].Context = 1 },
		"invalid protection":           func(f *DeserializationFacts) { f.Paths[0].Protection = "safe" },
		"guard without evidence":       func(f *DeserializationFacts) { f.Paths[0].Controls = nil },
		"path control outside context": func(f *DeserializationFacts) { f.Paths[0].Controls = []int{-1} },
		"duplicate path":               func(f *DeserializationFacts) { f.Paths = append(f.Paths, f.Paths[0]) },
		"missing path":                 func(f *DeserializationFacts) { f.Paths = nil },
		"wrong operand":                func(f *DeserializationFacts) { f.Paths[0].Operand = "code" },
		"wrong dependency":             func(f *DeserializationFacts) { f.Paths[0].Dependency = 1 },
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			facts := valid()
			change(&facts)
			if facts.Validate(1, 1) == nil {
				t.Error("invalid facts accepted")
			}
		})
	}
}
