package analysis

import (
	"fmt"
	"slices"
	"strings"
)

// DeserializationKind is the claim kind of a verified deserializer call.
const DeserializationKind = "deserialization_candidate"

// Capabilities state what the verified operation's format can build. They are
// contract facts read from the operation and its options.
const (
	DeserializationCodeExecution   = "code_execution"
	DeserializationObjectInjection = "object_injection"
	DeserializationRestrictedTypes = "restricted_types"
	DeserializationUnresolved      = "unresolved"
)

// Control kinds classify a recorded guard or restriction. The kind names what
// the control is, never whether it is adequate.
const (
	DeserializationIntegrity   = "integrity_check"
	DeserializationUnkeyedHash = "unkeyed_hash"
	DeserializationClassList   = "class_allow_list"
	DeserializationFormat      = "format_check"
)

// DeserializationFacts records the verified operation and paths to its data operand.
type DeserializationFacts struct {
	Operation  string                   `json:"operation"`
	ContractID string                   `json:"contract_id"`
	Capability string                   `json:"capability"`
	Option     string                   `json:"option,omitempty"`
	OptionGap  string                   `json:"option_gap,omitempty"`
	Version    string                   `json:"version,omitempty"`
	Controls   []DeserializationControl `json:"controls,omitempty"`
	Paths      []CommandPath            `json:"paths"`
}

// DeserializationControl references one piece of context evidence by index.
type DeserializationControl struct {
	Kind    string `json:"kind"`
	Context int    `json:"context"`
}

// Validate rejects a record whose operation, capability, option gap,
// controls or operand paths are malformed.
func (f *DeserializationFacts) Validate(deps, context int) error {
	if f == nil || f.Operation == "" || f.ContractID == "" {
		return fmt.Errorf("missing deserialization operation or contract")
	}
	switch f.Capability {
	case DeserializationCodeExecution, DeserializationObjectInjection, DeserializationRestrictedTypes, DeserializationUnresolved:
	default:
		return fmt.Errorf("invalid deserialization capability")
	}
	if (f.Capability == DeserializationUnresolved) != (f.OptionGap != "") ||
		f.OptionGap != "" && f.OptionGap != "loader_unresolved" && f.OptionGap != "version_unknown" {
		return fmt.Errorf("invalid deserialization option gap")
	}
	for _, control := range f.Controls {
		switch control.Kind {
		case DeserializationIntegrity, DeserializationUnkeyedHash, DeserializationClassList, DeserializationFormat:
		default:
			return fmt.Errorf("invalid deserialization control kind")
		}
		if control.Context < 0 || control.Context >= context {
			return fmt.Errorf("invalid deserialization control index")
		}
	}
	return validateInterpreterPaths(f.Paths, "data", deps, context)
}

// AddDeserializationClassRestriction cites an explicit restriction on every data path.
func (u *CandidateUse) AddDeserializationClassRestriction(e Evidence) {
	f := u.Deserialization
	index := len(u.Context)
	f.Controls = append(f.Controls, DeserializationControl{Kind: DeserializationClassList, Context: index})
	for i := range f.Paths {
		p := &f.Paths[i]
		p.Controls = append(p.Controls, index)
		p.Protection = "guarded"
		p.Reason = "A class restriction applies to this operand; its adequacy requires assessment."
	}
	u.Context = append(u.Context, e)
	u.Completeness.Evidence["guard"] = append(u.Completeness.Evidence["guard"], e)
	// The serialized facts carry the updated protection. The shared path
	// summary was built before the class restriction was added.
	u.Completeness.ModelFacts = slices.DeleteFunc(u.Completeness.ModelFacts, func(fact string) bool {
		return strings.HasPrefix(fact, "Operand path facts: ")
	})
}

// NoteDeserializationOrigin records when an operand has no request witness.
func (u *CandidateUse) NoteDeserializationOrigin() {
	for _, d := range u.Dependencies {
		if d.Source.Kind == "input_source" {
			return
		}
	}
	u.Gaps = append(u.Gaps, Gap{
		Kind: "deserialization_origin_unresolved", Detail: "A request origin for the data operand is missing.", At: u.Sink.Span,
	})
}
