package analysis

import (
	"fmt"
	"slices"
)

// MassAssignmentKind is the claim kind of a write whose property names the
// request chooses on an object (CWE-915).
const MassAssignmentKind = "mass_assignment_candidate"

// Mass-assignment shapes: the rows of branch 1 D-6.
const (
	MassAssignmentPropertyWrite = "dynamic_property_write"
	MassAssignmentSetterCall    = "dynamic_setter_call"
	MassAssignmentAccessor      = "property_accessor"
	MassAssignmentReflection    = "reflection_property_write"
	MassAssignmentForm          = "form_submission"
	MassAssignmentSerializer    = "serializer_population"
	MassAssignmentPayload       = "request_payload_mapping"
)

// Key guard kinds classify a recorded restriction on the request-chosen names.
// The kind names what the control is, never whether it is adequate.
const (
	KeyAllowList      = "key_allow_list"
	KeyExistenceCheck = "key_existence_check"
)

// Security-field census roles (lane contract section 2.3).
const (
	RoleCredential      = "credential"
	RoleLoginIdentifier = "login_identifier"
	RoleSource          = "role_source"
	RoleNameHint        = "name_hint"
)

// Gaps of the framework shapes this version records but does not judge, and
// of a census that cannot be resolved.
const (
	MassAssignmentFormUnmodeled       = "mass_assignment_form_unmodeled"
	MassAssignmentSerializerUnmodeled = "mass_assignment_serializer_unmodeled"
	MassAssignmentPayloadUnmodeled    = "mass_assignment_payload_unmodeled"
	SecurityFieldsUnresolved          = "security_fields_unresolved"
)

// SecurityField is one stored field and the roles source evidence establishes
// for it, with one evidence item per role at the establishing source.
type SecurityField struct {
	StorageKey string     `json:"storage_key"`
	Roles      []string   `json:"roles"`
	Evidence   []Evidence `json:"evidence"`
}

// MassAssignmentFacts records a key-controlled write, its target and the
// census roles of the target's fields (D-9).
type MassAssignmentFacts struct {
	Shape          string          `json:"shape"`
	TargetClass    string          `json:"target_class"`
	TargetStored   string          `json:"target_stored"`
	KeyGuards      []Evidence      `json:"key_guards,omitempty"`
	SecurityFields []SecurityField `json:"security_fields"`
	// MappedFields lists the target's mapped or declared properties, so a
	// field without a census role is still visible to the decision model.
	MappedFields []string `json:"mapped_fields,omitempty"`
}

// MassAssignmentShapes lists the shapes in D-6 order.
func MassAssignmentShapes() []string {
	return []string{MassAssignmentPropertyWrite, MassAssignmentSetterCall, MassAssignmentAccessor, MassAssignmentReflection, MassAssignmentForm, MassAssignmentSerializer, MassAssignmentPayload}
}

// Validate rejects a record whose shape, storage fact, guards or census roles
// are outside the closed lists.
func (f *MassAssignmentFacts) Validate() error {
	if f == nil || f.TargetClass == "" {
		return fmt.Errorf("missing mass-assignment target")
	}
	if !slices.Contains(MassAssignmentShapes(), f.Shape) {
		return fmt.Errorf("invalid mass-assignment shape")
	}
	switch f.TargetStored {
	case "yes", "no", "unresolved":
	default:
		return fmt.Errorf("invalid mass-assignment target_stored")
	}
	for _, g := range f.KeyGuards {
		if g.Kind != KeyAllowList && g.Kind != KeyExistenceCheck {
			return fmt.Errorf("invalid mass-assignment key guard kind")
		}
	}
	for _, field := range f.SecurityFields {
		if field.StorageKey == "" || len(field.Roles) == 0 || len(field.Evidence) != len(field.Roles) {
			return fmt.Errorf("invalid security field")
		}
		for _, role := range field.Roles {
			switch role {
			case RoleCredential, RoleLoginIdentifier, RoleSource, RoleNameHint:
			default:
				return fmt.Errorf("invalid security field role")
			}
		}
	}
	return nil
}

// HasKeyGuard reports a recorded key guard of the given kind.
func (f *MassAssignmentFacts) HasKeyGuard(kind string) bool {
	return f != nil && slices.ContainsFunc(f.KeyGuards, func(e Evidence) bool { return e.Kind == kind })
}
