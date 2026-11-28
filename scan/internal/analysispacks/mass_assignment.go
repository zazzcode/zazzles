package analysispacks

import "github.com/zazzcode/zazzles/scan/internal/analysis"

// MassAssignmentProtocol versions the mass-assignment claim questions.
const MassAssignmentProtocol = "mass-assignment-components-v1"

// MassAssignmentProtocolV2 is the protocol of a record whose census carries an
// owner_reference field (detection generalization 22). Only the field_impact
// text differs from v1; every other record keeps v1.
const MassAssignmentProtocolV2 = "mass-assignment-components-v2"

// ownerReferenceText is appended to the field_impact question of v2.
const ownerReferenceText = " An owner_reference field is the foreign key of a declared association to the account model, from the association contract; a request that chooses it chooses whose record is written."

// MassAssignmentOwnerReference reports a mass-assignment use whose census holds
// a field with the owner_reference role.
func MassAssignmentOwnerReference(u analysis.CandidateUse) bool {
	if u.MassAssignment == nil {
		return false
	}
	for _, f := range u.MassAssignment.SecurityFields {
		for _, r := range f.Roles {
			if r == analysis.RoleOwnerReference {
				return true
			}
		}
	}
	return false
}

// MassAssignmentQuestionsV2 returns the v1 questions with the v2 field_impact
// text. The names and choices equal v1.
func MassAssignmentQuestionsV2() []Question {
	items := MassAssignmentQuestions()
	for i := range items {
		if items[i].Name == "field_impact" {
			items[i].Instructions += ownerReferenceText
		}
	}
	return items
}

// MassAssignmentRoles are the evidence obligations of the key-controlled write
// claim (D-13).
func MassAssignmentRoles() []string {
	return []string{"input_source", "key_origin", "property_write", "target_class", "control_flow"}
}

func massAssignmentQuestionNames() []string {
	return []string{"key_control", "key_restriction", "field_impact"}
}

// MassAssignmentQuestions returns the family's questions in protocol order (D-13).
func MassAssignmentQuestions() []Question {
	return []Question{
		{"key_control", "Does the request choose which properties are written, as the key origin and use.mass_assignment.shape state (request_chosen, fixed, unknown)? A key bound from iterating a whole request bag is request-chosen."},
		{"key_restriction", "Do the recorded use.mass_assignment.key_guards limit the names to a set that excludes the fields the request should not choose (none, adequate, inadequate, unknown)? A key_existence_check such as property_exists restricts nothing. Answer none when no key guard is recorded."},
		{"field_impact", "Does the target class have a field the request should not choose, judged from use.mass_assignment.security_fields and the listed mapped_fields (privileged_field, no_sensitive_field, unknown)? credential, login_identifier and role_source roles come from framework contracts; a name_hint role is a hint from the field name only and must be weighed, not trusted."},
	}
}

// MassAssignmentChoices lists the accepted answers for a mass-assignment question.
func MassAssignmentChoices(question string) []map[string]string {
	switch question {
	case "key_control":
		return choicePairs(
			[2]string{"request_chosen", "The request chooses the property names written."},
			[2]string{"fixed", "The written property names are fixed by the code."},
			[2]string{"unknown", "The origin of the property names is not established."},
		)
	case "key_restriction":
		return choicePairs(
			[2]string{"none", "No recorded guard limits the names."},
			[2]string{"adequate", "A recorded key allow-list excludes every field the request should not choose."},
			[2]string{"inadequate", "A recorded guard leaves a field the request should not choose writable."},
			[2]string{"unknown", "The effect of the recorded guards is not established."},
		)
	case "field_impact":
		return choicePairs(
			[2]string{"privileged_field", "The target has a field the request should not choose."},
			[2]string{"no_sensitive_field", "No field of the target needs protection from the request."},
			[2]string{"unknown", "The target's fields are not established."},
		)
	}
	return nil
}
