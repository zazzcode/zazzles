package analysispacks

import "github.com/zazzcode/zazzles/scan/internal/analysis"

// AuthorizationProtocol versions the authorization claim questions (D-13).
const AuthorizationProtocol = "authorization-components-v1"

// PHPAuthorizationOperation is the verified operation this family judges.
const PHPAuthorizationOperation = "php-authorization-operation-v1"

var authorizationContracts = []string{PHPAuthorizationOperation}

// AuthorizationRoles are the evidence obligations of D-13.
func AuthorizationRoles() []string {
	return []string{"subject_selection", "protected_operation", "entry_access", "control_flow"}
}

// AuthorizationContract returns the semantics of one protected operation.
func AuthorizationContract(id string) *analysis.APIModel {
	if id != PHPAuthorizationOperation {
		return nil
	}
	return &analysis.APIModel{ID: id, Library: "php", Reference: "https://symfony.com/doc/current/security.html",
		Semantics: "An authorization candidate is one protected operation: a stored write, file write or delete, or a response that carries a census field of a record. The scanner records the subject, the operation, the entry's access rule and the guards that dominate the operation. It does not decide that a guard or a role is enough."}
}

func authorizationQuestionNames() []string {
	return []string{"subject_control", "guard_adequacy", "access_adequacy"}
}

// AuthorizationQuestions returns the family's questions in protocol order.
func AuthorizationQuestions() []Question {
	return []Question{
		{"subject_control", "Does the request choose which record the operation acts on, or which records are returned, as authorization.subject states (request_selected, not_selected, unknown)?"},
		{"guard_adequacy", "Do the recorded authorization.guards, judged by kind, limit the operation to a caller who should be allowed to perform it on this record (none, adequate, inadequate, unknown)? An address_check is a property of the connection, not of the user."},
		{"access_adequacy", "Is the entry's recorded access enough for the fields in security_fields and the operation, given peer_access (adequate, inadequate, unknown)?"},
	}
}

// AuthorizationChoices lists the accepted answers for an authorization question.
func AuthorizationChoices(question string) []map[string]string {
	switch question {
	case "subject_control":
		return choicePairs(
			[2]string{"request_selected", "The request chooses the record or the set of records the operation returns."},
			[2]string{"not_selected", "The request does not choose the record."},
			[2]string{"unknown", "The supplied evidence does not establish whether the request chooses the record."},
		)
	case "guard_adequacy":
		return choicePairs(
			[2]string{"none", "No guard is recorded on the operation."},
			[2]string{"adequate", "A recorded guard limits the operation to a caller who should be allowed to perform it on this record."},
			[2]string{"inadequate", "A recorded guard does not limit the operation to such a caller."},
			[2]string{"unknown", "The supplied evidence does not establish whether a recorded guard is enough."},
		)
	case "access_adequacy":
		return choicePairs(
			[2]string{"adequate", "The entry's recorded access is enough for the fields and the operation."},
			[2]string{"inadequate", "The entry's recorded access is not enough for the fields and the operation."},
			[2]string{"unknown", "The supplied evidence does not establish whether the entry's access is enough."},
		)
	}
	return nil
}
