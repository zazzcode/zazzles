package analysispacks

import "github.com/zazzcode/zazzles/scan/internal/analysis"

// AuthorizationProtocol versions the authorization claim questions (D-13).
// v2 tightens the guard_adequacy and access_adequacy question prose and choices
// after judged controls SYM-AUTHZ-N03 and SYM-AUTHZ-N05 were Confirmed under v1.
const AuthorizationProtocol = "authorization-components-v2"

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
		{"guard_adequacy", "Do the recorded authorization.guards, judged by kind, limit the operation to a caller who should be allowed to perform it on this record (none, adequate, inadequate, unknown)? Answer none only when no guard is recorded. An ownership_check, role_check, authenticated_check or secret_check that dominates this operation on this subject is adequate; a secret_check is a stored-field comparison with a request value not written back on the same path. An address_check is a property of the connection, not of the user."},
		{"access_adequacy", "Is the entry's recorded access enough for the fields in security_fields and the operation, given peer_access (adequate, inadequate, unknown)? When authentication is required and roles are listed, treat that as adequate for census-field reads and deletes under the entry unless peer_access shows the same privilege field under a weaker rule. When authentication is none, answer inadequate."},
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
			[2]string{"adequate", "A recorded ownership_check, role_check, authenticated_check or secret_check dominates this operation on this subject and limits it to an allowed caller."},
			[2]string{"inadequate", "Every recorded guard fails to limit the operation to an allowed caller (including an address_check alone)."},
			[2]string{"unknown", "The supplied evidence does not establish whether a recorded guard is enough."},
		)
	case "access_adequacy":
		return choicePairs(
			[2]string{"adequate", "Authentication is required with listed roles that cover this operation and its security_fields, and peer_access does not show a weaker writer of the same privilege field."},
			[2]string{"inadequate", "Authentication is none, or the recorded roles do not cover this operation given security_fields and peer_access."},
			[2]string{"unknown", "The supplied evidence does not establish whether the entry's access is enough."},
		)
	}
	return nil
}
