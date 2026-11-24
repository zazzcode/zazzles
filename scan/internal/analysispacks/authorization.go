package analysispacks

import "github.com/zazzcode/zazzles/scan/internal/analysis"

// AuthorizationProtocol versions the authorization claim questions (D-13).
// v2 let a role every signed-in user holds cover a request-selected
// object-level write. v3 said listed roles alone never cover such a write or
// delete, which also rejected a role only some users hold. v4 judges a role by
// who holds it: one every signed-in user holds is inadequate, one only some
// users hold is adequate unless a peer writer needs a role the entry lacks. v5
// aligns the judge instruction with the v4 question prose. v6 adds the
// written_values fact of an update and says what it means.
const AuthorizationProtocol = "authorization-components-v6"

// PHPAuthorizationOperation is the verified operation this family judges.
const PHPAuthorizationOperation = "php-authorization-operation-v1"

// NodeAuthorizationOperation is the verified operation set of the Node.js
// adapter: a Sequelize write with a where selector, an instance write on a
// found record, and a Mongo-style collection update or remove.
const NodeAuthorizationOperation = "node-authorization-operation-v1"

var authorizationContracts = []string{PHPAuthorizationOperation, NodeAuthorizationOperation}

// AuthorizationRoles are the evidence obligations of D-13.
func AuthorizationRoles() []string {
	return []string{"subject_selection", "protected_operation", "entry_access", "control_flow"}
}

// AuthorizationContract returns the semantics of one protected operation.
func AuthorizationContract(id string) *analysis.APIModel {
	if id == NodeAuthorizationOperation {
		return &analysis.APIModel{ID: id, Library: "node", Reference: "https://sequelize.org/docs/v6/core-concepts/model-querying-basics/",
			Semantics: "An authorization candidate is one protected operation: a Sequelize Model.update, destroy, increment or decrement, which acts on every row its where option matches; an update, destroy or save on an instance that findByPk or findOne returned; or an update or remove on a Mongo-style collection, which acts on every document its selector matches. The scanner records the subject (the model or collection and the keys that select the record), the operation, the entry's access and the conditions that dominate the operation. It does not decide that a condition or an access record is enough."}
	}
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
		{"access_adequacy", "Is the entry's recorded access enough for the fields in security_fields and the operation, given peer_access (adequate, inadequate, unknown)? When authentication is none, answer inadequate. Required roles are adequate for data_exposure of census fields. For an object_level or function_level write or delete on a request_selected subject, judge the listed roles by who holds them. A role every signed-in user holds (ROLE_USER, which Symfony's user contract gives every user, or an IS_AUTHENTICATED_* attribute) is inadequate: any user can pick another user's record. A role that only some users hold is adequate unless peer_access shows another writer of the same key that requires a role this entry does not."},
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
			[2]string{"adequate", "Authentication is required with listed roles that cover a census-field read, or with a role only some users hold for a request-selected write or delete, and no peer writer of the same key requires a role this entry lacks."},
			[2]string{"inadequate", "Authentication is none, or the only listed role is one every signed-in user holds for a request-selected write or delete, or a peer writer of the same key requires a role this entry lacks."},
			[2]string{"unknown", "The supplied evidence does not establish whether the entry's access is enough."},
		)
	}
	return nil
}
