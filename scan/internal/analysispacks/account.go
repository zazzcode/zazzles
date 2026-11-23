package analysispacks

import "github.com/zazzcode/zazzles/scan/internal/analysis"

// AccountProtocol versions the account claim questions. The
// protocol carries one question set per kind.
const AccountProtocol = "account-components-v2"

// Account operation contracts: the mail sinks and the password digests.
// Enumeration has no operation contract: its record is a finder, a branch
// and two responses.
const (
	SymfonyMailerContract  = "symfony-mailer-v1"
	PHPMailContract        = "php-mail-v1"
	PHPPasswordDigest      = "php-password-digest-v1"
	accountFamilyName      = "account"
	accountEnumerationRole = "account_lookup"
)

var accountContracts = []string{SymfonyMailerContract, PHPMailContract, PHPPasswordDigest}

// PasswordDigestUnmodeled reports a digest algorithm of contract
// php-password-digest-v1 whose parameters are not modeled: crypt and
// hash_pbkdf2 may be iterated. Every other recorded algorithm is one fast
// digest.
func PasswordDigestUnmodeled(algorithm string) bool {
	return algorithm == "crypt" || algorithm == "pbkdf2"
}

// ConfiguredPasswordDigest reports a security.password_hashers algorithm that
// selects a fast digest or no hash.
func ConfiguredPasswordDigest(algorithm string) bool {
	switch algorithm {
	case "md5", "sha1", "sha256", "sha512", "plaintext":
		return true
	}
	return false
}

// AccountRoles are the evidence obligations of one account kind.
func AccountRoles(kind string) []string {
	switch kind {
	case analysis.AccountEnumerationKind:
		return []string{"input_source", accountEnumerationRole, "result_branch", "entry_access"}
	case analysis.RecoveryDeliveryKind:
		return []string{"secret_source", "mail_recipient", "mail_content", "control_flow"}
	case analysis.PasswordHashKind:
		return []string{"digest_operation", "password_basis"}
	}
	return nil
}

// AccountContract returns the semantics of one account operation contract.
func AccountContract(id string) *analysis.APIModel {
	switch id {
	case SymfonyMailerContract:
		return &analysis.APIModel{ID: id, Library: "symfony/mailer", Reference: "https://symfony.com/doc/6.4/mailer.html",
			Semantics: "Symfony\\Component\\Mime\\Email and Symfony\\Bridge\\Twig\\Mime\\TemplatedEmail name recipients with to, addTo, cc, addCc, bcc and addBcc, and carry content in html, text, subject and (TemplatedEmail) context. MailerInterface::send and TransportInterface::send deliver the message to every recipient. Content is delivered to the recipients; it is not rendered by this application."}
	case PHPMailContract:
		return &analysis.APIModel{ID: id, Library: "php", Reference: "https://www.php.net/manual/en/function.mail.php",
			Semantics: "mail(to, subject, message) sends the message to the recipients in argument 1. Arguments 2 and 3 are the subject and the body. The call is the send."}
	case PHPPasswordDigest:
		return &analysis.APIModel{ID: id, Library: "php", Reference: "https://www.php.net/manual/en/function.password-hash.php",
			Semantics: "md5, sha1, crc32, and hash or hash_hmac with a literal algorithm compute one fast digest of their input. A single fast digest is not an adaptive password hash: password_hash, sodium_crypto_pwhash_str and the Symfony password hashers are. crypt and hash_pbkdf2 are recorded but their parameters are not modeled."}
	}
	return nil
}

func accountQuestionNames() []string {
	return []string{"response_difference", "existence_disclosure", "recipient_control", "validation_coverage", "secret_quality", "password_input", "hash_strength"}
}

// accountKindQuestions maps each kind to its question subset, in order.
func accountKindQuestions() map[string][]string {
	return map[string][]string{
		analysis.AccountEnumerationKind: {"response_difference", "existence_disclosure"},
		analysis.RecoveryDeliveryKind:   {"recipient_control", "validation_coverage", "secret_quality"},
		analysis.PasswordHashKind:       {"password_input", "hash_strength"},
	}
}

// AccountQuestions returns every account question in protocol order.
func AccountQuestions() []Question {
	return []Question{
		{"response_difference", "Can a caller tell the enumeration.found response from the enumeration.not_found response (distinguishable, indistinguishable, unknown)? Compare the two recorded response lists with each other: literals, status, redirect target and template."},
		{"existence_disclosure", "Does that difference tell a caller with no login whether an account exists for the value sent (discloses, does_not_disclose, unknown)? Judge from enumeration.lookup, the two response lists and the entry's access."},
		{"recipient_control", "Does the request choose who receives the secret, as recovery.recipient_origin states (request_controlled, account_bound, unknown)?"},
		{"validation_coverage", "Did a check tie every recipient to the account the secret is for, given recovery.recipient_validated and recovery.shape_uses (none, partial, complete, unknown)?"},
		{"secret_quality", "Is the secret unpredictable, given recovery.secret_strength and recovery.secret_bits (adequate, weak, unknown)?"},
		{"password_input", "Is the digest's input a user password, given password_hash.basis and its evidence (password, not_password, unknown)?"},
		{"hash_strength", "Is the stored form a single fast digest, given password_hash.algorithm, salted and iterated (fast_digest, adaptive, unknown)?"},
	}
}

// AccountKindQuestions returns the questions of one kind in protocol order.
func AccountKindQuestions(kind string) []Question {
	names := accountKindQuestions()[kind]
	var out []Question
	for _, q := range AccountQuestions() {
		for _, n := range names {
			if q.Name == n {
				out = append(out, q)
			}
		}
	}
	return out
}

// AccountChoices lists the accepted answers for an account question.
func AccountChoices(question string) []map[string]string {
	switch question {
	case "response_difference":
		return choicePairs(
			[2]string{"distinguishable", "A caller can tell the found response from the not-found response."},
			[2]string{"indistinguishable", "The two responses look the same to a caller."},
			[2]string{"unknown", "The supplied evidence does not establish whether the responses differ to a caller."},
		)
	case "existence_disclosure":
		return choicePairs(
			[2]string{"discloses", "The difference tells a caller with no login whether an account exists for the value sent."},
			[2]string{"does_not_disclose", "The difference does not reveal whether an account exists."},
			[2]string{"unknown", "The supplied evidence does not establish whether existence is disclosed."},
		)
	case "recipient_control":
		return choicePairs(
			[2]string{"request_controlled", "The request chooses who receives the secret."},
			[2]string{"account_bound", "The secret goes only to an address stored for the account."},
			[2]string{"unknown", "The supplied evidence does not establish who chooses the recipient."},
		)
	case "validation_coverage":
		return choicePairs(
			[2]string{"none", "No check ties a recipient to the account."},
			[2]string{"partial", "A check covered some recipients or one element, not every recipient."},
			[2]string{"complete", "A check tied every recipient to the account the secret is for."},
			[2]string{"unknown", "The supplied evidence does not establish the check's coverage."},
		)
	case "secret_quality":
		return choicePairs(
			[2]string{"adequate", "The secret comes from a cryptographically secure source."},
			[2]string{"weak", "The secret is predictable or guessable."},
			[2]string{"unknown", "The supplied evidence does not establish the secret's quality."},
		)
	case "password_input":
		return choicePairs(
			[2]string{"password", "The digest input is a user password."},
			[2]string{"not_password", "The digest input is not a password."},
			[2]string{"unknown", "The supplied evidence does not establish whether the input is a password."},
		)
	case "hash_strength":
		return choicePairs(
			[2]string{"fast_digest", "The stored form is one fast digest, salted or not."},
			[2]string{"adaptive", "The stored form comes from an adaptive, iterated password hash."},
			[2]string{"unknown", "The supplied evidence does not establish the hash strength."},
		)
	}
	return nil
}
