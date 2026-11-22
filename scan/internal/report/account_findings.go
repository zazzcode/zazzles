package report

import (
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
)

// accountFindingTypes are listed only when a record of their kind is present.
var accountFindingTypes = []analysis.FindingType{
	{ID: "account-enumeration", Label: "Account Enumeration", Coverage: "bounded PHP lookup-branch-response analysis",
		Description:    "An entry that needs no login looks up an account by a request value and answers differently when the account exists (CWE-204).",
		Interpretation: "The record holds the lookup, its result branch and the responses on each side, compared with each other. The scanner does not read meaning into the wording; whether the difference reveals an account is judged. Timing differences are not recorded.",
		Remediation:    "Give the found and not-found branches the same response, and move account-specific messages to a channel the account owner controls."},
	{ID: "weak-password-recovery", Label: "Weak Password Recovery", Coverage: "bounded PHP recovery-secret delivery analysis",
		Description:    "A generated recovery secret is mailed to a recipient the request controls beyond what a check covered, or the secret is guessable (CWE-640, CWE-1287).",
		Interpretation: "The record holds the secret source and its strength, the stored field, the recipient's origin and the checks that tied it to the account. A request value used as an array can name many recipients; a check of one element covers only that element. Mail content is a delivery sink for this claim only.",
		Remediation:    "Send the recovery secret only to the address stored for the account, generate it from a cryptographically secure source, and accept only a scalar identifier from the request."},
	{ID: "weak-password-hash", Label: "Weak Password Hash", Coverage: "bounded PHP password-digest analysis",
		Description:    "A password is stored as one fast digest such as md5 or sha1 (CWE-916).",
		Interpretation: "A password is established by evidence: a census credential field, a password-hasher class or the security configuration. A variable name alone establishes nothing. A salt does not make a fast digest adaptive.",
		Remediation:    "Hash passwords with password_hash or a Symfony password hasher configured with algorithm auto, and rehash stored digests on the next login."},
}

func accountFindingType(u analysis.CandidateUse) string {
	switch u.Kind {
	case analysis.AccountEnumerationKind:
		return "account-enumeration"
	case analysis.RecoveryDeliveryKind:
		return "weak-password-recovery"
	case analysis.PasswordHashKind:
		return "weak-password-hash"
	}
	return ""
}

func accountRule(u analysis.CandidateUse) (string, string) {
	switch u.Kind {
	case analysis.AccountEnumerationKind:
		return "scan/account-enumeration", "CWE-204"
	case analysis.RecoveryDeliveryKind:
		return "scan/weak-password-recovery", "CWE-640"
	}
	return "scan/weak-password-hash", "CWE-916"
}

func accountGuidance(u analysis.CandidateUse) Guidance {
	switch u.Kind {
	case analysis.AccountEnumerationKind:
		return Guidance{Title: "Answer the same way whether or not the account exists", Actions: []string{"Return the same message, status and redirect on the found and not-found branches.", "Tell the account owner by mail instead of telling the caller."}}
	case analysis.RecoveryDeliveryKind:
		return Guidance{Title: "Send recovery secrets only to the stored address", Actions: []string{"Look up the account and mail the secret to the address stored for it, never to a request value.", "Generate the secret with random_bytes and accept a scalar identifier, not an array."}}
	}
	return Guidance{Title: "Store passwords with an adaptive hash", Actions: []string{"Use password_hash or a Symfony password hasher with algorithm auto.", "Rehash existing fast digests when each user next signs in."}}
}

// describeAccount presents an account record and the judged status.
func describeAccount(u analysis.CandidateUse, f *analysis.Finding) {
	a := u.Assessment
	confirmed := a.Status == "completed" && a.QuestionVersion == analysispacks.AccountProtocol && len(a.BlockingGaps) == 0 && a.FindingStatus == "confirmed_vulnerability"
	var review, title, summary, protected, answers string
	switch u.Kind {
	case analysis.AccountEnumerationKind:
		x := u.Enumeration
		review, title = "Account lookup responses need review", "Account enumeration supported by source analysis"
		summary = "An entry with no login answers differently when an account of " + x.Lookup.Class + " exists for the request value (CWE-204)."
		protected = "The assessment supports that the two responses do not reveal whether an account exists."
		answers = "Enumeration assessment: responses " + displayLabel(a.Answers["response_difference"]) + ", disclosure " + displayLabel(a.Answers["existence_disclosure"])
	case analysis.RecoveryDeliveryKind:
		x := u.Recovery
		review, title = "Recovery-secret delivery needs review", "Weak password recovery supported by source analysis"
		summary = "A recovery secret is mailed to recipients the request controls (recipient validation " + displayLabel(x.RecipientValidated) + ") (CWE-640)."
		if x.RecipientValidated == analysis.RecipientPartial {
			summary = "A recovery secret is mailed to every element of a request array while a check covered one element (CWE-640, CWE-1287)."
		} else if x.SecretStrength == analysis.SecretWeak {
			summary = "A recovery secret comes from a predictable source (CWE-640)."
		}
		protected = "The assessment supports that every recipient is tied to the account and the secret is unpredictable."
		answers = "Recovery assessment: recipient " + displayLabel(a.Answers["recipient_control"]) + ", coverage " + displayLabel(a.Answers["validation_coverage"]) + ", secret " + displayLabel(a.Answers["secret_quality"])
	default:
		x := u.PasswordHash
		review, title = "Password digest needs review", "Weak password hash supported by source analysis"
		summary = "A password is stored as one " + x.Algorithm + " digest (CWE-916)."
		protected = "The assessment supports that the digest input is not a password."
		answers = "Password-hash assessment: input " + displayLabel(a.Answers["password_input"]) + ", strength " + displayLabel(a.Answers["hash_strength"])
	}
	if f.Status != "protected_for_claim" {
		f.Title, f.Summary = review, summary
	}
	if confirmed {
		f.RecordType, f.Status = "finding", "confirmed_vulnerability"
		f.Title, f.Summary = title, summary
	} else if f.Status == "protected_for_claim" {
		f.Title, f.Summary = "The account operation is covered for this claim", protected
	}
	if a.Reason != "" {
		f.Protection = answers + ". Scanner policy: " + a.Reason
	}
}
