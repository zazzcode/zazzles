package judge

import (
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
)

// applyAccountPolicy follows the shared policy order (protocol, evidence,
// answer consistency, blocking gaps, then the status rules) with one rule
// table per kind.
func applyAccountPolicy(use analysis.CandidateUse, a *analysis.Assessment) {
	a.FindingStatus, a.Protection = "needs_evidence", "uncertain"
	gap := func(kind, detail string) {
		a.Reason = detail
		a.BlockingGaps = append(a.BlockingGaps, analysis.Gap{Kind: "account_" + kind, Detail: detail, At: use.Sink.Span})
	}
	if a.QuestionVersion != analysispacks.AccountProtocol {
		gap("protocol_missing", "Versioned account answers are required.")
		return
	}
	c := use.Completeness
	claim, validate := accountClaim(use)
	if claim == "" || c == nil || c.ClaimKind != claim || !accountContractOK(use) {
		gap("claim_missing", "Account claims require source-backed facts, completeness and, for mail and digests, the operation contract.")
		return
	}
	if err := validate(); err != nil {
		gap("facts_invalid", err.Error())
		return
	}
	for _, role := range append(analysispacks.AccountRoles(use.Kind), c.Required...) {
		if len(c.Evidence[role]) == 0 {
			gap("evidence_missing", "Missing account evidence role "+role+".")
			return
		}
	}
	switch use.Kind {
	case analysis.AccountEnumerationKind:
		enumerationPolicy(use, a, gap)
	case analysis.RecoveryDeliveryKind:
		recoveryPolicy(use, a, gap)
	case analysis.PasswordHashKind:
		passwordHashPolicy(use, a, gap)
	}
}

func accountClaim(use analysis.CandidateUse) (string, func() error) {
	switch use.Kind {
	case analysis.AccountEnumerationKind:
		if use.Enumeration != nil {
			return "account_enumeration", use.Enumeration.Validate
		}
	case analysis.RecoveryDeliveryKind:
		if use.Recovery != nil {
			return "recovery_delivery", use.Recovery.Validate
		}
	case analysis.PasswordHashKind:
		if use.PasswordHash != nil {
			return "password_hash", use.PasswordHash.Validate
		}
	}
	return "", nil
}

func accountContractOK(use analysis.CandidateUse) bool {
	switch use.Kind {
	case analysis.AccountEnumerationKind:
		return use.APIModel == nil
	case analysis.RecoveryDeliveryKind:
		return use.APIModel != nil && (use.APIModel.ID == analysispacks.SymfonyMailerContract || use.APIModel.ID == analysispacks.PHPMailContract) && use.Recovery != nil && use.Recovery.MailContract == "api."+use.APIModel.ID
	case analysis.PasswordHashKind:
		return use.APIModel != nil && (use.APIModel.ID == analysispacks.PHPPasswordDigest || use.APIModel.ID == analysispacks.NodePasswordDigest)
	}
	return false
}

// accountBlocking moves the claim's blocking gaps onto the assessment.
func accountBlocking(use analysis.CandidateUse, a *analysis.Assessment, blocking func(string) bool) bool {
	var out []analysis.Gap
	for _, g := range use.Completeness.Blockers {
		if blocking(g.Kind) {
			out = append(out, g)
		}
	}
	if len(out) == 0 {
		return false
	}
	a.BlockingGaps = append(a.BlockingGaps, out...)
	a.Reason = "Claim-relevant account evidence is incomplete."
	return true
}

func enumerationPolicy(use analysis.CandidateUse, a *analysis.Assessment, gap func(string, string)) {
	f := use.Enumeration
	difference, disclosure := a.Answers["response_difference"], a.Answers["existence_disclosure"]
	if difference == "indistinguishable" && responsesDifferInStatusOrRedirect(f) {
		gap("answers_inconsistent", "indistinguishable contradicts recorded sequences that differ in status or redirect target.")
		return
	}
	if accountBlocking(use, a, enumerationBlocking) {
		return
	}
	if difference == "indistinguishable" || disclosure == "does_not_disclose" {
		a.FindingStatus, a.Protection = "protected_for_claim", "sufficient"
		a.Reason = "The assessment supports that the two responses do not reveal whether an account exists."
		return
	}
	if difference == "distinguishable" && disclosure == "discloses" {
		a.FindingStatus, a.Protection = "confirmed_vulnerability", "insufficient"
		a.Reason = "An entry with no login answers differently when an account exists for the request value."
		return
	}
	a.Reason = "The answers do not establish an existence disclosure or a protection."
}

// enumerationBlocking is response_unresolved and every entry-access gap.
func enumerationBlocking(kind string) bool {
	switch kind {
	case analysis.ResponseUnresolved, "access_rule_unresolved", "access_rule_condition_unmodeled", "voter_unmodeled", "access_expression_unmodeled", "authenticator_unmodeled", "symfony_config_unread":
		return true
	}
	return false
}

func responsesDifferInStatusOrRedirect(f *analysis.EnumerationFacts) bool {
	pick := func(side []analysis.BranchResponse, kind string) []string {
		var out []string
		for _, r := range side {
			if r.Kind == kind {
				out = append(out, r.Literal)
			}
		}
		return out
	}
	for _, kind := range []string{analysis.ResponseStatus, analysis.ResponseRedirect} {
		a, b := pick(f.Found, kind), pick(f.NotFound, kind)
		if len(a) != len(b) {
			return true
		}
		for i := range a {
			if a[i] != b[i] {
				return true
			}
		}
	}
	return false
}

func recoveryPolicy(use analysis.CandidateUse, a *analysis.Assessment, gap func(string, string)) {
	f := use.Recovery
	control, coverage, quality := a.Answers["recipient_control"], a.Answers["validation_coverage"], a.Answers["secret_quality"]
	switch {
	case coverage == "complete" && (f.RecipientValidated == analysis.RecipientPartial || f.RecipientValidated == analysis.RecipientNone):
		gap("answers_inconsistent", "validation_coverage complete contradicts recipient_validated "+f.RecipientValidated+".")
		return
	case quality == "adequate" && f.SecretStrength == analysis.SecretWeak:
		gap("answers_inconsistent", "secret_quality adequate contradicts secret_strength weak.")
		return
	case quality == "weak" && f.SecretStrength == analysis.SecretCSPRNG:
		gap("answers_inconsistent", "secret_quality weak contradicts secret_strength csprng.")
		return
	case quality == "adequate" && f.SecretBits.Known && f.SecretBits.Bits < 64:
		gap("answers_inconsistent", "secret_quality adequate contradicts secret_bits below 64.")
		return
	case control == "account_bound" && f.RecipientOrigin == analysis.RecipientRequestValue:
		gap("answers_inconsistent", "account_bound contradicts a recipient that is a request value.")
		return
	}
	// Recovery has no kind-specific blocking gap.
	if coverage == "complete" && quality == "adequate" {
		a.FindingStatus, a.Protection = "protected_for_claim", "sufficient"
		a.Reason = "The assessment supports that every recipient is tied to the account and the secret is unpredictable."
		return
	}
	if control == "request_controlled" && (coverage == "none" || coverage == "partial") || quality == "weak" {
		a.FindingStatus, a.Protection = "confirmed_vulnerability", "insufficient"
		a.Reason = "A recovery secret reaches recipients the request chooses beyond what a check covered, or the secret is guessable."
		return
	}
	a.Reason = "The answers do not establish a weak recovery delivery or a protection."
}

func passwordHashPolicy(use analysis.CandidateUse, a *analysis.Assessment, gap func(string, string)) {
	f := use.PasswordHash
	input, strength := a.Answers["password_input"], a.Answers["hash_strength"]
	if strength == "adaptive" && f.Algorithm != "" && !analysispacks.PasswordDigestUnmodeled(f.Algorithm) && f.Iterated == "no" {
		gap("answers_inconsistent", "adaptive contradicts a single call of a fast digest.")
		return
	}
	if accountBlocking(use, a, func(kind string) bool { return kind == analysis.PasswordDigestUnmodeled }) {
		return
	}
	if input == "not_password" {
		a.FindingStatus, a.Protection = "protected_for_claim", "sufficient"
		a.Reason = "The assessment supports that the digest input is not a password."
		return
	}
	if input == "password" && strength == "fast_digest" {
		a.FindingStatus, a.Protection = "confirmed_vulnerability", "insufficient"
		a.Reason = "A password is stored as one fast digest."
		return
	}
	a.Reason = "The answers do not establish a weak password hash or a protection."
}

func wireEnumeration(use analysis.CandidateUse, ref func(analysis.Evidence) string) any {
	f := use.Enumeration
	if f == nil {
		return nil
	}
	responses := func(side []analysis.BranchResponse) []map[string]any {
		out := make([]map[string]any, 0, len(side))
		for _, r := range side {
			item := map[string]any{"kind": r.Kind, "line": r.Span.StartLine}
			if r.Literal != "" {
				item["literal"] = r.Literal
			}
			out = append(out, item)
		}
		return out
	}
	out := map[string]any{
		"lookup": map[string]any{"class": f.Lookup.Class, "method": f.Lookup.Method, "criteria_fields": f.Lookup.CriteriaFields,
			"evidence": ref(f.Lookup.Evidence), "branch": ref(f.Lookup.Branch)},
		"found": responses(f.Found), "not_found": responses(f.NotFound), "security_fields": wireFields(f.SecurityFields, ref),
	}
	if use.EntryFacts != nil && use.EntryFacts.Access != nil {
		out["access"] = use.EntryFacts.Access
	} else if use.EntryFacts != nil && use.EntryFacts.HTTP != nil && use.EntryFacts.HTTP.Framework == "express" {
		// An Express entry whose chain holds no authentication middleware stores
		// no access record (authentication none); the request still states it.
		out["access"] = analysis.EntryAccess{Authentication: analysis.AccessNone, Sources: []analysis.Evidence{}}
	}
	return out
}

func wireRecovery(f *analysis.RecoveryFacts, ref func(analysis.Evidence) string) any {
	if f == nil {
		return nil
	}
	uses := make([]string, 0, len(f.ShapeUses))
	for _, e := range f.ShapeUses {
		uses = append(uses, ref(e))
	}
	out := map[string]any{"secret_source": ref(f.SecretSource), "secret_strength": f.SecretStrength, "secret_bits": f.SecretBits, "recipient": ref(f.Recipient),
		"recipient_origin": f.RecipientOrigin, "recipient_validated": f.RecipientValidated, "recipient_count": f.RecipientCount,
		"shape_uses": uses, "content": ref(f.Content), "mail_contract": f.MailContract, "security_fields": wireFields(f.SecurityFields, ref)}
	if f.StoredField != "" {
		out["stored_field"] = f.StoredField
	}
	return out
}

func wirePasswordHash(f *analysis.PasswordHashFacts, ref func(analysis.Evidence) string) any {
	if f == nil {
		return nil
	}
	basis := make([]string, 0, len(f.BasisEvidence))
	for _, e := range f.BasisEvidence {
		basis = append(basis, ref(e))
	}
	out := map[string]any{"algorithm": f.Algorithm, "basis": f.Basis, "basis_evidence": basis, "salted": f.Salted, "iterated": f.Iterated,
		"security_fields": wireFields(f.SecurityFields, ref)}
	if f.HasherClass != "" {
		out["hasher_class"] = f.HasherClass
	}
	return out
}

func wireFields(fields []analysis.SecurityFieldFact, ref func(analysis.Evidence) string) []map[string]any {
	out := make([]map[string]any, 0, len(fields))
	for _, s := range fields {
		evidence := make([]string, 0, len(s.Evidence))
		for _, e := range s.Evidence {
			evidence = append(evidence, ref(e))
		}
		out = append(out, map[string]any{"storage_key": s.StorageKey, "roles": s.Roles, "evidence": evidence})
	}
	return out
}
