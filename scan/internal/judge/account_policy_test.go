package judge

import (
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
)

func accountEvidence(line int) analysis.Evidence {
	return analysis.Evidence{Kind: "source", Span: analysis.Span{File: "src/Account.php", StartLine: line, EndLine: line}}
}

func accountPolicyUse(kind string, blockers ...string) analysis.CandidateUse {
	e := accountEvidence(10)
	u := analysis.CandidateUse{ID: "use:account", Kind: kind, Sink: e}
	c := &analysis.Completeness{Evidence: map[string][]analysis.Evidence{}}
	for _, role := range analysispacks.AccountRoles(kind) {
		c.Evidence[role] = []analysis.Evidence{e}
	}
	switch kind {
	case analysis.AccountEnumerationKind:
		c.ClaimKind = "account_enumeration"
		u.Enumeration = &analysis.EnumerationFacts{
			Lookup:   analysis.EnumerationLookup{Class: `App\Entity\Account`, Method: "findOneBy", CriteriaFields: []string{"mail"}, Evidence: e, Branch: accountEvidence(11)},
			Found:    []analysis.BranchResponse{{Kind: analysis.ResponseFlash, Literal: "A"}, {Kind: analysis.ResponseRedirect, Literal: "join"}},
			NotFound: []analysis.BranchResponse{{Kind: analysis.ResponseRedirect, Literal: "home"}},
		}
	case analysis.RecoveryDeliveryKind:
		c.ClaimKind = "recovery_delivery"
		u.APIModel = analysispacks.AccountContract(analysispacks.SymfonyMailerContract)
		u.Recovery = &analysis.RecoveryFacts{SecretSource: e, SecretStrength: analysis.SecretCSPRNG, Recipient: e, RecipientOrigin: analysis.RecipientRequestValue,
			RecipientValidated: analysis.RecipientPartial, RecipientCount: analysis.RecipientCountRequest, ShapeUses: []analysis.Evidence{e, accountEvidence(20)},
			Content: e, MailContract: "api." + analysispacks.SymfonyMailerContract}
	case analysis.PasswordHashKind:
		c.ClaimKind = "password_hash"
		u.APIModel = analysispacks.AccountContract(analysispacks.PHPPasswordDigest)
		u.PasswordHash = &analysis.PasswordHashFacts{Algorithm: "md5", Basis: analysis.BasisCredentialField, BasisEvidence: []analysis.Evidence{e}, Salted: "no", Iterated: "no"}
	}
	for _, g := range blockers {
		c.Blockers = append(c.Blockers, analysis.Gap{Kind: g, At: e.Span})
	}
	u.Completeness = c
	return u
}

// One row per rule of the three kind tables, plus the shared policy order.
func TestAccountPolicy(t *testing.T) {
	enum, rec, hash := analysis.AccountEnumerationKind, analysis.RecoveryDeliveryKind, analysis.PasswordHashKind
	same := func(u analysis.CandidateUse) analysis.CandidateUse {
		u.Enumeration.NotFound = append([]analysis.BranchResponse{}, u.Enumeration.Found...)
		return u
	}
	for _, tt := range []struct {
		rule, kind, version string
		answers             map[string]string
		change              func(analysis.CandidateUse) analysis.CandidateUse
		blockers            []string
		status, gap         string
	}{
		// Shared order.
		{"protocol", enum, "account-components-v0", map[string]string{"response_difference": "distinguishable", "existence_disclosure": "discloses"}, nil, nil, "needs_evidence", "account_protocol_missing"},
		{"claim", rec, "", map[string]string{"recipient_control": "request_controlled", "validation_coverage": "partial", "secret_quality": "adequate"}, func(u analysis.CandidateUse) analysis.CandidateUse {
			u.Completeness.ClaimKind = "injection"
			return u
		}, nil, "needs_evidence", "account_claim_missing"},
		{"facts", hash, "", map[string]string{"password_input": "password", "hash_strength": "fast_digest"}, func(u analysis.CandidateUse) analysis.CandidateUse {
			u.PasswordHash.Basis = "name"
			return u
		}, nil, "needs_evidence", "account_facts_invalid"},
		{"evidence", enum, "", map[string]string{"response_difference": "distinguishable", "existence_disclosure": "discloses"}, func(u analysis.CandidateUse) analysis.CandidateUse {
			delete(u.Completeness.Evidence, "entry_access")
			return u
		}, nil, "needs_evidence", "account_evidence_missing"},
		// Enumeration.
		{"enumeration inconsistent", enum, "", map[string]string{"response_difference": "indistinguishable", "existence_disclosure": "discloses"}, nil, nil, "needs_evidence", "account_answers_inconsistent"},
		{"enumeration blocking response_unresolved", enum, "", map[string]string{"response_difference": "distinguishable", "existence_disclosure": "discloses"}, nil, []string{analysis.ResponseUnresolved}, "needs_evidence", analysis.ResponseUnresolved},
		{"enumeration blocking access gap", enum, "", map[string]string{"response_difference": "distinguishable", "existence_disclosure": "discloses"}, nil, []string{"access_rule_condition_unmodeled"}, "needs_evidence", "access_rule_condition_unmodeled"},
		{"enumeration protected indistinguishable", enum, "", map[string]string{"response_difference": "indistinguishable", "existence_disclosure": "unknown"}, same, nil, "protected_for_claim", ""},
		{"enumeration protected does_not_disclose", enum, "", map[string]string{"response_difference": "distinguishable", "existence_disclosure": "does_not_disclose"}, nil, nil, "protected_for_claim", ""},
		{"enumeration confirmed", enum, "", map[string]string{"response_difference": "distinguishable", "existence_disclosure": "discloses"}, nil, nil, "confirmed_vulnerability", ""},
		{"enumeration otherwise", enum, "", map[string]string{"response_difference": "unknown", "existence_disclosure": "unknown"}, nil, nil, "needs_evidence", ""},
		// Recovery delivery.
		{"recovery complete with partial", rec, "", map[string]string{"recipient_control": "request_controlled", "validation_coverage": "complete", "secret_quality": "adequate"}, nil, nil, "needs_evidence", "account_answers_inconsistent"},
		{"recovery adequate with weak", rec, "", map[string]string{"recipient_control": "request_controlled", "validation_coverage": "partial", "secret_quality": "adequate"}, func(u analysis.CandidateUse) analysis.CandidateUse {
			u.Recovery.SecretStrength = analysis.SecretWeak
			return u
		}, nil, "needs_evidence", "account_answers_inconsistent"},
		{"recovery weak with csprng", rec, "", map[string]string{"recipient_control": "request_controlled", "validation_coverage": "partial", "secret_quality": "weak"}, nil, nil, "needs_evidence", "account_answers_inconsistent"},
		{"recovery account_bound with request origin", rec, "", map[string]string{"recipient_control": "account_bound", "validation_coverage": "partial", "secret_quality": "adequate"}, nil, nil, "needs_evidence", "account_answers_inconsistent"},
		{"recovery protected", rec, "", map[string]string{"recipient_control": "request_controlled", "validation_coverage": "complete", "secret_quality": "adequate"}, func(u analysis.CandidateUse) analysis.CandidateUse {
			u.Recovery.RecipientValidated, u.Recovery.RecipientCount, u.Recovery.ShapeUses = analysis.RecipientFull, analysis.RecipientCountOne, nil
			return u
		}, nil, "protected_for_claim", ""},
		{"recovery confirmed partial", rec, "", map[string]string{"recipient_control": "request_controlled", "validation_coverage": "partial", "secret_quality": "adequate"}, nil, nil, "confirmed_vulnerability", ""},
		{"recovery confirmed none", rec, "", map[string]string{"recipient_control": "request_controlled", "validation_coverage": "none", "secret_quality": "adequate"}, nil, nil, "confirmed_vulnerability", ""},
		{"recovery confirmed weak secret", rec, "", map[string]string{"recipient_control": "account_bound", "validation_coverage": "complete", "secret_quality": "weak"}, func(u analysis.CandidateUse) analysis.CandidateUse {
			u.Recovery.SecretStrength, u.Recovery.RecipientOrigin, u.Recovery.RecipientValidated = analysis.SecretWeak, analysis.RecipientStoredField, analysis.RecipientFull
			u.Recovery.RecipientCount, u.Recovery.ShapeUses = analysis.RecipientCountOne, nil
			return u
		}, nil, "confirmed_vulnerability", ""},
		{"recovery otherwise", rec, "", map[string]string{"recipient_control": "unknown", "validation_coverage": "unknown", "secret_quality": "unknown"}, nil, nil, "needs_evidence", ""},
		// Password hashing.
		{"hash adaptive for a single digest", hash, "", map[string]string{"password_input": "password", "hash_strength": "adaptive"}, nil, nil, "needs_evidence", "account_answers_inconsistent"},
		{"hash adaptive for a single hash() digest outside the configuration list", hash, "", map[string]string{"password_input": "password", "hash_strength": "adaptive"}, func(u analysis.CandidateUse) analysis.CandidateUse {
			u.PasswordHash.Algorithm = "sha384"
			return u
		}, nil, "needs_evidence", "account_answers_inconsistent"},
		{"hash blocking unmodeled digest", hash, "", map[string]string{"password_input": "password", "hash_strength": "fast_digest"}, func(u analysis.CandidateUse) analysis.CandidateUse {
			u.PasswordHash.Algorithm = "crypt"
			return u
		}, []string{analysis.PasswordDigestUnmodeled}, "needs_evidence", analysis.PasswordDigestUnmodeled},
		{"hash protected not_password", hash, "", map[string]string{"password_input": "not_password", "hash_strength": "fast_digest"}, nil, nil, "protected_for_claim", ""},
		{"hash confirmed", hash, "", map[string]string{"password_input": "password", "hash_strength": "fast_digest"}, nil, nil, "confirmed_vulnerability", ""},
		{"hash confirmed salted", hash, "", map[string]string{"password_input": "password", "hash_strength": "fast_digest"}, func(u analysis.CandidateUse) analysis.CandidateUse {
			u.PasswordHash.Salted = "yes"
			return u
		}, nil, "confirmed_vulnerability", ""},
		{"hash otherwise", hash, "", map[string]string{"password_input": "unknown", "hash_strength": "unknown"}, nil, nil, "needs_evidence", ""},
	} {
		t.Run(tt.rule, func(t *testing.T) {
			u := accountPolicyUse(tt.kind, tt.blockers...)
			if tt.change != nil {
				u = tt.change(u)
			}
			version := tt.version
			if version == "" {
				version = analysispacks.AccountProtocol
			}
			a := analysis.Assessment{QuestionVersion: version, Answers: tt.answers}
			applyPolicy(u, &a)
			assertPolicy(t, a, tt.status, tt.gap)
		})
	}
}
