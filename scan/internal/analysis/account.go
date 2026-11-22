package analysis

import "fmt"

// Account-family claim kinds: account enumeration (CWE-204),
// recovery-secret delivery (CWE-640, CWE-1287) and weak password hashing
// (CWE-916).
const (
	AccountEnumerationKind = "account_enumeration_candidate"
	RecoveryDeliveryKind   = "recovery_delivery_candidate"
	PasswordHashKind       = "password_hash_candidate"
)

// RoleRecoverySecret is the census role of a stored field written from a
// random-secret source and compared with a request value.
const RoleRecoverySecret = "recovery_secret"

// Account gaps.
const (
	ResponseUnresolved      = "response_unresolved"
	PasswordDigestUnmodeled = "password_digest_unmodeled"
)

// Branch response kinds: how one side of a lookup branch answers.
const (
	ResponseFlash     = "flash"
	ResponseBody      = "body"
	ResponseStatus    = "status"
	ResponseRedirect  = "redirect"
	ResponseTemplate  = "template"
	ResponseException = "exception"
)

// BranchResponse is one response on one side of a lookup branch. The scanner
// records the literal and never reads meaning into it.
type BranchResponse struct {
	Kind    string `json:"kind"` // flash | body | status | redirect | template | exception | response_unresolved
	Literal string `json:"literal,omitempty"`
	Span    Span   `json:"span"`
}

// EnumerationLookup is the account finder whose criteria hold a request value.
type EnumerationLookup struct {
	Class          string   `json:"class"`
	Method         string   `json:"method"`
	CriteriaFields []string `json:"criteria_fields"`
	Evidence       Evidence `json:"evidence"`
	Branch         Evidence `json:"branch"`
}

// EnumerationFacts is the lookup, its result branch and the two responses.
type EnumerationFacts struct {
	Lookup         EnumerationLookup   `json:"lookup"`
	Found          []BranchResponse    `json:"found"`
	NotFound       []BranchResponse    `json:"not_found"`
	SecurityFields []SecurityFieldFact `json:"security_fields"`
}

// Validate rejects a record outside the closed lists.
func (f *EnumerationFacts) Validate() error {
	if f == nil || f.Lookup.Class == "" || f.Lookup.Evidence.Span.File == "" || f.Lookup.Branch.Span.File == "" {
		return fmt.Errorf("missing enumeration lookup")
	}
	if len(f.Found) == 0 && len(f.NotFound) == 0 {
		return fmt.Errorf("missing branch responses")
	}
	for _, side := range [][]BranchResponse{f.Found, f.NotFound} {
		for _, r := range side {
			switch r.Kind {
			case ResponseFlash, ResponseBody, ResponseStatus, ResponseRedirect, ResponseTemplate, ResponseException, ResponseUnresolved:
			default:
				return fmt.Errorf("invalid branch response kind")
			}
		}
	}
	return nil
}

// Recovery values: secret strength and the recipient facts.
const (
	SecretCSPRNG          = "csprng"
	SecretWeak            = "weak"
	RecipientFull         = "full"
	RecipientPartial      = "partial"
	RecipientNone         = "none"
	RecipientCountOne     = "one"
	RecipientCountRequest = "request_controlled"
	RecipientRequestValue = "request_value"
	RecipientStoredField  = "stored_field"
)

// RecoveryFacts is a generated secret that reaches mail content, with the
// origin of the recipient and what checked it.
type RecoveryFacts struct {
	SecretSource       Evidence            `json:"secret_source"`
	SecretStrength     string              `json:"secret_strength"` // csprng | weak
	StoredField        string              `json:"stored_field,omitempty"`
	StoredAt           *Evidence           `json:"stored_at,omitempty"`
	Recipient          Evidence            `json:"recipient"`
	RecipientOrigin    string              `json:"recipient_origin"`    // request_value | stored_field
	RecipientValidated string              `json:"recipient_validated"` // full | partial | none
	RecipientCount     string              `json:"recipient_count"`     // one | request_controlled
	ShapeUses          []Evidence          `json:"shape_uses,omitempty"`
	Content            Evidence            `json:"content"`
	MailContract       string              `json:"mail_contract"`
	SecurityFields     []SecurityFieldFact `json:"security_fields"`
}

// Validate rejects a record outside the closed lists.
func (f *RecoveryFacts) Validate() error {
	if f == nil || f.SecretSource.Span.File == "" || f.Recipient.Span.File == "" || f.Content.Span.File == "" || f.MailContract == "" {
		return fmt.Errorf("missing recovery facts")
	}
	switch f.SecretStrength {
	case SecretCSPRNG, SecretWeak:
	default:
		return fmt.Errorf("invalid secret strength")
	}
	switch f.RecipientValidated {
	case RecipientFull, RecipientPartial, RecipientNone:
	default:
		return fmt.Errorf("invalid recipient_validated")
	}
	switch f.RecipientCount {
	case RecipientCountOne, RecipientCountRequest:
	default:
		return fmt.Errorf("invalid recipient_count")
	}
	switch f.RecipientOrigin {
	case RecipientRequestValue, RecipientStoredField:
	default:
		return fmt.Errorf("invalid recipient origin")
	}
	if f.RecipientValidated == RecipientPartial && len(f.ShapeUses) < 2 {
		return fmt.Errorf("partial validation needs both use sites")
	}
	return nil
}

// Password-hash bases: the evidence that a digest input is a password.
const (
	BasisCredentialField     = "credential_field"
	BasisHasherClass         = "hasher_class"
	BasisConfiguration       = "configuration"
	BasisSQLCredentialColumn = "sql_credential_column"
)

// PasswordHashFacts is a fast digest that evidence says is the stored form of
// a password.
type PasswordHashFacts struct {
	Algorithm      string              `json:"algorithm"`
	Basis          string              `json:"basis"` // credential_field | hasher_class | configuration | sql_credential_column
	BasisEvidence  []Evidence          `json:"basis_evidence"`
	Salted         string              `json:"salted"`
	Iterated       string              `json:"iterated"`
	HasherClass    string              `json:"hasher_class,omitempty"`
	SecurityFields []SecurityFieldFact `json:"security_fields"`
}

// Validate rejects a record outside the closed lists.
func (f *PasswordHashFacts) Validate() error {
	if f == nil || f.Algorithm == "" || len(f.BasisEvidence) == 0 {
		return fmt.Errorf("missing password hash facts")
	}
	switch f.Basis {
	case BasisCredentialField, BasisHasherClass, BasisConfiguration, BasisSQLCredentialColumn:
	default:
		return fmt.Errorf("invalid password basis")
	}
	for _, v := range []string{f.Salted, f.Iterated} {
		if v != "yes" && v != "no" {
			return fmt.Errorf("invalid salted or iterated")
		}
	}
	return nil
}
