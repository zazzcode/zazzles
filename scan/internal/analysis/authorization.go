package analysis

import "fmt"

// AuthorizationBlockingGap reports whether the gap blocks this authorization claim.
// Incomplete security fields block only claims that rely solely on the census.
func AuthorizationBlockingGap(kind string, censusOnly bool) bool {
	switch kind {
	case "access_rule_unresolved", "access_rule_condition_unmodeled", "voter_unmodeled", "access_expression_unmodeled", "authenticator_unmodeled", GuardUnclassified, "symfony_config_unread":
		return true
	case SecurityFieldsUnresolved:
		return censusOnly
	default:
		return false
	}
}

// AuthorizationKind is the claim kind of an operation that changes or reveals a
// record the request selects (CWE-862, CWE-639, CWE-285, CWE-291).
const AuthorizationKind = "authorization_candidate"

// Authorization facets. A candidate may carry more than one.
const (
	FacetObjectLevel   = "object_level"
	FacetFunctionLevel = "function_level"
	FacetDataExposure  = "data_exposure"
)

// Subject provenance values of D-4.
const (
	SubjectRequestSelected = "request_selected"
	SubjectEnumerated      = "enumerated"
	SubjectSessionUser     = "session_user"
	SubjectCreated         = "created"
)

// Guard kinds of D-6 and D-8. guard_unclassified is the anything-else row.
const (
	GuardRole          = "role_check"
	GuardOwnership     = "ownership_check"
	GuardAuthenticated = "authenticated_check"
	GuardSecret        = "secret_check"
	GuardAddress       = "address_check"
	GuardUnclassified  = "guard_unclassified"
)

// Address sources of D-8.
const (
	AddressFrameworkIP     = "framework_client_ip"
	AddressPeer            = "peer_address"
	AddressForwardedHeader = "forwarded_header"
)

// Access authentication values.
const (
	AccessRequired   = "required"
	AccessNone       = "none"
	AccessUnresolved = "unresolved"
)

// EntryAccess is what one Symfony entry requires of its caller.
type EntryAccess struct {
	Authentication string     `json:"authentication"` // required | none | unresolved
	Roles          []string   `json:"roles,omitempty"`
	Sources        []Evidence `json:"sources"`
	Gaps           []Gap      `json:"gaps,omitempty"`
	// RejectsAll is set when a middleware on the chain can accept no request,
	// so the entry's operations are unreachable through it.
	RejectsAll bool `json:"rejects_all,omitempty"`
}

// StateChange is one stored write an entry performs.
type StateChange struct {
	StorageKey string `json:"storage_key,omitempty"`
	Operation  string `json:"operation"` // create | update | delete | file_write | file_delete
	Span       Span   `json:"span"`
}

// AddressTrust records whether a framework client address can be forged.
// This branch leaves status "unread"; branch 4 fills the value.
type AddressTrust struct {
	Status   string   `json:"status"`
	Evidence Evidence `json:"evidence,omitempty"`
}

// AuthorizationGuard is one dominating check. The scanner lists it and does
// not decide that it is sufficient.
type AuthorizationGuard struct {
	Kind          string        `json:"kind"`
	Form          string        `json:"form,omitempty"`
	AddressSource string        `json:"address_source,omitempty"`
	Literals      []string      `json:"literals,omitempty"`
	LiteralClass  []string      `json:"literal_class,omitempty"` // loopback | private | public, parallel to Literals
	AddressTrust  *AddressTrust `json:"address_trust,omitempty"`
	Evidence      Evidence      `json:"evidence"`
	Gaps          []Gap         `json:"gaps,omitempty"`
}

// PeerAccess is another entry that writes the same storage key.
type PeerAccess struct {
	Entry      string      `json:"entry"`
	Access     EntryAccess `json:"access"`
	GuardKinds []string    `json:"guard_kinds,omitempty"`
}

// SecurityFieldFact is one census field an operation writes or returns.
type SecurityFieldFact struct {
	StorageKey string     `json:"storage_key"`
	Roles      []string   `json:"roles"`
	Evidence   []Evidence `json:"evidence,omitempty"`
}

// AuthorizationFacts is the operation-centered record. Guards are evidence.
type AuthorizationFacts struct {
	Facets             []string             `json:"facets"`
	SubjectClass       string               `json:"subject_class"`
	SubjectProvenance  string               `json:"subject_provenance"`
	Operation          StateChange          `json:"operation"`
	SecurityFields     []SecurityFieldFact  `json:"security_fields"`
	Guards             []AuthorizationGuard `json:"guards"`
	MethodSafe         string               `json:"method_safe"`
	PeerAccess         []PeerAccess         `json:"peer_access,omitempty"`
	ServerSideRequests []string             `json:"server_side_requests,omitempty"`
}

// Validate rejects a record outside the closed lists.
func (f *AuthorizationFacts) Validate() error {
	plain := f != nil && f.SubjectClass == "" && len(f.Facets) == 0 && len(f.Guards) == 1 && f.Guards[0].Kind == GuardAddress
	if f == nil || (!plain && (f.SubjectClass == "" || len(f.Facets) == 0)) {
		return fmt.Errorf("missing authorization facts")
	}
	if !plain {
		switch f.SubjectProvenance {
		case SubjectRequestSelected, SubjectEnumerated, SubjectSessionUser, SubjectCreated:
		default:
			return fmt.Errorf("invalid subject provenance")
		}
	}
	for _, facet := range f.Facets {
		switch facet {
		case FacetObjectLevel, FacetFunctionLevel, FacetDataExposure:
		default:
			return fmt.Errorf("invalid authorization facet")
		}
	}
	switch f.Operation.Operation {
	case "create", "update", "delete", "file_write", "file_delete", "read":
	default:
		return fmt.Errorf("invalid authorization operation")
	}
	switch f.MethodSafe {
	case "yes", "no":
	default:
		return fmt.Errorf("invalid method_safe")
	}
	for _, g := range f.Guards {
		switch g.Kind {
		case GuardRole, GuardOwnership, GuardAuthenticated, GuardSecret, GuardAddress, GuardUnclassified:
		default:
			return fmt.Errorf("invalid guard kind")
		}
		if g.Evidence.Span.File == "" {
			return fmt.Errorf("guard missing evidence")
		}
	}
	return nil
}
