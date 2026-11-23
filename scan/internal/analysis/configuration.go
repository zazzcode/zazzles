package analysis

// ConfigurationKind is a judged setting joined to application facts.
const ConfigurationKind = "configuration_candidate"

// Configuration checks. A name outside this list is not a check.
const (
	CheckDirectoryListing       = "directory_listing"
	CheckCSRFDisabled           = "csrf_disabled"
	CheckSessionCookieScript    = "session_cookie_script_readable"
	CheckSessionCookieTransport = "session_cookie_insecure_transport"
	CheckDebugEnabled           = "debug_enabled"
	CheckScheduledPrivileged    = "scheduled_privileged_writable"
	CheckRemoteInclude          = "remote_include_enabled"
)

// ConfigurationFacts is one setting, its scope and the application facts it
// joins. The scanner does not decide that the setting is a defect.
type ConfigurationFacts struct {
	Check       string     `json:"check"`
	Setting     Evidence   `json:"setting"`
	Value       string     `json:"value"`
	Scope       string     `json:"scope,omitempty"`
	Joined      []Evidence `json:"joined"`
	Mitigations []Evidence `json:"mitigations,omitempty"`
}
