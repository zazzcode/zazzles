package analysis

import "fmt"

// UploadFacts records a verified upload write: how the stored file name is
// formed, the server-side type controls that dominate the write, and whether
// the destination is served (close-findings-gaps W5, D-20). Adapters
// establish them from source; views do not infer them.
type UploadFacts struct {
	Operation  string `json:"operation"`
	ContractID string `json:"contract_id"`
	// StoredName is client, client_basename, server_generated, mixed or unknown.
	StoredName string `json:"stored_name"`
	// ExtensionOrigin is client, fixed, allow_listed, content_derived or unknown.
	ExtensionOrigin string          `json:"extension_origin"`
	TypeControls    []UploadControl `json:"type_controls,omitempty"`
	// DestinationServed is yes when the destination directory is under a
	// source-established document root, no when it is outside, else unknown.
	DestinationServed string `json:"destination_served"`
	Destination       string `json:"destination,omitempty"`
	// Paths cover every dependency: the uploaded content (operand
	// "upload_content") and request-derived parts of the stored name
	// (operand "stored_name").
	Paths []CommandPath `json:"paths"`
}

// UploadControl is one server-side control on the uploaded file's type.
// ClientControlled marks a check of a value the client supplies (its
// declared MIME type), which is recorded but constrains nothing.
type UploadControl struct {
	Kind             string `json:"kind"`
	Context          int    `json:"context"`
	ClientControlled bool   `json:"client_controlled,omitempty"`
}

// Upload control kinds.
const (
	UploadClientDeclaredType = "client_declared_type"
	UploadExtensionAllowList = "extension_allow_list"
	UploadContentSniff       = "content_sniff"
	UploadReEncode           = "re_encode"
)

// Validate checks enumerations and every index against the candidate use.
func (f *UploadFacts) Validate(deps, context int) error {
	if f == nil {
		return nil
	}
	if f.Operation == "" || f.ContractID == "" {
		return fmt.Errorf("invalid upload operation")
	}
	switch f.StoredName {
	case "client", "client_basename", "server_generated", "mixed", "unknown":
	default:
		return fmt.Errorf("invalid stored-name origin %q", f.StoredName)
	}
	switch f.ExtensionOrigin {
	case "client", "fixed", "allow_listed", "content_derived", "unknown":
	default:
		return fmt.Errorf("invalid extension origin %q", f.ExtensionOrigin)
	}
	switch f.DestinationServed {
	case "yes", "no", "unknown":
	default:
		return fmt.Errorf("invalid destination fact %q", f.DestinationServed)
	}
	for _, c := range f.TypeControls {
		switch c.Kind {
		case UploadClientDeclaredType, UploadExtensionAllowList, UploadContentSniff, UploadReEncode:
		default:
			return fmt.Errorf("invalid upload control %q", c.Kind)
		}
		if c.Context < 0 || c.Context >= context {
			return fmt.Errorf("invalid upload control index")
		}
	}
	seen := map[int]bool{}
	for _, p := range f.Paths {
		if p.Dependency < 0 || p.Dependency >= deps || seen[p.Dependency] || p.Operand != "upload_content" && p.Operand != "stored_name" {
			return fmt.Errorf("invalid or duplicate upload operand path")
		}
		seen[p.Dependency] = true
		if p.Protection != "raw" && p.Protection != "guarded" && p.Protection != "unknown" {
			return fmt.Errorf("invalid operand protection")
		}
		for _, i := range p.Controls {
			if i < 0 || i >= context {
				return fmt.Errorf("invalid operand control index")
			}
		}
	}
	if len(seen) != deps || deps == 0 {
		return fmt.Errorf("upload paths do not cover every dependency")
	}
	return nil
}

// ServerTypeControl reports a server-side control that constrains the type.
func (f *UploadFacts) ServerTypeControl() bool {
	for _, c := range f.TypeControls {
		if !c.ClientControlled {
			return true
		}
	}
	return false
}
