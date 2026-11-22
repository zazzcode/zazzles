package analysis

import (
	"cmp"
	"encoding/json"
	"slices"
	"strings"
)

// EntryPoint identifies an exposed operation within one application/service instance.
// Kind, language, dispatch mechanism and transport are independent dimensions.
type EntryPoint struct {
	ID              string                 `json:"id"`
	Kind            string                 `json:"kind"`
	Name            string                 `json:"name,omitempty"`
	InstanceID      string                 `json:"instance_id"`
	Location        Evidence               `json:"location"`
	HTTP            *HTTPEntryMetadata     `json:"http,omitempty"`
	Browser         *BrowserEntryMetadata  `json:"browser,omitempty"`
	GraphQL         *GraphQLEntryMetadata  `json:"graphql,omitempty"`
	GRPC            *GRPCEntryMetadata     `json:"grpc,omitempty"`
	UnknownMetadata json.RawMessage        `json:"unknown_metadata,omitempty"`
	Transports      []TransportAssociation `json:"transports,omitempty"`
	Gaps            []Gap                  `json:"gaps,omitempty"`
	// Access is what a Symfony route requires of its caller (lane contract §2.3).
	// FILE entries leave it unset. It is context, never protection for another claim.
	Access *EntryAccess `json:"access,omitempty"`
	// StateChanges lists stored writes the action performs, including writes on a safe method.
	StateChanges []StateChange `json:"state_changes,omitempty"`
}

// HTTPEntryMetadata contains delivery details, not generic entry identity.
type HTTPEntryMetadata struct {
	SourcePath string `json:"source_path,omitempty"`
	Framework  string `json:"framework,omitempty"`
	Method     string `json:"method,omitempty"`
	Path       string `json:"path,omitempty"`
	Mount      string `json:"mount,omitempty"`
	Receiver   string `json:"receiver,omitempty"`
	// Router, Surface, Segments and Aliases describe file-system (Next.js) entries:
	// "app" or "pages"; route_handler, server_action, page or api_route; the raw
	// folder segments; and literal rewrite sources that also reach the entry.
	Router   string   `json:"router,omitempty"`
	Surface  string   `json:"surface,omitempty"`
	Segments []string `json:"segments,omitempty"`
	Aliases  []string `json:"aliases,omitempty"`
}

// BrowserEntryMetadata distinguishes event registrations from script/component roots.
type BrowserEntryMetadata struct {
	Category  string `json:"category"`
	Event     string `json:"event,omitempty"`
	Target    string `json:"target,omitempty"`
	Framework string `json:"framework,omitempty"`
}

// GraphQLEntryMetadata identifies a schema coordinate; transport is associated separately.
type GraphQLEntryMetadata struct {
	Type      string `json:"type,omitempty"`
	Field     string `json:"field,omitempty"`
	Operation string `json:"operation,omitempty"`
}

// GRPCEntryMetadata describes a service method even when streaming flow is unsupported.
type GRPCEntryMetadata struct {
	Package         string `json:"package,omitempty"`
	Service         string `json:"service,omitempty"`
	Method          string `json:"method,omitempty"`
	ClientStreaming bool   `json:"client_streaming"`
	ServerStreaming bool   `json:"server_streaming"`
}

// TransportAssociation preserves supported delivery evidence without creating a value edge.
// EntryID is optional when delivery evidence exists but no transport entry was inventoried.
type TransportAssociation struct {
	Kind     string     `json:"kind"`
	EntryID  string     `json:"entry_id,omitempty"`
	Evidence []Evidence `json:"evidence"`
}

// EntryRegistration records source/configuration wiring and generated origin evidence.
type EntryRegistration struct {
	DeclaredHandler *Symbol    `json:"declared_handler,omitempty"`
	SyntaxSteps     []Step     `json:"syntax_steps,omitempty"`
	ID              string     `json:"id"`
	EntryID         string     `json:"entry_id"`
	Origin          Evidence   `json:"origin"`
	Framework       string     `json:"framework,omitempty"`
	DerivedFrom     []Evidence `json:"derived_from,omitempty"`
	Gaps            []Gap      `json:"gaps,omitempty"`
}

// DispatchBinding represents one stage/target alternative, not a call or value-flow proof.
// Unresolved alternatives have gaps and no fabricated CallableID.
type DispatchBinding struct {
	ID             string     `json:"id"`
	EntryID        string     `json:"entry_id"`
	RegistrationID string     `json:"registration_id"`
	CallableID     string     `json:"callable_id,omitempty"`
	Mechanism      string     `json:"mechanism"`
	Resolution     string     `json:"resolution"`
	Stage          int        `json:"stage"`
	Alternative    string     `json:"alternative,omitempty"`
	Conditions     []Evidence `json:"conditions,omitempty"`
	Gaps           []Gap      `json:"gaps,omitempty"`
}

// Callable identifies implementation source independently of its exposed entries.
type Callable struct {
	ID         string   `json:"id"`
	Name       string   `json:"name,omitempty"`
	Language   string   `json:"language"`
	Definition Evidence `json:"definition"`
}

// InvocationContext owns the bindings and applicable controls of one dispatch context.
// Source records can be shared; context-dependent protection is never stored on Callable.
type InvocationContext struct {
	ID                string              `json:"id"`
	EntryID           string              `json:"entry_id"`
	DispatchBindingID string              `json:"dispatch_binding_id"`
	Inputs            []InputBinding      `json:"inputs,omitempty"`
	Receiver          *InputBinding       `json:"receiver,omitempty"`
	Closures          []InputBinding      `json:"closures,omitempty"`
	Controls          []ApplicableControl `json:"controls,omitempty"`
	Gaps              []Gap               `json:"gaps,omitempty"`
}

// InputBinding maps a role/projection onto an actual parameter, closure or ambient framework binding.
// Role names do not establish trust, value transfer or application requirements.
type InputBinding struct {
	Constant   *string     `json:"constant,omitempty"`
	Role       string      `json:"role"`
	Parameter  string      `json:"parameter"`
	Projection []string    `json:"projection,omitempty"`
	Origin     InputOrigin `json:"origin"`
}

// InputOrigin records provenance separately from its input role. External does not
// mean attacker-controlled; that question needs evidence in the claim's analysis.
type InputOrigin struct {
	Kind           string     `json:"kind"`
	Evidence       []Evidence `json:"evidence,omitempty"`
	RelatedEntryID string     `json:"related_entry_id,omitempty"`
}

// ApplicableControl binds supplied control evidence to this exact dispatch context.
// Evidence presence does not assert control completeness or semantic protection.
type ApplicableControl struct {
	InvocationContextID string   `json:"invocation_context_id"`
	DispatchBindingID   string   `json:"dispatch_binding_id"`
	Evidence            Evidence `json:"evidence"`
}

// EntryCatalog is the shared entry/dispatch record store used by current reports
// and adapters; catalog views share the canonical source-backed record collections.
type EntryCatalog struct {
	Entries            []EntryPoint        `json:"entries"`
	Registrations      []EntryRegistration `json:"registrations"`
	DispatchBindings   []DispatchBinding   `json:"dispatch_bindings"`
	Callables          []Callable          `json:"callables"`
	InvocationContexts []InvocationContext `json:"invocation_contexts"`
	Gaps               []Gap               `json:"gaps,omitempty"`
}

// Canonical validates and orders record collections without mutating construction
// slices. Ordered input/control/condition witnesses retain their semantic order.
// The returned nested evidence remains shared and must be treated as immutable.
func (c EntryCatalog) Canonical() (EntryCatalog, error) {
	if err := c.Validate(); err != nil {
		return EntryCatalog{}, err
	}
	c.Entries = slices.Clone(c.Entries)
	c.Registrations = slices.Clone(c.Registrations)
	c.DispatchBindings = slices.Clone(c.DispatchBindings)
	c.Callables = slices.Clone(c.Callables)
	c.InvocationContexts = slices.Clone(c.InvocationContexts)
	c.Gaps = canonicalEntryGaps(c.Gaps)
	for i := range c.Entries {
		c.Entries[i].Gaps = canonicalEntryGaps(c.Entries[i].Gaps)
	}
	for i := range c.Registrations {
		c.Registrations[i].Gaps = canonicalEntryGaps(c.Registrations[i].Gaps)
	}
	for i := range c.DispatchBindings {
		c.DispatchBindings[i].Gaps = canonicalEntryGaps(c.DispatchBindings[i].Gaps)
	}
	for i := range c.InvocationContexts {
		c.InvocationContexts[i].Gaps = canonicalEntryGaps(c.InvocationContexts[i].Gaps)
	}
	slices.SortFunc(c.Entries, func(a, b EntryPoint) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(c.Registrations, func(a, b EntryRegistration) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(c.DispatchBindings, func(a, b DispatchBinding) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(c.Callables, func(a, b Callable) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(c.InvocationContexts, func(a, b InvocationContext) int { return strings.Compare(a.ID, b.ID) })
	return c, nil
}

func canonicalEntryGaps(gaps []Gap) []Gap {
	out := slices.Clone(gaps)
	slices.SortFunc(out, func(a, b Gap) int {
		return cmp.Or(strings.Compare(a.At.File, b.At.File), cmp.Compare(a.At.StartByte, b.At.StartByte), cmp.Compare(a.At.EndByte, b.At.EndByte), cmp.Compare(a.At.StartLine, b.At.StartLine), cmp.Compare(a.At.EndLine, b.At.EndLine), strings.Compare(a.Kind, b.Kind), strings.Compare(a.Detail, b.Detail))
	})
	return out
}
