package analysis

import (
	"encoding/json"
	"fmt"
)

type entryCatalogIndex struct {
	entries       map[string]EntryPoint
	registrations map[string]EntryRegistration
	dispatches    map[string]DispatchBinding
	callables     map[string]Callable
}

// Validate checks reference ownership and structural provenance, not runtime
// feasibility, guard adequacy, input trust or completeness of discovered entries.
func (c EntryCatalog) Validate() error {
	index, err := c.index()
	if err != nil {
		return err
	}
	for _, e := range c.Entries {
		if err := validateEntryPoint(e, index); err != nil {
			return fmt.Errorf("entry %q: %w", e.ID, err)
		}
	}
	for _, r := range c.Registrations {
		if _, ok := index.entries[r.EntryID]; !ok {
			return fmt.Errorf("registration %q: unknown entry %q", r.ID, r.EntryID)
		}
		if err := validateEntrySource(r.Origin); err != nil {
			return fmt.Errorf("registration %q: %w", r.ID, err)
		}
		if err := validateEntryEvidence(r.DerivedFrom); err != nil {
			return fmt.Errorf("registration %q: %w", r.ID, err)
		}
	}
	for _, f := range c.Callables {
		if f.Language == "" {
			return fmt.Errorf("callable %q: language is required", f.ID)
		}
		if err := validateEntrySource(f.Definition); err != nil {
			return fmt.Errorf("callable %q: %w", f.ID, err)
		}
	}
	for _, b := range c.DispatchBindings {
		if err := validateEntryDispatch(b, index); err != nil {
			return fmt.Errorf("dispatch %q: %w", b.ID, err)
		}
	}
	for _, ctx := range c.InvocationContexts {
		if err := validateEntryInvocation(ctx, index); err != nil {
			return fmt.Errorf("invocation %q: %w", ctx.ID, err)
		}
	}
	return nil
}

func (c EntryCatalog) index() (entryCatalogIndex, error) {
	index := entryCatalogIndex{map[string]EntryPoint{}, map[string]EntryRegistration{}, map[string]DispatchBinding{}, map[string]Callable{}}
	seen := map[string]string{}
	add := func(kind, id string) error {
		if id == "" {
			return fmt.Errorf("%s ID is required", kind)
		}
		if previous, ok := seen[id]; ok {
			return fmt.Errorf("duplicate ID %q (%s and %s)", id, previous, kind)
		}
		seen[id] = kind
		return nil
	}
	for _, e := range c.Entries {
		if err := add("entry", e.ID); err != nil {
			return index, err
		}
		index.entries[e.ID] = e
	}
	for _, r := range c.Registrations {
		if err := add("registration", r.ID); err != nil {
			return index, err
		}
		index.registrations[r.ID] = r
	}
	for _, b := range c.DispatchBindings {
		if err := add("dispatch", b.ID); err != nil {
			return index, err
		}
		index.dispatches[b.ID] = b
	}
	for _, f := range c.Callables {
		if err := add("callable", f.ID); err != nil {
			return index, err
		}
		index.callables[f.ID] = f
	}
	for _, ctx := range c.InvocationContexts {
		if err := add("invocation", ctx.ID); err != nil {
			return index, err
		}
	}
	return index, nil
}

func validateEntryPoint(e EntryPoint, index entryCatalogIndex) error {
	if e.Kind == "" || e.InstanceID == "" {
		return fmt.Errorf("kind and instance identity are required")
	}
	if err := validateEntrySource(e.Location); err != nil {
		return err
	}
	if err := validateEntryMetadata(e); err != nil {
		return err
	}
	for _, transport := range e.Transports {
		if transport.Kind == "" || len(transport.Evidence) == 0 {
			return fmt.Errorf("transport kind and evidence are required")
		}
		if transport.EntryID != "" {
			target, ok := index.entries[transport.EntryID]
			if !ok || target.Kind != transport.Kind || target.ID == e.ID {
				return fmt.Errorf("invalid transport entry %q", transport.EntryID)
			}
		}
		if err := validateEntryEvidence(transport.Evidence); err != nil {
			return err
		}
	}
	return nil
}

func validateEntryMetadata(e EntryPoint) error {
	count := 0
	for _, present := range []bool{e.HTTP != nil, e.Browser != nil, e.GraphQL != nil, e.GRPC != nil} {
		if present {
			count++
		}
	}
	matches := false
	switch e.Kind {
	case "http":
		matches = e.HTTP != nil
	case "browser":
		matches = e.Browser != nil
	case "graphql":
		matches = e.GraphQL != nil
	case "grpc":
		matches = e.GRPC != nil
	default:
		if count != 0 {
			return fmt.Errorf("unknown kind cannot use another kind's typed metadata")
		}
		if len(e.UnknownMetadata) > 0 && !json.Valid(e.UnknownMetadata) {
			return fmt.Errorf("invalid unknown metadata JSON")
		}
		return nil
	}
	if !matches || count != 1 || len(e.UnknownMetadata) > 0 {
		return fmt.Errorf("metadata must match entry kind %q exclusively", e.Kind)
	}
	return nil
}

func validateEntryDispatch(b DispatchBinding, index entryCatalogIndex) error {
	if _, ok := index.entries[b.EntryID]; !ok {
		return fmt.Errorf("unknown entry %q", b.EntryID)
	}
	registration, ok := index.registrations[b.RegistrationID]
	if !ok {
		return fmt.Errorf("unknown registration %q", b.RegistrationID)
	}
	if registration.EntryID != b.EntryID {
		return fmt.Errorf("registration/entry ownership mismatch")
	}
	if b.Mechanism == "" {
		return fmt.Errorf("dispatch mechanism is required")
	}
	if b.Stage < 0 {
		return fmt.Errorf("dispatch stage must be nonnegative")
	}
	switch b.Resolution {
	case "resolved":
		if b.CallableID == "" {
			return fmt.Errorf("resolved dispatch needs callable")
		}
	case "partial":
		if b.CallableID == "" || len(b.Gaps) == 0 {
			return fmt.Errorf("partial dispatch needs known callable and gap")
		}
	case "unresolved":
		if b.CallableID != "" {
			return fmt.Errorf("unresolved dispatch cannot fabricate callable")
		}
		if len(b.Gaps) == 0 {
			return fmt.Errorf("unresolved dispatch needs gap")
		}
	default:
		return fmt.Errorf("unknown dispatch resolution %q", b.Resolution)
	}
	if b.CallableID != "" {
		if _, ok := index.callables[b.CallableID]; !ok {
			return fmt.Errorf("unknown callable %q", b.CallableID)
		}
	}
	return validateEntryEvidence(b.Conditions)
}

func validateEntryInvocation(ctx InvocationContext, index entryCatalogIndex) error {
	binding, ok := index.dispatches[ctx.DispatchBindingID]
	if !ok {
		return fmt.Errorf("unknown dispatch %q", ctx.DispatchBindingID)
	}
	if ctx.EntryID != binding.EntryID {
		return fmt.Errorf("dispatch/entry ownership mismatch")
	}
	if binding.CallableID == "" && (len(ctx.Inputs) > 0 || ctx.Receiver != nil || len(ctx.Closures) > 0) {
		return fmt.Errorf("unresolved callable cannot have parameter bindings")
	}
	for _, control := range ctx.Controls {
		// A prior middleware's evidence is supplied as applicable to the final dispatch
		// by its adapter. Referencing a sibling binding cannot make it applicable here.
		if control.DispatchBindingID != ctx.DispatchBindingID || control.InvocationContextID != ctx.ID {
			return fmt.Errorf("control ownership does not match invocation dispatch")
		}
		if err := validateEntrySource(control.Evidence); err != nil {
			return fmt.Errorf("control: %w", err)
		}
	}
	for _, input := range ctx.Inputs {
		if err := validateEntryInput(input, index); err != nil {
			return err
		}
	}
	for _, closure := range ctx.Closures {
		if err := validateEntryInput(closure, index); err != nil {
			return err
		}
	}
	if ctx.Receiver != nil {
		return validateEntryInput(*ctx.Receiver, index)
	}
	return nil
}

func validateEntryInput(input InputBinding, index entryCatalogIndex) error {
	if input.Constant != nil && input.Origin.Kind != "constant" {
		return fmt.Errorf("constant binding requires constant origin")
	}
	if input.Role == "" || input.Parameter == "" {
		return fmt.Errorf("input role and parameter are required")
	}
	switch input.Origin.Kind {
	case "external", "derived", "constant":
		if len(input.Origin.Evidence) == 0 {
			return fmt.Errorf("input origin needs evidence")
		}
	case "unknown":
	default:
		return fmt.Errorf("invalid input origin %q", input.Origin.Kind)
	}
	if input.Origin.RelatedEntryID != "" {
		if _, ok := index.entries[input.Origin.RelatedEntryID]; !ok {
			return fmt.Errorf("input origin references unknown entry %q", input.Origin.RelatedEntryID)
		}
	}
	return validateEntryEvidence(input.Origin.Evidence)
}

func validateEntryEvidence(items []Evidence) error {
	for _, e := range items {
		if err := validateEntrySource(e); err != nil {
			return err
		}
	}
	return nil
}
