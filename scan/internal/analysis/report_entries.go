package analysis

import "fmt"

// HTTPRoute projects optional HTTP metadata for HTTP-specific adapters and selectors.
// The returned syntax view is not an independent canonical entry or association.
func (e EntryPoint) HTTPRoute() Route {
	r := Route{ID: e.ID, Registration: e.Location.Span}
	if e.HTTP != nil {
		r.Method = e.HTTP.Method
		r.PathPattern = e.HTTP.Path
		r.Framework = e.HTTP.Framework
	}
	return r
}

// Catalog returns a view of the report's canonical entry collections.
func (r *AnalysisReport) Catalog() EntryCatalog {
	return EntryCatalog{Entries: r.Entries, Registrations: r.Registrations, DispatchBindings: r.DispatchBindings, Callables: r.Callables, InvocationContexts: r.InvocationContexts, Gaps: r.Gaps}
}

// Handler returns a known implementation's source for existing HTTP-specific checks.
// Multiple alternatives remain in DispatchBindings; this view does not establish completeness.
func (r *AnalysisReport) Handler(entryID string) *Evidence {
	for _, b := range r.DispatchBindings {
		if b.EntryID == entryID && b.CallableID != "" {
			for i := range r.Callables {
				if r.Callables[i].ID == b.CallableID {
					return &r.Callables[i].Definition
				}
			}
		}
	}
	return nil
}

// BindUses attaches non-serialized read views for judge requests. IDs are the only
// persisted candidate associations; the pointed-to records belong to this report.
func (r *AnalysisReport) BindUses() error {
	entries := map[string]*EntryPoint{}
	contexts := map[string]*InvocationContext{}
	bindings := map[string]*DispatchBinding{}
	for i := range r.Entries {
		entries[r.Entries[i].ID] = &r.Entries[i]
	}
	for i := range r.InvocationContexts {
		contexts[r.InvocationContexts[i].ID] = &r.InvocationContexts[i]
	}
	for i := range r.DispatchBindings {
		bindings[r.DispatchBindings[i].ID] = &r.DispatchBindings[i]
	}
	for i := range r.Uses {
		u := &r.Uses[i]
		u.EntryFacts = entries[u.EntryID]
		u.InvocationFacts = contexts[u.InvocationContextID]
		if u.EntryFacts == nil || u.InvocationFacts == nil || u.InvocationFacts.EntryID != u.EntryID {
			return fmt.Errorf("candidate %q has missing or conflicting entry/context association", u.ID)
		}
		u.EntryKind = u.EntryFacts.Kind
		u.DispatchFacts = bindings[u.InvocationFacts.DispatchBindingID]
		if u.DispatchFacts == nil || u.DispatchFacts.EntryID != u.EntryID {
			return fmt.Errorf("candidate %q has conflicting dispatch association", u.ID)
		}
	}
	return nil
}

// MergeEntries joins a language adapter's canonical records into the report.
func (r *AnalysisReport) MergeEntries(other *AnalysisReport) {
	r.Entries = append(r.Entries, other.Entries...)
	r.Registrations = append(r.Registrations, other.Registrations...)
	r.DispatchBindings = append(r.DispatchBindings, other.DispatchBindings...)
	r.Callables = append(r.Callables, other.Callables...)
	r.InvocationContexts = append(r.InvocationContexts, other.InvocationContexts...)
}

// SelectEntries keeps the closed entry/registration/context/use subset for a filter.
// Related source evidence and scan gaps remain available even outside the selection.
func (r *AnalysisReport) SelectEntries(keep map[string]bool) {
	entries := r.Entries[:0]
	for _, e := range r.Entries {
		if keep[e.ID] {
			entries = append(entries, e)
		}
	}
	r.Entries = entries
	regs := r.Registrations[:0]
	for _, e := range r.Registrations {
		if keep[e.EntryID] {
			regs = append(regs, e)
		}
	}
	r.Registrations = regs
	bindings := r.DispatchBindings[:0]
	calls := map[string]bool{}
	for _, b := range r.DispatchBindings {
		if keep[b.EntryID] {
			bindings = append(bindings, b)
			calls[b.CallableID] = true
		}
	}
	r.DispatchBindings = bindings
	funcs := r.Callables[:0]
	for _, f := range r.Callables {
		if calls[f.ID] {
			funcs = append(funcs, f)
		}
	}
	r.Callables = funcs
	contexts := r.InvocationContexts[:0]
	for _, c := range r.InvocationContexts {
		if keep[c.EntryID] {
			contexts = append(contexts, c)
		}
	}
	r.InvocationContexts = contexts
	uses := r.Uses[:0]
	for _, u := range r.Uses {
		if keep[u.EntryID] {
			uses = append(uses, u)
		}
	}
	r.Uses = uses
}

func (r *AnalysisReport) validateReferences() error {
	index, err := r.Catalog().index()
	if err != nil {
		return err
	}
	for _, e := range r.Entries {
		if e.Kind == "" || e.InstanceID == "" {
			return fmt.Errorf("entry kind and instance identity are required")
		}
		if err := validateEntryMetadata(e); err != nil {
			return err
		}
	}
	for _, f := range r.Callables {
		if f.Language == "" {
			return fmt.Errorf("callable language is required")
		}
	}
	for _, reg := range r.Registrations {
		if _, ok := index.entries[reg.EntryID]; !ok {
			return fmt.Errorf("registration has unknown entry")
		}
	}
	for _, b := range r.DispatchBindings {
		if err := validateEntryDispatch(b, index); err != nil {
			return err
		}
	}
	for _, ctx := range r.InvocationContexts {
		if err := validateEntryInvocation(ctx, index); err != nil {
			return err
		}
	}
	return nil
}

// EntryGaps projects registration, dispatch and invocation uncertainty into an
// entry's coverage view, including entries with no candidate uses.
func (r *AnalysisReport) EntryGaps(id string) []Gap {
	out := []Gap{}
	seen := map[Gap]bool{}
	add := func(items []Gap) {
		for _, g := range items {
			if !seen[g] {
				seen[g] = true
				out = append(out, g)
			}
		}
	}
	for _, e := range r.Entries {
		if e.ID == id {
			add(e.Gaps)
		}
	}
	for _, e := range r.Registrations {
		if e.EntryID == id {
			add(e.Gaps)
		}
	}
	for _, e := range r.DispatchBindings {
		if e.EntryID == id {
			add(e.Gaps)
		}
	}
	for _, e := range r.InvocationContexts {
		if e.EntryID == id {
			add(e.Gaps)
		}
	}
	return canonicalEntryGaps(out)
}

// ValidateUses checks current candidate identity uniqueness and resolves canonical
// associations. Historical duplicate IDs remain readable under their provenance.
func (r *AnalysisReport) ValidateUses() error {
	seen := map[string]bool{}
	for _, u := range r.Uses {
		if u.ID == "" {
			return fmt.Errorf("candidate ID is required")
		}
		if seen[u.ID] && r.SourceSchemaVersion == 0 {
			return fmt.Errorf("duplicate candidate ID %q", u.ID)
		}
		seen[u.ID] = true
	}
	return r.BindUses()
}
