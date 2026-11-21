package analysis

import (
	"encoding/json"
	"fmt"
	"sort"
)

type reportWire AnalysisReport

type legacyEntry struct {
	Route   Route     `json:"route"`
	Handler *Evidence `json:"resolved_handler,omitempty"`
	Gaps    []Gap     `json:"gaps"`
}
type legacyClientEntry struct {
	ID, Kind, Name, Framework string
	Location                  Span
}

// UnmarshalJSON converts historical wire formats once at the input boundary.
// Source text/hashes/spans and raw assessments are preserved; unknown invocation
// facts are recorded as gaps rather than reconstructed from source proximity.
func (r *AnalysisReport) UnmarshalJSON(data []byte) error {
	var header struct {
		SchemaVersion int                 `json:"schema_version"`
		Entries       []json.RawMessage   `json:"entries"`
		Uses          []json.RawMessage   `json:"uses"`
		ClientEntries []legacyClientEntry `json:"client_entries"`
		Practice      []GuidelinesRef     `json:"practice"`
	}
	if err := json.Unmarshal(data, &header); err != nil {
		return err
	}
	if header.SchemaVersion < 1 || header.SchemaVersion > ReportSchemaVersion {
		return fmt.Errorf("unsupported analysis schema %d", header.SchemaVersion)
	}
	var out AnalysisReport
	if header.SchemaVersion >= 3 {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(data, &fields); err != nil {
			return err
		}
		for _, key := range []string{"client_entries", "practice"} {
			if _, ok := fields[key]; ok {
				return fmt.Errorf("schema %d rejects legacy %s", header.SchemaVersion, key)
			}
		}
		for _, raw := range header.Uses {
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(raw, &fields); err != nil {
				return err
			}
			for _, key := range []string{"route_id", "client_id"} {
				if _, ok := fields[key]; ok {
					return fmt.Errorf("schema %d rejects legacy candidate association %s", header.SchemaVersion, key)
				}
			}
		}
		if err := json.Unmarshal(data, (*reportWire)(&out)); err != nil {
			return err
		}
		if out.SourceSchemaVersion != 0 && out.SourceSchemaVersion != 1 && out.SourceSchemaVersion != 2 {
			return fmt.Errorf("invalid source schema provenance")
		}
		if out.SourceSchemaVersion == 0 {
			if err := out.Catalog().Validate(); err != nil {
				return err
			}
		} else if err := out.validateReferences(); err != nil {
			return err
		}
	} else {
		// Exclude old entries/uses from canonical decoding; their layouts are incompatible.
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(data, &fields); err != nil {
			return err
		}
		delete(fields, "entries")
		delete(fields, "uses")
		delete(fields, "findings")
		rest, err := json.Marshal(fields)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(rest, (*reportWire)(&out)); err != nil {
			return err
		}
		out.SourceSchemaVersion = header.SchemaVersion
		out.SchemaVersion = ReportSchemaVersion
		if out.AnalysisGuidelines == nil && header.SchemaVersion == 1 {
			out.AnalysisGuidelines = header.Practice
		}
		if err := out.convertLegacyEntries(header.Entries, header.ClientEntries, header.Uses); err != nil {
			return err
		}
	}
	if header.Uses == nil {
		return fmt.Errorf("analysis uses array is required")
	}
	if err := out.ValidateUses(); err != nil {
		return err
	}
	*r = out
	return nil
}

func (r *AnalysisReport) convertLegacyEntries(entries []json.RawMessage, clients []legacyClientEntry, uses []json.RawMessage) error {
	r.Entries = []EntryPoint{}
	r.Uses = []CandidateUse{}
	routes := map[string]string{}
	clientsByID := map[string]string{}
	for _, raw := range entries {
		var old legacyEntry
		if err := json.Unmarshal(raw, &old); err != nil {
			return err
		}
		if old.Route.ID == "" {
			return fmt.Errorf("legacy route identity missing")
		}
		id := "entry:legacy:http:" + old.Route.ID
		e := EntryPoint{ID: id, Kind: "http", Name: old.Route.Method + " " + old.Route.PathPattern, InstanceID: "legacy:" + old.Route.Registration.File, Location: r.legacyLocation(old.Route.Registration), HTTP: &HTTPEntryMetadata{Method: old.Route.Method, Path: old.Route.PathPattern, Framework: old.Route.Framework}, Gaps: old.Gaps}
		routes[old.Route.ID] = id
		r.addLegacyEntry(e, old.Handler)
		r.Registrations[len(r.Registrations)-1].DeclaredHandler = &old.Route.Handler
		r.Registrations[len(r.Registrations)-1].SyntaxSteps = old.Route.Steps
	}
	for _, old := range clients {
		id := "entry:legacy:browser:" + old.ID
		e := EntryPoint{ID: id, Kind: "browser", Name: old.Name, InstanceID: "legacy:" + old.Location.File, Location: r.legacyLocation(old.Location), Browser: &BrowserEntryMetadata{Category: old.Kind, Framework: old.Framework}}
		clientsByID[old.ID] = id
		r.addLegacyEntry(e, nil)
	}
	for _, raw := range uses {
		type candidateWire CandidateUse
		var old struct {
			candidateWire
			RouteID  string `json:"route_id"`
			ClientID string `json:"client_id"`
		}
		if err := json.Unmarshal(raw, &old); err != nil {
			return err
		}
		u := CandidateUse(old.candidateWire)
		u.EntryID = routes[old.RouteID]
		if old.ClientID != "" {
			u.EntryID = clientsByID[old.ClientID]
		}
		if old.RouteID != "" && old.ClientID != "" {
			u.EntryID = ""
		} // Do not guess which conflicting exposure was intended.
		if u.EntryID == "" {
			u.EntryID = "entry:legacy:unresolved:" + u.ID
			e := EntryPoint{ID: u.EntryID, Kind: "unknown", Name: "Unresolved legacy entry", InstanceID: "legacy:unresolved", Location: u.Sink, Gaps: []Gap{{Kind: "legacy_entry_unresolved", Detail: "Saved use has missing or ambiguous entry association", At: u.Sink.Span}}}
			r.addLegacyEntry(e, nil)
		}
		u.InvocationContextID = "invocation:" + u.EntryID
		normalizeUseRoles(&u)
		r.Uses = append(r.Uses, u)
	}
	for i := range r.Uses {
		x := r.Uses[i].XSS
		if x == nil {
			continue
		}
		for j, id := range x.RelatedEntries {
			if current := routes[id]; current != "" {
				x.RelatedEntries[j] = current
			}
		}
		for j, p := range x.Paths {
			if current := routes[p.Entry]; current != "" {
				x.Paths[j].Entry = current
			}
		}
	}
	return r.validateReferences()
}

func (r *AnalysisReport) legacyLocation(span Span) Evidence {
	e := Evidence{Kind: "legacy_registration", Span: span}
	for _, file := range r.Files {
		if file.Span.File == span.File {
			e.SHA256 = file.SHA256
			break
		}
	}
	return e
}

func (r *AnalysisReport) addLegacyEntry(e EntryPoint, handler *Evidence) {
	gap := Gap{Kind: "legacy_invocation_unavailable", Detail: "Saved schema lacks explicit invocation bindings and dispatch completeness", At: e.Location.Span}
	reg := EntryRegistration{ID: "registration:" + e.ID, EntryID: e.ID, Origin: e.Location}
	b := DispatchBinding{ID: "dispatch:" + e.ID, EntryID: e.ID, RegistrationID: reg.ID, Mechanism: "legacy_source_slice", Resolution: "unresolved", Gaps: []Gap{gap}}
	if handler != nil {
		key, err := SnapshotRecordID("callable", *handler, handler.Span.File, "legacy-body")
		if err != nil {
			key = "callable:" + e.ID
		}
		found := false
		for _, f := range r.Callables {
			found = found || f.ID == key
		}
		if !found {
			r.Callables = append(r.Callables, Callable{ID: key, Language: "unknown", Definition: *handler})
		}
		b.CallableID = key
		b.Resolution = "partial"
	}
	r.Entries = append(r.Entries, e)
	r.Registrations = append(r.Registrations, reg)
	r.DispatchBindings = append(r.DispatchBindings, b)
	r.InvocationContexts = append(r.InvocationContexts, InvocationContext{ID: "invocation:" + e.ID, EntryID: e.ID, DispatchBindingID: b.ID, Gaps: []Gap{gap}})
}

func normalizeUseRoles(u *CandidateUse) {
	role := func(s string) string {
		switch s {
		case "request_source":
			return "input_source"
		case "route_handler":
			return "invoked_callable"
		}
		return s
	}
	ev := func(e *Evidence) { e.Kind = role(e.Kind) }
	ev(&u.Sink)
	for i := range u.Context {
		ev(&u.Context[i])
	}
	for i := range u.Dependencies {
		ev(&u.Dependencies[i].Source)
		for j := range u.Dependencies[i].Transfers {
			ev(&u.Dependencies[i].Transfers[j])
		}
	}
	for i := range u.ControlEdges {
		ev(&u.ControlEdges[i].From)
		ev(&u.ControlEdges[i].To)
	}
	if c := u.Completeness; c != nil {
		for i := range c.Required {
			c.Required[i] = role(c.Required[i])
		}
		evidence := map[string][]Evidence{}
		keys := []string{}
		for key := range c.Evidence {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			values := c.Evidence[key]
			for i := range values {
				ev(&values[i])
			}
			evidence[role(key)] = append(evidence[role(key)], values...)
		}
		c.Evidence = evidence
	}
}
