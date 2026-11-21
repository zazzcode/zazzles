package analysis

import (
	"fmt"
	"sort"
	"strings"
)

// EntrySelector identifies portable operations; optional file scope narrows ownership.
type EntrySelector struct {
	Kind             string `json:"kind"`
	Method           string `json:"method,omitempty"`
	Path             string `json:"path,omitempty"`
	Type             string `json:"type,omitempty"`
	Field            string `json:"field,omitempty"`
	Service          string `json:"service,omitempty"`
	Category         string `json:"category,omitempty"`
	Name             string `json:"name,omitempty"`
	Event            string `json:"event,omitempty"`
	RegistrationFile string `json:"registration_file,omitempty"`
}

// KnownEntryKind reports whether selection of a kind is supported.
func KnownEntryKind(kind string) bool {
	return kind == "http" || kind == "browser" || kind == "graphql" || kind == "grpc"
}

// Validate rejects incomplete and incompatible kind-specific selectors.
func (s EntrySelector) Validate() error {
	valid := false
	switch s.Kind {
	case "http":
		valid = s.Method != "" && strings.HasPrefix(s.Path, "/") && s.Type == "" && s.Field == "" && s.Service == "" && s.Category == "" && s.Name == "" && s.Event == ""
	case "graphql":
		valid = s.Type != "" && s.Field != "" && s.Method == "" && s.Path == "" && s.Service == "" && s.Category == "" && s.Name == "" && s.Event == ""
	case "grpc":
		valid = s.Service != "" && s.Method != "" && s.Path == "" && s.Type == "" && s.Field == "" && s.Category == "" && s.Name == "" && s.Event == ""
	case "browser":
		valid = s.Category != "" && s.Name != "" && s.Method == "" && s.Path == "" && s.Type == "" && s.Field == "" && s.Service == ""
	}
	if !valid {
		return fmt.Errorf("invalid %q entry selector: require only kind-specific identity fields", s.Kind)
	}
	if s.RegistrationFile != "" && (strings.HasPrefix(s.RegistrationFile, "/") || strings.Contains(s.RegistrationFile, "\\") || strings.Contains("/"+s.RegistrationFile+"/", "/../")) {
		return fmt.Errorf("selector registration_file must be relative to the target root")
	}
	return nil
}

// EntrySelection records intersecting CLI scope without changing entry identities.
type EntrySelection struct {
	RegistrationFile string `json:"registration_file,omitempty"`
	Route            string `json:"route,omitempty"`
	Kind             string `json:"kind,omitempty"`
	ID               string `json:"id,omitempty"`
}

// CheckMatch records every matched entry/context, including zero-use contexts.
type CheckMatch struct {
	CheckID             string `json:"check_id"`
	EntryID             string `json:"entry_id"`
	InvocationContextID string `json:"invocation_context_id,omitempty"`
	UseCount            int    `json:"use_count"`
}

// NormalizedSelector converts old method/path requirements at the boundary.
func (c Check) NormalizedSelector() EntrySelector {
	if c.Selector != nil {
		return *c.Selector
	}
	return EntrySelector{Kind: "http", Method: c.Method, Path: c.Path}
}

// Matches identifies an entry independently of any finding or protection status.
func (s EntrySelector) Matches(e EntryPoint) bool {
	if s.Kind != e.Kind {
		return false
	}
	switch s.Kind {
	case "http":
		return e.HTTP != nil && e.HTTP.Method == s.Method && e.HTTP.Path == s.Path
	case "graphql":
		return e.GraphQL != nil && e.GraphQL.Type == s.Type && e.GraphQL.Field == s.Field
	case "grpc":
		if e.GRPC == nil {
			return false
		}
		service := e.GRPC.Service
		if e.GRPC.Package != "" {
			service = e.GRPC.Package + "." + service
		}
		return service == s.Service && e.GRPC.Method == s.Method
	case "browser":
		return e.Browser != nil && e.Browser.Category == s.Category && e.Name == s.Name && (s.Event == "" || s.Event == e.Browser.Event)
	}
	return false
}

// MatchesContext applies optional registration-file ownership to an invocation.
func (s EntrySelector) MatchesContext(r *AnalysisReport, c InvocationContext) bool {
	if s.RegistrationFile == "" {
		return true
	}
	for _, b := range r.DispatchBindings {
		if b.ID == c.DispatchBindingID {
			for _, reg := range r.Registrations {
				if reg.ID == b.RegistrationID {
					return reg.Origin.Span.File == s.RegistrationFile
				}
			}
		}
	}
	return false
}

// FilterEntries applies intersecting filters and retains the closed record subset.
func (r *AnalysisReport) FilterEntries(scope EntrySelection) error {
	if scope.Kind != "" && !KnownEntryKind(scope.Kind) {
		return fmt.Errorf("invalid entry kind %q", scope.Kind)
	}
	ids := map[string]bool{}
	for _, e := range r.Entries {
		if scope.Kind != "" && scope.Kind != e.Kind || scope.ID != "" && scope.ID != e.ID {
			continue
		}
		if scope.RegistrationFile != "" {
			fileMatch := e.Location.Span.File == scope.RegistrationFile
			for _, reg := range r.Registrations {
				fileMatch = fileMatch || (reg.EntryID == e.ID && reg.Origin.Span.File == scope.RegistrationFile)
			}
			if !fileMatch {
				continue
			}
		}
		if scope.Route != "" && (e.Kind != "http" || e.HTTP == nil || e.HTTP.Path != scope.Route) {
			continue
		}
		ids[e.ID] = true
	}
	if len(ids) == 0 {
		return fmt.Errorf("selected entry scope was not found in the supported entry inventory")
	}
	r.SelectedScope = &scope
	r.SelectedRoute = scope.Route
	r.SelectEntries(ids)
	return r.BindUses()
}

// RecordCheckMatches exposes selection coverage separately from security findings.
func (r *AnalysisReport) RecordCheckMatches(checks []Check) {
	r.CheckMatches = nil
	for _, check := range checks {
		selector := check.NormalizedSelector()
		matched := false
		for _, e := range r.Entries {
			if !selector.Matches(e) {
				continue
			}
			for _, ctx := range r.InvocationContexts {
				if ctx.EntryID != e.ID || !selector.MatchesContext(r, ctx) {
					continue
				}
				matched = true
				m := CheckMatch{CheckID: check.ID, EntryID: e.ID, InvocationContextID: ctx.ID}
				for _, u := range r.Uses {
					if u.EntryID == e.ID && u.InvocationContextID == ctx.ID && u.Check != nil && u.Check.ID == check.ID {
						m.UseCount++
					}
				}
				r.CheckMatches = append(r.CheckMatches, m)
			}
		}
		if !matched {
			gap := Gap{Kind: "check_selector_missing", Detail: check.ID + ": selector matched zero invocation contexts"}
			found := false
			for _, g := range r.Gaps {
				found = found || g == gap
			}
			if !found {
				r.Gaps = append(r.Gaps, gap)
			}
		}
	}
	sort.Slice(r.CheckMatches, func(i, j int) bool {
		a, b := r.CheckMatches[i], r.CheckMatches[j]
		if a.CheckID != b.CheckID {
			return a.CheckID < b.CheckID
		}
		if a.EntryID != b.EntryID {
			return a.EntryID < b.EntryID
		}
		return a.InvocationContextID < b.InvocationContextID
	})
}

// MatchesFields selects source-role evidence without asserting value transfer or trust.
func MatchesFields(d Dependency, fields []string) bool {
	for _, field := range fields {
		if d.Source.Text == field || strings.HasPrefix(d.Source.Text, field+":") || strings.HasSuffix(d.Source.Text, ".body."+field) || strings.HasSuffix(d.Source.Text, ".payload."+field) || strings.HasSuffix(d.Source.Text, ".query."+field) || strings.HasSuffix(d.Source.Text, ".params."+field) {
			return true
		}
		for _, e := range d.Transfers {
			if e.Kind == "field_projection" && e.Text == field {
				return true
			}
		}
	}
	return false
}
