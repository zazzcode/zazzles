package report

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

type entryDetail struct{ Label, Value string }
type entryView struct {
	Label     string
	Details   []entryDetail
	Locations []analysis.Evidence
}

func entryPresentation(e analysis.EntryPoint) entryView {
	v := entryView{Label: e.Name, Locations: []analysis.Evidence{e.Location}}
	add := func(label, value string) {
		if value != "" {
			v.Details = append(v.Details, entryDetail{label, value})
		}
	}
	switch e.Kind {
	case "http":
		if m := e.HTTP; m != nil {
			v.Label = strings.TrimSpace(m.Method + " " + m.Path)
			add("Mount", m.Mount)
			add("Receiver", m.Receiver)
			add("Framework", m.Framework)
		}
	case "browser":
		if m := e.Browser; m != nil {
			add("Category", m.Category)
			add("Event", m.Event)
			add("Target", m.Target)
			add("Framework", m.Framework)
		}
	case "graphql":
		if m := e.GraphQL; m != nil {
			v.Label = strings.Trim(m.Type+"."+m.Field, ".")
			add("Operation", m.Operation)
		}
	case "grpc":
		if m := e.GRPC; m != nil {
			service := m.Service
			if m.Package != "" {
				service = m.Package + "." + service
			}
			v.Label = strings.Trim(service+"/"+m.Method, "/")
			add("Client streaming", fmt.Sprint(m.ClientStreaming))
			add("Server streaming", fmt.Sprint(m.ServerStreaming))
		}
	default:
		add("Unresolved metadata", "Unknown entry kind: "+e.Kind)
	}
	if v.Label == "" {
		v.Label = e.ID
		add("Metadata", "Entry identity details unresolved")
	}
	add("Entry ID", e.ID)
	add("Instance", e.InstanceID)
	if len(e.UnknownMetadata) > 0 {
		add("Available metadata", string(e.UnknownMetadata))
	}
	for _, t := range e.Transports {
		add("Transport", t.Kind+" "+t.EntryID)
		v.Locations = append(v.Locations, t.Evidence...)
	}
	return v
}

func entryDetails(r *analysis.AnalysisReport, e analysis.EntryPoint) entryView {
	v := entryPresentation(e)
	if e.Access != nil {
		roles := strings.Join(e.Access.Roles, ", ")
		if roles == "" {
			roles = "none"
		}
		v.Details = append(v.Details, entryDetail{"Access", e.Access.Authentication + " " + roles})
	}
	for _, reg := range r.Registrations {
		if reg.EntryID == e.ID {
			v.Details = append(v.Details, entryDetail{"Registration", reg.ID})
			v.Locations = append(v.Locations, reg.Origin)
			v.Locations = append(v.Locations, reg.DerivedFrom...)
		}
	}
	callables := map[string]bool{}
	for _, b := range r.DispatchBindings {
		if b.EntryID == e.ID {
			v.Details = append(v.Details, entryDetail{"Dispatch", fmt.Sprintf("%s · %s · %s · stage %d · %s", b.ID, b.Mechanism, b.Resolution, b.Stage, b.Alternative)})
			callables[b.CallableID] = true
			v.Locations = append(v.Locations, b.Conditions...)
		}
	}
	for _, c := range r.Callables {
		if callables[c.ID] {
			v.Details = append(v.Details, entryDetail{"Callable", c.Name + " " + c.ID})
			v.Locations = append(v.Locations, c.Definition)
		}
	}
	for _, c := range r.InvocationContexts {
		if c.EntryID == e.ID {
			data, _ := json.Marshal(c)
			v.Details = append(v.Details, entryDetail{"Invocation context", string(data)})
		}
	}
	sort.SliceStable(v.Details, func(i, j int) bool {
		return v.Details[i].Label < v.Details[j].Label || v.Details[i].Label == v.Details[j].Label && v.Details[i].Value < v.Details[j].Value
	})
	return v
}

// EntryLabel returns the kind-specific identity used by human-facing exports.
func EntryLabel(e analysis.EntryPoint) string { return entryPresentation(e).Label }
