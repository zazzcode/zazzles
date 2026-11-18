package parse

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/lang"
)

func snapshotID(kind string, source analysis.Evidence, owner, key string) string {
	id, err := analysis.SnapshotRecordID(kind, source, owner, key)
	if err != nil { // Retain source-backed discovery gaps; malformed evidence is rejected at finalization.
		return fmt.Sprintf("%s:unresolved:%s:%d:%s", kind, source.Span.File, source.Span.StartByte, key)
	}
	return id
}

func httpEntry(r analysis.Route, source analysis.Evidence, instance string) analysis.EntryPoint {
	return analysis.EntryPoint{ID: snapshotID("entry", source, instance, r.ID+":"+r.Method+":"+r.PathPattern), Kind: "http", Name: r.Method + " " + r.PathPattern, InstanceID: instance, Location: source, HTTP: &analysis.HTTPEntryMetadata{Method: r.Method, Path: r.PathPattern, Framework: r.Framework}}
}

func browserEntry(m *sourceModule, nodeEvidence analysis.Evidence, name, category string) analysis.EntryPoint {
	// A source-scope marker is not a callback registration/body. Relevant bounded
	// excerpts already live in each use; sending the whole module would inflate
	// otherwise bounded judge requests and imply unsupported dispatch evidence.
	nodeEvidence.Text = ""
	nodeEvidence.ModelText = ""
	instance := "browser:" + m.file + ":" + m.hash
	return analysis.EntryPoint{ID: snapshotID("entry", nodeEvidence, instance, category+":"+name), Kind: "browser", Name: name, InstanceID: instance, Location: nodeEvidence, Browser: &analysis.BrowserEntryMetadata{Category: category}}
}

func registerInvocation(out *analysis.AnalysisReport, entry analysis.EntryPoint, handler *analysis.Evidence, mechanism string, inputs []analysis.InputBinding, gaps []analysis.Gap) analysis.InvocationContext {
	reg := analysis.EntryRegistration{ID: snapshotID("registration", entry.Location, entry.ID, "registration"), EntryID: entry.ID, Origin: entry.Location, Gaps: append([]analysis.Gap{}, gaps...)}
	if entry.HTTP != nil {
		reg.Framework = entry.HTTP.Framework
	} else if entry.Browser != nil {
		reg.Framework = entry.Browser.Framework
	}
	binding := analysis.DispatchBinding{ID: snapshotID("dispatch", entry.Location, reg.ID, mechanism), EntryID: entry.ID, RegistrationID: reg.ID, Mechanism: mechanism, Resolution: "unresolved", Gaps: append([]analysis.Gap{}, gaps...)}
	if handler != nil {
		id := snapshotID("callable", *handler, handler.Span.File, "lexical-body")
		binding.CallableID = id
		binding.Resolution = "resolved"
		found := false
		for _, f := range out.Callables {
			found = found || f.ID == id
		}
		if !found {
			// The callable's language follows its file. Unknown extensions keep the
			// historical JavaScript label.
			language := lang.JavaScript
			if detected, ok := lang.Detect(handler.Span.File); ok {
				language = detected
			}
			out.Callables = append(out.Callables, analysis.Callable{ID: id, Language: string(language), Definition: *handler})
		}
	} else if len(binding.Gaps) == 0 {
		binding.Gaps = []analysis.Gap{{Kind: "dispatch_unresolved", Detail: "No supported callable target", At: entry.Location.Span}}
	}
	binding.ID = snapshotID("dispatch", entry.Location, reg.ID, mechanism+":"+binding.CallableID)
	ctx := analysis.InvocationContext{ID: snapshotID("invocation", entry.Location, binding.ID, "default"), EntryID: entry.ID, DispatchBindingID: binding.ID, Inputs: inputs, Gaps: append([]analysis.Gap{}, gaps...)}
	out.Entries = append(out.Entries, entry)
	out.Registrations = append(out.Registrations, reg)
	out.DispatchBindings = append(out.DispatchBindings, binding)
	out.InvocationContexts = append(out.InvocationContexts, ctx)
	return ctx
}

func finalizeEntries(out *analysis.AnalysisReport) error {
	// Helpers can accumulate the same callable across language/browser adapter views.
	seen := map[string]bool{}
	funcs := out.Callables[:0]
	for _, f := range out.Callables {
		if !seen[f.ID] {
			seen[f.ID] = true
			funcs = append(funcs, f)
		}
	}
	out.Callables = funcs
	// Candidate completeness is scoped to this invocation, never matched across sibling registrations.
	for i := range out.Uses {
		u := &out.Uses[i]
		if u.InvocationContextID == "" {
			for _, ctx := range out.InvocationContexts {
				if ctx.EntryID == u.EntryID {
					u.InvocationContextID = ctx.ID
					break
				}
			}
		}
	}
	if err := out.BindUses(); err != nil {
		return err
	}
	enrichInvocationEvidence(out)
	rekeyInvocations(out)
	cat, err := out.Catalog().Canonical()
	if err != nil {
		return err
	}
	out.Entries = cat.Entries
	out.Registrations = cat.Registrations
	out.DispatchBindings = cat.DispatchBindings
	out.Callables = cat.Callables
	out.InvocationContexts = cat.InvocationContexts
	return out.ValidateUses()
}

func (f *flow) seedInvocation() {
	for _, input := range f.invocation.Inputs {
		switch input.Role {
		case "http.request":
			f.request = input.Parameter
		case "http.response":
			f.response = input.Parameter
		case "http.query", "http.body", "http.params", "http.headers":
			if f.parts == nil {
				f.parts = map[string]string{}
			}
			f.parts[input.Parameter] = inputRole(input.Role)
		default:
			v := value{}
			for _, source := range input.Origin.Evidence {
				source.Kind = "input_source"
				v.deps = append(v.deps, analysis.Dependency{Source: source})
			}
			if input.Origin.Kind == "unknown" {
				v.gaps = append(v.gaps, analysis.Gap{Kind: "input_origin_unknown", Detail: input.Role})
			}
			f.env[input.Parameter] = v
		}
	}
}

func httpInput(role, param string, e analysis.Evidence) analysis.InputBinding {
	return analysis.InputBinding{Role: role, Parameter: param, Origin: analysis.InputOrigin{Kind: "external", Evidence: []analysis.Evidence{e}}}
}

func inputRole(role string) string { return strings.TrimPrefix(role, "http.") }

func browserInvocation(entry analysis.EntryPoint) analysis.InvocationContext {
	reg := snapshotID("registration", entry.Location, entry.ID, "registration")
	callable := snapshotID("callable", entry.Location, entry.Location.Span.File, "lexical-body")
	binding := snapshotID("dispatch", entry.Location, reg, "browser_source_slice:"+callable)
	return analysis.InvocationContext{ID: snapshotID("invocation", entry.Location, binding, "default"), EntryID: entry.ID, DispatchBindingID: binding}
}

func enrichInvocationEvidence(out *analysis.AnalysisReport) {
	for i := range out.Uses {
		u := &out.Uses[i]
		ctx := u.InvocationFacts
		if ctx == nil {
			continue
		}
		if c := u.Completeness; c != nil {
			if c.Evidence == nil {
				c.Evidence = map[string][]analysis.Evidence{}
			}
			for _, role := range []string{"entry_registration", "dispatch_binding"} {
				found := false
				for _, r := range c.Required {
					found = found || r == role
				}
				if !found {
					c.Required = append(c.Required, role)
				}
			}
			c.Evidence["entry_registration"] = []analysis.Evidence{u.EntryFacts.Location}
			if u.DispatchFacts.CallableID != "" {
				c.Evidence["dispatch_binding"] = []analysis.Evidence{u.EntryFacts.Location}
			}
			invocationEvidence := []analysis.Evidence{}
			for _, input := range ctx.Inputs {
				invocationEvidence = append(invocationEvidence, input.Origin.Evidence...)
			}
			if len(invocationEvidence) == 0 {
				invocationEvidence = append(invocationEvidence, c.Evidence["persistence_mapping"]...)
			}
			if len(invocationEvidence) > 0 {
				required := false
				for _, role := range c.Required {
					required = required || role == "invocation_binding"
				}
				if !required {
					c.Required = append(c.Required, "invocation_binding")
				}
				c.Evidence["invocation_binding"] = invocationEvidence
			}
			// Framework-generated operations may have a modeled dispatch without
			// a repository callable. Keep that distinction rather than inventing one.
			if u.DispatchFacts.CallableID == "" && len(c.Evidence["persistence_mapping"]) > 0 {
				c.Evidence["dispatch_binding"] = append([]analysis.Evidence{}, c.Evidence["persistence_mapping"]...)
			}

		}
		for _, e := range u.Context {
			switch e.Kind {
			case "guard_test", "conditional_test", conditionalFalseTest, "branch_precondition", "authentication_adapter", "invoked_callable":
				found := false
				for _, control := range ctx.Controls {
					found = found || control.Evidence == e
				}
				if !found {
					ctx.Controls = append(ctx.Controls, analysis.ApplicableControl{InvocationContextID: ctx.ID, DispatchBindingID: ctx.DispatchBindingID, Evidence: e})
				}
			}
		}
	}
}

func rekeyInvocations(out *analysis.AnalysisReport) {
	keys := map[string]string{}
	entries := map[string]analysis.EntryPoint{}
	for _, e := range out.Entries {
		entries[e.ID] = e
	}
	for i := range out.InvocationContexts {
		ctx := &out.InvocationContexts[i]
		controls := []analysis.Evidence{}
		for _, c := range ctx.Controls {
			controls = append(controls, c.Evidence)
		}
		key, _ := json.Marshal(struct {
			Inputs, Closures []analysis.InputBinding
			Receiver         *analysis.InputBinding
			Controls         []analysis.Evidence
			Gaps             []analysis.Gap
		}{ctx.Inputs, ctx.Closures, ctx.Receiver, controls, ctx.Gaps})
		id := snapshotID("invocation", entries[ctx.EntryID].Location, ctx.DispatchBindingID, string(key))
		keys[ctx.ID] = id
		ctx.ID = id
		for j := range ctx.Controls {
			ctx.Controls[j].InvocationContextID = id
		}
	}
	seen := map[string]int{}
	for i := range out.Uses {
		u := &out.Uses[i]
		u.InvocationContextID = keys[u.InvocationContextID]
		key, _ := json.Marshal(struct {
			Kind         string
			Sink         analysis.Evidence
			Dependencies []analysis.Dependency
			Context      []analysis.Evidence
			Check        *analysis.Check
		}{u.Kind, u.Sink, u.Dependencies, u.Context, u.Check})
		id := snapshotID("candidate", entries[u.EntryID].Location, u.InvocationContextID, string(key))
		// Preserve separately inventoried identical observations deterministically;
		// differing operand/call witnesses already have distinct structural keys.
		occurrence := seen[id]
		seen[id]++
		if occurrence > 0 {
			id += fmt.Sprintf(":%d", occurrence)
		}
		u.ID = id
	}
}
