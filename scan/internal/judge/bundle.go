package judge

import (
	"fmt"
	"sort"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

// wireBundle sends each source span once. Edges and role references point into
// the same evidence table, avoiding repeated handler/model bodies in the prompt.
func wireBundle(use analysis.CandidateUse) any {
	table := []analysis.Evidence{}
	ids := map[string]string{}
	ref := func(e analysis.Evidence) string {
		key := fmt.Sprintf("%s:%s:%d:%d:%s", e.SHA256, e.Span.File, e.Span.StartByte, e.Span.EndByte, e.Kind)
		if id := ids[key]; id != "" {
			return id
		}
		id := fmt.Sprintf("e%d", len(table))
		ids[key] = id
		table = append(table, e)
		return id
	}
	edges := []map[string]string{}
	for _, e := range use.ControlEdges {
		edges = append(edges, map[string]string{"from": ref(e.From), "to": ref(e.To), "kind": e.Kind})
	}
	sink := ref(use.Sink)
	context := []string{}
	for _, e := range use.Context {
		context = append(context, ref(e))
	}
	dependencies := []map[string]any{}
	for _, d := range use.Dependencies {
		steps := []string{}
		for _, e := range d.Transfers {
			steps = append(steps, ref(e))
		}
		dep := map[string]any{"source": ref(d.Source), "transfers": steps, "sink_slot": d.SinkSlot, "storage_key": d.StorageKey}
		if len(d.Transforms) > 0 {
			// Exactly stated transforms ride their chain; records without one
			// keep their request bytes.
			transforms := []map[string]any{}
			for _, x := range d.Transforms {
				transforms = append(transforms, map[string]any{"kind": x.Kind, "pattern": x.Pattern, "flags": x.Flags, "group": x.Group, "sub_pattern": x.SubPattern, "class": x.Class, "alphabet": x.Alphabet, "line": x.At.StartLine})
			}
			dep["transforms"] = transforms
		}
		dependencies = append(dependencies, dep)
	}
	roles := map[string][]string{}
	var required []string
	var blockers, coverage []analysis.Gap
	scope := "bounded local candidate; unresolved facts remain unknown"
	if c := use.Completeness; c != nil {
		required = c.Required
		blockers = c.Blockers
		coverage = c.Coverage
		scope = c.Scope
		keys := []string{}
		for k := range c.Evidence {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			for _, e := range c.Evidence[k] {
				roles[k] = append(roles[k], ref(e))
			}
		}
	} else {
		blockers = use.Gaps
	}
	obligations := map[string]bool{}
	for _, role := range required {
		obligations[role] = true
	}
	if use.Components != nil {
		for _, role := range use.Components.Required {
			obligations[role] = true
		}
	}
	required = make([]string, 0, len(obligations))
	for role := range obligations {
		required = append(required, role)
	}
	sort.Strings(required)
	storedOrigin := wireStoredOrigin(use, ref)
	augmentRoles(use, roles, ref)
	invocation := wireInvocation(use, ref)
	inputFacts := wireInputFacts(use, ref)
	wireTable, excerpts := sharedSourceExcerpts(table)
	return struct {
		Invocation      any                 `json:"invocation"`
		EvidenceVersion int                 `json:"evidence_version"`
		TraceGraph      traceGraph          `json:"trace_graph"`
		CoverageLedger  []evidenceCoverage  `json:"evidence_coverage"`
		ClaimKind       string              `json:"claim_kind"`
		ID              string              `json:"candidate_id"`
		Kind            string              `json:"kind"`
		Check           *analysis.Check     `json:"declared_requirement,omitempty"`
		Sink            string              `json:"sink_evidence"`
		Context         []string            `json:"context_evidence"`
		Dependencies    []map[string]any    `json:"dependencies"`
		Required        []string            `json:"required_evidence"`
		Blockers        []analysis.Gap      `json:"blocking_gaps"`
		Coverage        []analysis.Gap      `json:"coverage_gaps"`
		Scope           string              `json:"scope"`
		Evidence        []wireEvidence      `json:"evidence"`
		SourceExcerpts  []analysis.Evidence `json:"source_excerpts"`
		ControlEdges    []map[string]string `json:"control_edges"`
		ModelFacts      []string            `json:"model_facts,omitempty"`
		Resolved        []analysis.Gap      `json:"resolved_gaps,omitempty"`
		APIModel        *analysis.APIModel  `json:"api_model,omitempty"`
		XSS             *analysis.XSSFacts  `json:"xss,omitempty"`
		Command         any                 `json:"command,omitempty"`
		Path            any                 `json:"path,omitempty"`
		InputFacts      any                 `json:"input_facts,omitempty"`
		Outbound        any                 `json:"outbound,omitempty"`
		Code            any                 `json:"code,omitempty"`
		Redirect        any                 `json:"redirect,omitempty"`
		StoredOrigin    any                 `json:"stored_origin,omitempty"`
		Deserialization any                 `json:"deserialization,omitempty"`
		Upload          any                 `json:"upload,omitempty"`
		Pollution       any                 `json:"pollution,omitempty"`
	}{invocation, 8, buildTraceGraph(use, ref), coverageLedger(required, roles), claimKind(use), use.ID, use.Kind, use.Check, sink, context, dependencies, required, blockers, coverage, scope, wireTable, excerpts, edges, modelFacts(use), resolvedGaps(use), use.APIModel, use.XSS, wireContextFacts(use.Command, context, false), wireContextFacts(use.Path, context, true), inputFacts, wireContextFacts(wireOutbound(use), context, false), wireContextFacts(use.Code, context, false), wireContextFacts(wireRedirect(use), context, false), storedOrigin, wireDeserialization(use.Deserialization, context), wireUpload(use, context), wireContextFacts(use.Pollution, context, false)}
}

func modelFacts(use analysis.CandidateUse) []string {
	if use.Completeness == nil {
		return nil
	}
	return use.Completeness.ModelFacts
}
func resolvedGaps(use analysis.CandidateUse) []analysis.Gap {
	if use.Completeness == nil {
		return nil
	}
	return use.Completeness.Resolved
}

func claimKind(use analysis.CandidateUse) string {
	if use.Completeness != nil {
		return use.Completeness.ClaimKind
	}
	return "candidate_only"
}

// wireOutbound sends destination facts only for an SSRF claim; outbound
// observations are never sent, so no other request changes.
func wireOutbound(use analysis.CandidateUse) *analysis.OutboundFacts {
	if use.Kind != "ssrf_candidate" {
		return nil
	}
	return use.Outbound
}

func wireRedirect(u analysis.CandidateUse) *analysis.RedirectFacts {
	if u.Redirect == nil {
		return nil
	}
	copy := *u.Redirect
	copy.RelatedUse = ""
	return &copy
}

// wireStoredOrigin sends a record's write census and read queries (W3b,
// D-4) only when the stored-origin question applies, so no other request
// changes. Writes and the schema are evidence rows (eN).
func wireStoredOrigin(use analysis.CandidateUse, ref func(analysis.Evidence) string) any {
	if !storedOriginAskable(use) {
		return nil
	}
	type write struct {
		Evidence string `json:"evidence"`
		Literal  bool   `json:"literal"`
	}
	type store struct {
		Key         string  `json:"key"`
		Writes      []write `json:"writes"`
		StaticRead  bool    `json:"static_read"`
		ClosedStore string  `json:"closed_store"`
		Schema      string  `json:"schema,omitempty"`
	}
	stores := []store{}
	for _, s := range use.StoredOrigin.Stores {
		w := store{Key: s.Key, Writes: []write{}, StaticRead: s.StaticRead, ClosedStore: s.ClosedStore}
		for _, x := range s.Writes {
			w.Writes = append(w.Writes, write{ref(x.Evidence), x.Literal})
		}
		if s.Schema != nil {
			w.Schema = ref(*s.Schema)
		}
		stores = append(stores, w)
	}
	reads := []string{}
	for _, d := range use.Dependencies {
		for _, e := range append([]analysis.Evidence{d.Source}, d.Transfers...) {
			if e.Kind == "storage_query" || e.Kind == "storage_read" {
				reads = append(reads, ref(e))
			}
		}
	}
	return map[string]any{"stores": stores, "read_queries": reads}
}

// wireUpload sends the upload facts with their control indices as context
// IDs; records without upload facts keep their request bytes.
func wireUpload(use analysis.CandidateUse, context []string) any {
	if use.Upload == nil {
		return nil
	}
	return wireContextFacts(use.Upload, context, false)
}

// wireDeserialization projects structured controls and the path control indices.
func wireDeserialization(f *analysis.DeserializationFacts, context []string) any {
	if f == nil {
		return nil
	}
	copyFacts := *f
	copyFacts.Controls = nil
	out := wireContextFacts(copyFacts, context, false).(map[string]any)
	if len(f.Controls) > 0 {
		controls := make([]map[string]string, 0, len(f.Controls))
		for _, control := range f.Controls {
			citation := fmt.Sprintf("invalid_context:%d", control.Context)
			if control.Context >= 0 && control.Context < len(context) {
				citation = context[control.Context]
			}
			controls = append(controls, map[string]string{"kind": control.Kind, "context": citation})
		}
		out["controls"] = controls
	}
	return out
}
