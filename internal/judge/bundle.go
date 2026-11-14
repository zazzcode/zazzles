package judge

import (
	"fmt"
	"sort"

	"github.com/zazzcode/zazzles/internal/analysis"
)

// wireBundle sends each source span once. Edges and role references point into
// the same evidence table, avoiding repeated handler/model bodies in the prompt.
func wireBundle(use analysis.CandidateUse) any {
	table := []analysis.Evidence{}
	ids := map[string]string{}
	ref := func(e analysis.Evidence) string {
		if e.ModelText != "" && e.Text != "" {
			e.Text = e.ModelText
			e.ModelText = ""
		}
		e.ModelText = ""
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
		dependencies = append(dependencies, map[string]any{"source": ref(d.Source), "transfers": steps, "sink_slot": d.SinkSlot, "storage_key": d.StorageKey})
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
	augmentRoles(use, roles, ref)
	invocation := wireInvocation(use, ref)
	inputFacts := wireInputFacts(use.InputFacts, ref)
	wireTable, excerpts := sharedSourceExcerpts(table)
	return struct {
		Invocation      any                    `json:"invocation"`
		EvidenceVersion int                    `json:"evidence_version"`
		TraceGraph      traceGraph             `json:"trace_graph"`
		CoverageLedger  []evidenceCoverage     `json:"evidence_coverage"`
		ClaimKind       string                 `json:"claim_kind"`
		ID              string                 `json:"candidate_id"`
		Kind            string                 `json:"kind"`
		Check           *analysis.Check        `json:"declared_requirement,omitempty"`
		Sink            string                 `json:"sink_evidence"`
		Context         []string               `json:"context_evidence"`
		Dependencies    []map[string]any       `json:"dependencies"`
		Required        []string               `json:"required_evidence"`
		Roles           map[string][]string    `json:"evidence_roles"`
		Blockers        []analysis.Gap         `json:"blocking_gaps"`
		Coverage        []analysis.Gap         `json:"coverage_gaps"`
		Scope           string                 `json:"scope"`
		Evidence        []wireEvidence         `json:"evidence"`
		SourceExcerpts  []analysis.Evidence    `json:"source_excerpts"`
		ControlEdges    []map[string]string    `json:"control_edges"`
		ModelFacts      []string               `json:"model_facts,omitempty"`
		Resolved        []analysis.Gap         `json:"resolved_gaps,omitempty"`
		APIModel        *analysis.APIModel     `json:"api_model,omitempty"`
		XSS             *analysis.XSSFacts     `json:"xss,omitempty"`
		Command         *analysis.CommandFacts `json:"command,omitempty"`
		Path            *analysis.PathFacts    `json:"path,omitempty"`
		InputFacts      any                    `json:"input_facts,omitempty"`
	}{invocation, 6, buildTraceGraph(use, ref), coverageLedger(required, roles), claimKind(use), use.ID, use.Kind, use.Check, sink, context, dependencies, required, roles, blockers, coverage, scope, wireTable, excerpts, edges, modelFacts(use), resolvedGaps(use), use.APIModel, use.XSS, use.Command, use.Path, inputFacts}
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
