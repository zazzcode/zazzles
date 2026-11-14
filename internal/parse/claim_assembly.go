package parse

import (
	"strings"

	"github.com/zazzcode/zazzles/internal/analysis"
)

// claimHooks parameterizes the assembly shared by every process-or-file claim
// family: scoping to the use's own entry, supplied route/middleware context,
// handler control flow, guards and claim-scoped completeness. A family supplies
// only what differs: its facts, guard finder, gap coverage and completeness.
type claimHooks struct {
	kind, checkID, checkKind string
	present                  func(*analysis.CandidateUse) bool
	fields                   func(analysis.CandidateUse, analysis.EntryPoint) []string
	guards                   func(*analysis.CandidateUse) (guards, transforms []analysis.Evidence)
	gapCovered               func(u *analysis.CandidateUse, g analysis.Gap, controlComplete bool, complete, transforms []analysis.Evidence, extra map[string][]analysis.Evidence) bool
	complete                 func(u *analysis.CandidateUse, extra map[string][]analysis.Evidence, blockers, coverage []analysis.Gap) *analysis.Completeness
	// finish records per-path protection from the guards found (guardIndex[i] is the use.Context index of guards[i]).
	finish   func(u *analysis.CandidateUse, c *analysis.Completeness, guards []analysis.Evidence, guardIndex []int)
	contract func(*analysis.CandidateUse) *analysis.APIModel
	// chainGapCovered optionally accepts additional chain/context gaps that do not
	// concern the claim's operand; the operation's own request value never does.
	chainGapCovered func(u *analysis.CandidateUse, g analysis.Gap) bool
}

// namespacedRoles groups a use's context evidence by role. Control-kind evidence
// in a claim-scoped use must not become an applicable control of the shared
// invocation context: that would change the invocation identity and every
// existing sibling candidate ID. The kinds are namespaced with the family prefix
// here and restored as role names.
func namespacedRoles(u *analysis.CandidateUse, prefix string) map[string][]analysis.Evidence {
	for i, e := range u.Context {
		switch e.Kind {
		case "guard_test", "conditional_test", "branch_precondition", "authentication_adapter", "invoked_callable":
			u.Context[i].Kind = prefix + e.Kind
		}
	}
	roles := evidenceRoles(u.Context)
	for kind, items := range roles {
		if strings.HasPrefix(kind, prefix) {
			switch strings.TrimPrefix(kind, prefix) {
			case "guard_test", "conditional_test", "branch_precondition", "authentication_adapter", "invoked_callable":
				roles[strings.TrimPrefix(kind, prefix)] = append(roles[strings.TrimPrefix(kind, prefix)], items...)
				delete(roles, kind)
			}
		}
	}
	return roles
}

func (s *moduleSet) assembleClaims(report *analysis.AnalysisReport, h claimHooks) {
	entries := map[string]analysis.EntryPoint{}
	for _, e := range report.Entries {
		entries[e.ID] = e
	}
	for i := range report.Uses {
		u := &report.Uses[i]
		if u.Kind != h.kind || !h.present(u) || u.Completeness != nil {
			continue
		}
		entry, ok := entries[u.EntryID]
		if !ok {
			continue
		}
		fields := h.fields(*u, entry)
		check := analysis.Check{ID: h.checkID, Kind: h.checkKind, Fields: fields}
		switch entry.Kind {
		case "graphql":
			check.Selector = &analysis.EntrySelector{Kind: "graphql", Type: entry.GraphQL.Type, Field: entry.GraphQL.Field}
		case "grpc":
			service := entry.GRPC.Service
			if entry.GRPC.Package != "" {
				service = entry.GRPC.Package + "." + service
			}
			check.Selector = &analysis.EntrySelector{Kind: "grpc", Service: service, Method: entry.GRPC.Method}
		default:
			check.Method, check.Path = entry.HTTPRoute().Method, entry.HTTPRoute().PathPattern
		}
		s.contextLimits = nil
		s.contextFields = fields
		// Only this invocation's entry supplies chain evidence: a sibling entry with an
		// identical (empty) selector must not contribute its registration gaps.
		scoped := *report
		scoped.Entries = []analysis.EntryPoint{entry}
		chain, chainGaps := s.chainEvidence(&scoped, check)
		chainGaps = s.withoutTransportOnlyGaps(chainGaps)
		blockers := []analysis.Gap{}
		for _, g := range append(append([]analysis.Gap{}, chainGaps...), s.contextLimits...) {
			// The operation itself receives the request value; that is the claim, not a missing helper.
			if g.Kind == "input_helper_unresolved" && g.At.File == u.Sink.Span.File && g.At.StartByte >= u.Sink.Span.StartByte && g.At.EndByte <= u.Sink.Span.EndByte {
				continue
			}
			if h.chainGapCovered != nil && h.chainGapCovered(u, g) {
				continue
			}
			blockers = append(blockers, g)
		}

		// Control flow of the supplied handlers.
		controlComplete := false
		var complete []analysis.Evidence
		extra := map[string][]analysis.Evidence{"invoked_callable": nil}
		for _, e := range u.Context {
			if e.Kind != "handler" {
				continue
			}
			module := s.modules[e.Span.File]
			if module == nil {
				continue
			}
			body := nodeAt(module.tree.RootNode(), e.Span.StartByte, e.Span.EndByte)
			if body == nil {
				continue
			}
			edges, missing := controlContext(module, body)
			u.ControlEdges = append(u.ControlEdges, edges...)
			blockers = append(blockers, missing...)
			controlComplete = len(missing) == 0
			if controlComplete {
				complete = append(complete, e)
			}
			extra["control_flow"] = append(extra["control_flow"], e)
		}
		// Guards that dominate or enclose the call and mention an operand.
		guards, transforms := h.guards(u)
		guardIndex := []int{}
		for _, g := range guards {
			guardIndex = append(guardIndex, len(u.Context))
			u.Context = append(u.Context, g)
		}
		u.Context = append(u.Context, chain...)
		coverage := []analysis.Gap{}
		for _, g := range u.Gaps {
			if h.gapCovered(u, g, controlComplete, complete, transforms, extra) {
				coverage = append(coverage, g)
			} else {
				blockers = append(blockers, g)
			}
		}
		c := h.complete(u, extra, blockers, coverage)
		if len(chain) > 0 && len(chainGaps) == 0 && len(s.contextLimits) == 0 {
			// Supplied route/middleware context supersedes discovery's generic warning.
			remaining := []analysis.Gap{}
			for _, g := range c.Coverage {
				if g.Kind == "middleware_unresolved" {
					c.Resolved = append(c.Resolved, g)
				} else {
					remaining = append(remaining, g)
				}
			}
			c.Coverage = remaining
		}
		for _, t := range transforms {
			c.ModelFacts = append(c.ModelFacts, "Supported transfer "+t.Text+" at "+t.Span.File+" carries its receiver into the result; judge whether its pattern constrains the value. The transfer is not a validator by itself.")
		}
		h.finish(u, c, guards, guardIndex)
		u.Completeness = c
		u.APIModel = h.contract(u)
		u.Gaps = append(append([]analysis.Gap{}, u.Gaps...), c.Blockers...)
		u.Gaps = dedupeGaps(u.Gaps)
		u.Check = nil
	}
}
