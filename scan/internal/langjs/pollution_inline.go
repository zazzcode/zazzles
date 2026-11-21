package langjs

import (
	"slices"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

func (f *flow) pollutionInlineAssignment(site, lhs *sitter.Node) {
	if f.depth != 0 {
		return
	}
	handler := enclosingFunction(site)
	if handler == nil {
		return
	}
	for i, w := range f.set.inlinePollutionWrites(f.module, handler)[site.Id()] {
		if !pollutionInlinePathStable(f.module, handler, w.pathOrigin, site) {
			continue
		}
		v := f.pollutionReadValue(w.pathOrigin)
		if !pollutionRequest([]value{v}) {
			continue
		}
		binding := []analysis.Evidence{
			f.module.evidence("sink_binding", lhs),
			f.module.evidence("sink_binding", w.rootDecl),
			f.module.evidence("prototype_write", site),
			f.module.evidence("prototype_walk", w.walk),
		}
		facts := &analysis.PollutionFacts{Operation: analysis.PollutionWalk, KeyOperand: w.operand}
		f.recordPollution(site, i, []pollutionOperand{{node: w.pathOrigin, value: v, splitPath: true}}, facts, binding, w.guard)
	}
}

// An inline operand is evaluated at the final assignment. Ensure the value
// still names the split input, including its container when it is a field.
func pollutionInlinePathStable(m *sourceModule, handler, origin, site *sitter.Node) bool {
	base, path := pollutionStartPath(origin, m.src)
	if base == nil {
		return false
	}
	decl, _ := pollutionStartBinding(m, base)
	if decl == nil {
		return false
	}
	from := origin.StartByte()
	if len(path) > 0 {
		from = handler.StartByte()
	}
	return pollutionStartStableBetween(m, base, path, decl, from, site.StartByte())
}

// The walk shape is independent of invocation, but the inline path's origin
// is evaluated in the handler flow at the assignment.
func (s *moduleSet) inlinePollutionWrites(m *sourceModule, handler *sitter.Node) map[uintptr][]pollutionWrite {
	if s.pollutionInline == nil {
		s.pollutionInline = make(map[uintptr]map[uintptr][]pollutionWrite)
	}
	if writes, ok := s.pollutionInline[handler.Id()]; ok {
		return writes
	}
	writes := map[uintptr][]pollutionWrite{}
	body := handler.ChildByFieldName("body")
	pollutionWalk(body, func(n *sitter.Node) {
		for _, w := range pollutionPathWalks(m, body, n, nil, nil) {
			id := w.sites[0].Id()
			writes[id] = append(writes[id], w)
		}
	})
	s.pollutionInline[handler.Id()] = writes
	return writes
}

func pollutionWalkControlCovered(u *analysis.CandidateUse, g analysis.Gap) bool {
	if g.Kind != "control_flow_unresolved" && g.Kind != "unsupported_control_flow" {
		return false
	}
	return slices.ContainsFunc(u.Context, func(e analysis.Evidence) bool {
		return e.Kind == "prototype_walk" && e.Span == g.At
	})
}
