package parse

import (
	"fmt"
	"github.com/zazzcode/zazzles/internal/analysis"
)

// interpreterChainEvidence recognizes the existing authentication adapter in
// applicable global middleware as well as route middleware. It changes only
// these families; authentication is context, never an operand restriction.
func (s *moduleSet) interpreterChainEvidence(r *analysis.AnalysisReport, check analysis.Check, u *analysis.CandidateUse) ([]analysis.Evidence, []analysis.Gap) {
	if u.EntryKind == "browser" {
		return nil, nil
	}
	chain, gaps := s.pathChainEvidence(r, check, u)
	covered := map[string]int{}
	var adapters []analysis.Evidence
	for _, e := range chain {
		if e.Kind != "middleware_registration" {
			continue
		}
		m := s.modules[e.Span.File]
		if m == nil {
			continue
		}
		call := nodeAt(m.tree.RootNode(), e.Span.StartByte, e.Span.EndByte)
		if call == nil {
			continue
		}
		args := call.ChildByFieldName("arguments")
		if args == nil {
			continue
		}
		for i := uint(0); i < args.NamedChildCount(); i++ {
			arg := args.NamedChild(i)
			adapter := s.authenticationAdapter(m, arg)
			if len(adapter) == 0 {
				continue
			}
			adapters = append(adapters, adapter...)
			_, _, _, missing := s.handler(m, arg)
			for _, g := range missing {
				g.Kind = "applicable_middleware_unresolved"
				covered[fmt.Sprintf("%s|%s|%v", g.Kind, g.Detail, g.At)]++
			}
		}
	}
	kept := []analysis.Gap{}
	for _, g := range gaps {
		key := fmt.Sprintf("%s|%s|%v", g.Kind, g.Detail, g.At)
		if covered[key] > 0 {
			covered[key]--
			continue
		}
		kept = append(kept, g)
	}
	return append(chain, adapters...), kept
}
