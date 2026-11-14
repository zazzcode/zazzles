package parse

import "github.com/zazzcode/zazzles/internal/analysis"

// pathChainEvidence uses the resolved invocation's stage, so handlers that run
// after this operation cannot become its validators or unresolved predecessors.
func (s *moduleSet) pathChainEvidence(report *analysis.AnalysisReport, check analysis.Check, u *analysis.CandidateUse) ([]analysis.Evidence, []analysis.Gap) {
	c := s.nodeHTTP[u.EntryID]
	if c == nil || !c.pathOnly {
		return s.chainEvidence(report, check)
	}
	m := c.registration
	r := c.entry.HTTPRoute()
	context, gaps := s.middlewareContext(m, r)
	context = append(context, m.evidence("route_registration", c.call))
	args := c.call.ChildByFieldName("arguments")
	if args == nil {
		return context, gaps
	}
	for i := uint(1); i < args.NamedChildCount() && i <= uint(c.pathIndex); i++ {
		arg := args.NamedChild(i)
		if adapter := pathUploadAdapter(m, arg); len(adapter) > 0 {
			context = append(context, adapter...)
			continue
		}
		if adapter := s.authenticationAdapter(m, arg); len(adapter) > 0 {
			context = append(context, adapter...)
			continue
		}
		if transportMiddleware(m, arg) {
			continue
		}
		hm, node := s.pathHandler(m, arg)
		if hm == nil {
			_, _, _, missing := s.handler(m, arg)
			gaps = append(gaps, missing...)
			continue
		}
		_, body, req, missing := s.handler(hm, node)
		if body == nil {
			gaps = append(gaps, missing...)
			continue
		}
		if req == "" {
			parts, rest := requestParts(hm, body, missing)
			_, missing = pathRequestParts(hm, body, parts, rest)
		}
		gaps = append(gaps, missing...)
		context = append(context, hm.evidence("invoked_callable", body))
		gaps = append(gaps, s.inputHelperGaps(hm, body, req, check.Fields)...)
	}
	return context, gaps
}
