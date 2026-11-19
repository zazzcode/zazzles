package report

import (
	"fmt"
	"sort"

	"github.com/zazzcode/zazzles/internal/analysis"
)

// assessmentState reports whether the use's semantic assessment ran. An empty
// status is an unjudged record.
func assessmentState(u analysis.CandidateUse) string {
	switch u.Assessment.Status {
	case "completed", "failed":
		return u.Assessment.Status
	}
	return "not_run"
}

// assessmentLabel is the short display marker separating judged from unjudged
// records, so an unjudged poor_practice is not read as a judged one.
func assessmentLabel(state string) string {
	switch state {
	case "completed":
		return "Judged"
	case "failed":
		return "Judge failed"
	}
	return "Not judged"
}

// externalOriginNotEstablished is the Review reason for a construction record
// with no external-origin dependency.
const externalOriginNotEstablished = "external_origin_not_established"

// blockingEvidence names the claim-relevant evidence that keeps a Review record
// from a final outcome. Judged records report the policy's blocking gaps;
// otherwise the candidate's own blockers, missing required roles and gaps are
// listed. Nothing is invented or discharged: every entry comes from the record.
func blockingEvidence(u analysis.CandidateUse, f analysis.Finding) []analysis.BlockingReason {
	if f.Status != "needs_review" && f.Status != "needs_evidence" {
		return nil
	}
	var out []analysis.BlockingReason
	seen := map[string]bool{}
	add := func(kind, detail, source string, at *analysis.Span) {
		key := fmt.Sprintf("%s|%s|%s", kind, detail, source)
		if at != nil {
			key += fmt.Sprintf("|%s:%d:%d", at.File, at.StartByte, at.EndByte)
		}
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, analysis.BlockingReason{Kind: kind, Detail: detail, Source: source, At: at})
	}
	gap := func(g analysis.Gap, source string) {
		var at *analysis.Span
		if g.At.File != "" {
			s := g.At
			at = &s
		}
		add(g.Kind, g.Detail, source, at)
	}
	if constructionWithoutOrigin(u) {
		s := u.Sink.Span
		add(externalOriginNotEstablished, "No dependency of this query construction has a request, storage, file, fetched, browser or API-response origin, so external control is not established.", "scanner", &s)
	}
	if (u.Assessment.Status == "completed" || u.Assessment.Status == "not_run") && len(u.Assessment.BlockingGaps) > 0 {
		for _, g := range u.Assessment.BlockingGaps {
			gap(g, "policy")
		}
		return sortedReasons(out)
	}
	if c := u.Completeness; c != nil {
		for _, g := range c.Blockers {
			gap(g, "scanner")
		}
		for _, role := range c.Required {
			if len(c.Evidence[role]) == 0 {
				add("missing_evidence:"+role, "Required evidence role "+role+" has no recorded evidence.", "scanner", nil)
			}
		}
	}
	for _, g := range u.Gaps {
		gap(g, "scanner")
	}
	if u.Kind == "outbound_http_candidate" && constantDestination(u) {
		s := u.Sink.Span
		add("constant_destination_no_request_dependency", "The destination origin is a constant and no request value reaches the destination operand; request values reach only headers or body, so no destination-control (SSRF) claim is formed for this call.", "scanner", &s)
	}
	return sortedReasons(out)
}

func sortedReasons(r []analysis.BlockingReason) []analysis.BlockingReason {
	sort.SliceStable(r, func(i, j int) bool {
		a, b := r[i], r[j]
		if a.Source != b.Source {
			return a.Source > b.Source // policy first
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.Detail < b.Detail
	})
	return r
}

// constantDestination reports an outbound candidate whose destination origin is
// a constant and whose destination operand has no request dependency path.
func constantDestination(u analysis.CandidateUse) bool {
	return u.Outbound != nil && u.Outbound.DestinationOrigin == analysis.DestinationConstant && len(u.Outbound.Paths) == 0
}

// claimFamily groups candidate kinds that are one claim family.
func claimFamily(u analysis.CandidateUse) string {
	switch {
	case u.Redirect != nil:
		return "redirect"
	case u.Code != nil:
		return "code"
	}
	switch u.Kind {
	case "outbound_http_candidate", "ssrf_candidate":
		return "outbound"
	}
	return u.Kind
}

// linkIndependentClaims makes each of two or more claims of different families
// on one operation (same file, sink span and invocation context) list the
// others. Every record is kept; none is merged or dropped.
func linkIndependentClaims(r *analysis.AnalysisReport) {
	type site struct {
		file       string
		start, end int
		context    string
	}
	groups := map[site][]int{}
	for i, u := range r.Uses {
		if i >= len(r.Findings) || r.Findings[i].GroupedInto != "" || u.Sink.Span.File == "" {
			continue
		}
		k := site{u.Sink.Span.File, u.Sink.Span.StartByte, u.Sink.Span.EndByte, u.InvocationContextID}
		groups[k] = append(groups[k], i)
	}
	for _, idx := range groups {
		for _, i := range idx {
			var ids []string
			for _, j := range idx {
				if j != i && claimFamily(r.Uses[j]) != claimFamily(r.Uses[i]) {
					ids = append(ids, r.Uses[j].ID)
				}
			}
			if len(ids) > 0 {
				sort.Strings(ids)
				r.Findings[i].LinkedUseIDs = ids
			}
		}
	}
}

// explainOutcomes fills the assessment, blocking and linked-claim fields.
func explainOutcomes(r *analysis.AnalysisReport) {
	for i := range r.Findings {
		if i >= len(r.Uses) {
			break
		}
		r.Findings[i].AssessmentState = assessmentState(r.Uses[i])
		r.Findings[i].BlockingEvidence = blockingEvidence(r.Uses[i], r.Findings[i])
	}
	linkIndependentClaims(r)
}
