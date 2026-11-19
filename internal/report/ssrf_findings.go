package report

import (
	"strings"

	"github.com/zazzcode/zazzles/internal/analysis"
)

func describeSSRF(u analysis.CandidateUse, f *analysis.Finding) {
	f.Title = "Outbound destination needs SSRF review"
	f.Summary = "Scan identified a request-derived value reaching the destination operand of an outbound HTTP call. Whether it controls the destination host, and whether a restriction applies, has not been established as a defect or as protected."
	if u.Outbound != nil {
		f.Summary = "Scan identified a request-derived value reaching the destination operand of " + u.Outbound.Operation + ": " + ssrfFlowSummary(u) + ". Destination control, restriction and coverage are assessed as separate facets; request data sent as a body or header is not destination control."
	}
}

// ssrfFlowSummary names the request values that reach the destination.
func ssrfFlowSummary(u analysis.CandidateUse) string {
	var names []string
	for _, d := range u.Dependencies {
		names = append(names, d.Source.Text)
	}
	if len(names) == 0 {
		return "no request value recorded"
	}
	return strings.Join(names, ", ")
}

func confirmSSRF(u analysis.CandidateUse, f *analysis.Finding) {
	f.RecordType, f.Status = "finding", "confirmed_vulnerability"
	f.Title = "Server-side request forgery supported by source analysis"
	f.Summary = "A request-derived value (" + ssrfFlowSummary(u) + ") controls the destination of " + u.Outbound.Operation + " with no enforced destination restriction (CWE-918). This is a static source judgment, not runtime network reachability, DNS, redirect or deployment-policy analysis, or independent Findings Review."
	f.Uncertainty += " Network policy, proxies, cloud metadata reachability and redirect targets are not inferred. Unresolved sibling paths, if any, remain separate blocking or coverage records."
}

func confirmWeakSSRF(u analysis.CandidateUse, f *analysis.Finding) {
	f.RecordType, f.Status = "finding", "poor_practice"
	f.Title = "Outbound destination checked only as a string (poor practice)"
	f.Summary = "A request-derived value controls the destination of " + u.Outbound.Operation + " and is restricted only by an unparsed string prefix, substring or pattern test (CWE-918). Userinfo, alternative host forms and redirects can pass such a test. Parse the URL and compare its scheme and host with an allow-list instead. This is a construction-practice finding, not a confirmed exploit."
}

func ssrfGuidance() Guidance {
	return Guidance{Title: "Keep request data from choosing the outbound destination", Actions: []string{
		"Prefer selecting the destination from a fixed table of trusted URLs by a request-supplied key instead of accepting a URL.",
		"Otherwise parse the URL and require its scheme and host to match a finite allow-list before the request, rejecting on failure. A string prefix, substring or regular-expression test on the raw text is not a restriction.",
		"Disable redirect following, or re-check each redirect target against the same allow-list, and decide whether internal address ranges must be blocked after DNS resolution.",
	}, ExampleStatus: "not_generated; permitted destinations and tests are application-specific"}
}

func ssrfFindingGuidance(u analysis.CandidateUse, at string) Guidance {
	g := ssrfGuidance()
	g.Actions = append([]string{"At " + at + ", stop passing " + ssrfFlowSummary(u) + " as the destination of " + u.Outbound.Operation + " unless it is first restricted to trusted destinations."}, g.Actions...)
	return g
}

// destinationOriginText explains an observation's destination origin.
func destinationOriginText(o *analysis.OutboundFacts) string {
	if o == nil {
		return ""
	}
	switch o.DestinationOrigin {
	case analysis.DestinationRequest:
		return " A request value reaches the destination operand, but the HTTP client binding is not verified, so no SSRF claim is assessed."
	case analysis.DestinationExternalData:
		return " Only stored or remote-response data reaches the destination operand; second-order destinations are recorded, not assessed."
	case analysis.DestinationConstant:
		return " The destination operand is a constant string; request values can affect only the request content."
	case analysis.DestinationEnvironment:
		return " The destination operand is read from the process environment, not from the request."
	}
	return " No request value was established in the destination operand; this is not proof that none can reach it."
}
