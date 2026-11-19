package parse

import (
	"fmt"

	"github.com/zazzcode/zazzles/internal/analysis"
)

// Assemble merges language reports in the fixed JS/TS, Python, PHP order and
// finalizes the merge once. A nil report is a language that did not run. A
// Python or PHP entry passes only that runner's report, which is already final
// and is returned unchanged.
func Assemble(entry string, js, py, php *analysis.AnalysisReport) (*analysis.AnalysisReport, error) {
	if js == nil {
		if entry == "" || (py == nil) == (php == nil) {
			return nil, fmt.Errorf("assemble: a report without JS/TS needs exactly one Python or PHP entry report")
		}
		if py != nil {
			KeepStoredOriginFacts(py)
			return py, nil
		}
		KeepStoredOriginFacts(php)
		return php, nil
	}
	out := js
	for _, more := range []*analysis.AnalysisReport{py, php} {
		if more == nil {
			continue
		}
		out.MergeEntries(more)
		out.Uses = append(out.Uses, more.Uses...)
		out.Gaps = append(out.Gaps, more.Gaps...)
		out.Files = append(out.Files, more.Files...)
		if len(more.Entries) > 0 {
			out.Limitations = append(out.Limitations, more.Limitations...)
			out.AnalysisGuidelines = append(out.AnalysisGuidelines, more.AnalysisGuidelines...)
		}
	}
	if err := FinalizeEntries(out); err != nil {
		return nil, err
	}
	blockUnlinkedStoredOrigins(out)
	KeepStoredOriginFacts(out)
	linkNavigationClaims(out)
	return out, nil
}

func linkNavigationClaims(out *analysis.AnalysisReport) {
	for i := range out.Uses {
		u := &out.Uses[i]
		if u.Redirect == nil {
			continue
		}
		for _, other := range out.Uses {
			if other.XSS != nil && other.Kind == "xss_candidate" && other.Sink.Span == u.Sink.Span && other.InvocationContextID == u.InvocationContextID {
				u.Redirect.RelatedUse = other.ID
				if u.Completeness != nil {
					u.Completeness.ModelFacts = append(u.Completeness.ModelFacts, "redirect_also_xss")
				}
				break
			}
		}
	}
}
