package parse

import "github.com/zazzcode/zazzles/internal/analysis"

// blockUnlinkedStoredOrigins applies one rule to every non-rendering claim in
// every language: when each operand dependency is a storage read with no linked
// request writer (an ORM row, a server-held keyed store, ...), the value is
// stored data of unresolved origin. It may be attacker-influenced through a
// second-order write the scanner does not model, so the claim stays visible as
// Review with a storage_origin_unresolved blocker; it is neither dropped nor
// judged as request-controlled. Rendering claims apply the same rule in
// assembleXSSClaims. A request dependency beside the stored one is unaffected.
func blockUnlinkedStoredOrigins(report *analysis.AnalysisReport) {
	for i := range report.Uses {
		u := &report.Uses[i]
		if u.Completeness == nil || u.Kind == "xss_candidate" || u.Kind == "xss_data_candidate" || !unlinkedStoredOnly(u.Dependencies) {
			continue
		}
		present := false
		for _, g := range u.Completeness.Blockers {
			present = present || g.Kind == "storage_origin_unresolved"
		}
		if !present {
			u.Completeness.Blockers = append(u.Completeness.Blockers, analysis.Gap{Kind: "storage_origin_unresolved", Detail: "Every operand dependency is a stored value with no linked request writer; second-order origin is unresolved.", At: u.Sink.Span})
		}
	}
}

func unlinkedStoredOnly(deps []analysis.Dependency) bool {
	if len(deps) == 0 {
		return false
	}
	for _, d := range deps {
		if d.Source.Kind != "storage_read" {
			return false
		}
	}
	return true
}
