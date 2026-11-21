package report

import (
	"fmt"
	"strings"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

func describeXSS(u analysis.CandidateUse, f *analysis.Finding) {
	if u.Kind == "xss_data_candidate" {
		f.Title = "API data needs a rendering link before XSS assessment"
		f.Summary = "Request-derived data is returned as JSON. JSON output is not an HTML rendering sink. Link any browser consumer and its output context before making an XSS claim."
		f.Protection = "No HTML sink has been established for this data edge."
		return
	}
	f.Title = "HTML rendering protection needs review"
	f.Validation = "Input validation is separate from context-appropriate output encoding and sanitization."
	f.Summary = "A source value reaches a rendering operation. Resolve its output context and every transformation before judging XSS."
	if u.XSS == nil {
		return
	}
	x := u.XSS
	if hasGap(u, "render_options_unresolved") {
		f.Title = "Escaped fields observed; request-controlled rendering options need review"
		f.Summary = "The template escapes these field expressions, but the handler also forwards request-derived data as the complete rendering options object. That can affect template selection or engine options. Field escaping alone does not establish protection for this rendering flow."
		f.Protection = x.ProtectionReason
		return
	}
	if x.Type == "cross_tier" && !x.OriginResolved && x.Protection != "encoded" && x.Protection != "sanitized" {
		f.Title = "API response reaches browser output; origin link needs review"
		f.Summary = "A client HTTP response reaches rendering. Link the producing route, response field and source/write origin before judging cross-tier XSS."
		f.Protection = x.ProtectionReason
		return
	}
	f.Protection = "Output context: " + x.OutputContext + ". " + x.ProtectionReason + xssPathSummary(x.Paths)
	if x.Type == "stored" && !x.OriginResolved {
		f.Title = "Stored value reaches HTML output; write origin needs review"
		f.Summary = "A verified storage read reaches rendering, but no matching request-to-storage write is established. Resolve that origin and storage protections before judging stored XSS."
		return
	}
	switch x.Protection {
	case "raw", "ineffective":
		f.RecordType, f.Status = "finding", "poor_practice"
		f.Title = "Untrusted data reaches raw HTML output"
		f.Summary = "A source-backed input flow reaches a verified rendering sink without established context-appropriate encoding or effective sanitization. Correct the output construction; runtime exploit confirmation is separate."
	case "encoded", "sanitized":
		f.RecordType, f.Status = "protection", "protected_for_claim"
		f.Title = "Context-appropriate rendering protection is present"
		f.Summary = "The modeled output uses escaping or a verified sanitizer appropriate to this context. This protects the named rendering claim; other contexts and uses require separate assessment."
	}
}

// xssPathSummary names each differing source path, so an unsafe path stays
// visible beside unresolved or protected siblings at the same sink.
func xssPathSummary(paths []analysis.XSSPath) string {
	if len(paths) == 0 {
		return ""
	}
	var parts []string
	for _, p := range paths {
		part := fmt.Sprintf("path %d %s", p.Dependency+1, p.Protection)
		// Server entry IDs end in METHOD:path; other entries are shown as recorded.
		if fields := strings.SplitN(p.Entry, ":", 5); len(fields) == 5 && fields[0] == "route" {
			part += " (written by " + fields[3] + " " + fields[4] + ")"
		} else if p.Entry != "" {
			part += " (written by " + p.Entry + ")"
		}
		parts = append(parts, part)
	}
	return " Per-path protection: " + strings.Join(parts, "; ") + "."
}
