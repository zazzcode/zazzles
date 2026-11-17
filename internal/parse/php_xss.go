package parse

import (
	"strconv"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
)

// recordXSS records a rendering claim at a terminal output operation. PHP
// renders by string interpolation/concatenation ending in echo/print; there is
// no template engine, so the output context is HTML text unless the value
// itself establishes otherwise (D-7).
func (f *phpFlow) recordXSS(sink analysis.Evidence, v phpValue, context string) {
	if len(v.deps) == 0 {
		return
	}
	deps := []analysis.Dependency{}
	paths := []analysis.XSSPath{}
	hasRaw, hasUnknown := false, false
	stored := false
	for _, d := range v.deps {
		p := d.protection
		if p == "escaped_routine" {
			// mysqli_real_escape_string and friends are recorded transforms,
			// never output encoding: their guarantee is SQL-syntax scoped.
			p = "unknown"
		}
		if (p == "encoded" || p == "sanitized") && context != "html_text" && context != "html_attribute" {
			p = "unknown"
		}
		if p == "numeric" || p == "non_content" {
			p = "encoded"
		}
		if p == "" || p == "raw" {
			p = "raw"
		}
		hasRaw = hasRaw || p == "raw"
		hasUnknown = hasUnknown || p == "unknown"
		stored = stored || d.dep.StorageKey != ""
		deps = append(deps, d.dep)
		paths = append(paths, analysis.XSSPath{Dependency: len(deps) - 1, Protection: p})
	}
	p, reason := "encoded", "Every modeled source path is HTML-escaped in HTML text or a quoted non-active attribute."
	if hasUnknown {
		p, reason = "unknown", "A source transformation or output context remains unresolved."
	}
	if hasRaw {
		// A raw witness is scoped to its own source-to-render path; unresolved
		// sibling content merged into the same rendered value stays visible in
		// u.Gaps without voiding the witness.
		p, reason = "raw", "A supported source path reaches HTML without context-appropriate escaping; unknown siblings remain explicit."
	}
	// Protection unknown rides the value's own unresolved paths, and only
	// when no raw path is established (a protection claim requires every
	// modeled path resolved; a finding does not).
	if !hasRaw {
		for _, g := range append([]analysis.Gap{}, v.gaps...) {
			switch g.Kind {
			case "php_loop_unresolved", "php_dynamic_include", "php_call_unresolved", "php_value_unresolved", "dependency_limit", "transfer_limit", "work_limit":
				p, reason = "unknown", "A relevant PHP control or value path is unresolved."
			}
		}
		if v.unknown {
			p = "unknown"
			reason = "A value definition or output alternative is unresolved."
		}
	}
	kind := "reflected"
	if stored {
		kind = "stored"
	}
	u := analysis.CandidateUse{ID: "use:" + f.invocation.ID + ":" + sink.Span.File + ":" + strconv.Itoa(sink.Span.StartByte) + ":xss", EntryID: f.invocation.EntryID, InvocationContextID: f.invocation.ID, Kind: "xss_candidate", Sink: sink, Dependencies: deps, Context: phpDedupeEvidence(f.context), Gaps: append(append([]analysis.Gap{}, f.gaps...), v.gaps...), Assessment: analysis.Assessment{Status: "not_run"}, XSS: &analysis.XSSFacts{Type: kind, EntryKind: "server", OutputContext: context, ContentType: "text/html", Protection: p, ProtectionReason: reason, OriginResolved: !stored, Paths: paths}, APIModel: analysispacks.XSSContract("php-html-output-v1", "php")}
	u.Context = append(u.Context, v.escapes...)
	// The echo/print render binding is the sink itself; the shared XSS claim
	// assembler expects it as role evidence.
	u.Context = append(u.Context, analysis.Evidence{Kind: "render_binding", Text: sink.Text, Span: sink.Span, SHA256: sink.SHA256})
	f.report.Uses = append(f.report.Uses, u)
}
