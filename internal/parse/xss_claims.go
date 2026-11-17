package parse

import (
	"fmt"
	"strings"

	"github.com/zazzcode/zazzles/internal/analysis"
)

// dropCodeOwnedXSS removes a script-context XSS candidate recorded at the same
// operation as a code-injection candidate (eval, Function constructor, timer
// string). The code-injection family owns that operation, so a duplicate XSS
// claim is not emitted. A script-context XSS at any other sink is untouched.
func dropCodeOwnedXSS(report *analysis.AnalysisReport) {
	type key struct {
		file       string
		start, end int
	}
	code := map[key]bool{}
	for _, u := range report.Uses {
		// Only browser eval is code-owned (docs/analysis/code-injection.md);
		// string timers and Function keep their script-context XSS record.
		if u.Code != nil && u.Code.ContractID == "js-eval-v1" {
			code[key{u.Sink.Span.File, u.Sink.Span.StartByte, u.Sink.Span.EndByte}] = true
		}
	}
	if len(code) == 0 {
		return
	}
	kept := report.Uses[:0:0]
	for _, u := range report.Uses {
		if u.Kind == "xss_candidate" && u.XSS != nil && u.XSS.OutputContext == "script" &&
			code[key{u.Sink.Span.File, u.Sink.Span.StartByte, u.Sink.Span.EndByte}] {
			continue
		}
		kept = append(kept, u)
	}
	report.Uses = kept
}

func assembleXSSClaims(report *analysis.AnalysisReport) {
	dropCodeOwnedXSS(report)
	for i := range report.Uses {
		u := &report.Uses[i]
		if u.Kind != "xss_candidate" || u.XSS == nil {
			continue
		}
		c := &analysis.Completeness{ClaimKind: "xss", Required: []string{"render_source", "render_binding", "render_context"},
			Evidence: map[string][]analysis.Evidence{}, Scope: "Bounded source-to-rendering flow; output context and protections are scoped to this sink.",
			Coverage: append([]analysis.Gap{}, u.Gaps...), Blockers: []analysis.Gap{}}
		for _, dep := range u.Dependencies {
			c.Evidence["render_source"] = append(c.Evidence["render_source"], dep.Source)
		}
		for _, e := range u.Context {
			if e.Kind == "render_binding" {
				c.Evidence["render_binding"] = append(c.Evidence["render_binding"], e)
			}
		}
		c.Evidence["render_context"] = []analysis.Evidence{u.Sink}
		for _, e := range u.Context {
			if e.Kind == "render_markup_context" {
				c.Evidence["render_context"] = append(c.Evidence["render_context"], e)
			}
		}
		if u.XSS.Protection == "unknown" || u.XSS.OutputContext == "unknown" || u.XSS.OutputContext == "mixed" {
			c.Blockers = append(c.Blockers, analysis.Gap{Kind: "render_protection_unresolved", Detail: u.XSS.ProtectionReason, At: u.Sink.Span})
		}
		if (u.XSS.Type == "stored" || u.XSS.Type == "cross_tier") && !u.XSS.OriginResolved {
			c.Blockers = append(c.Blockers, analysis.Gap{Kind: "storage_origin_unresolved", Detail: "No complete source-to-storage write link is established.", At: u.Sink.Span})
		}
		for _, gap := range u.Gaps {
			switch gap.Kind {
			case "work_limit", "dependency_limit", "transfer_limit", "gap_limit", "template_parse_unresolved":
				c.Blockers = append(c.Blockers, gap)
			}
		}
		c.ModelFacts = []string{"output_context=" + u.XSS.OutputContext, "protection=" + u.XSS.Protection, fmt.Sprintf("origin_resolved=%t", u.XSS.OriginResolved)}
		if u.XSS.OutputContext == "url" && u.XSS.EntryKind == "client" && navigationSink(u.Sink.Text) {
			c.ModelFacts = append(c.ModelFacts, "browser_navigation_sink: "+u.Sink.Text+" at "+u.Sink.Span.File)
		}
		for _, d := range u.Dependencies {
			if d.Source.Kind == "fetched_content" {
				c.ModelFacts = append(c.ModelFacts, "xss_via_fetched_content: "+u.Sink.Text+" at "+u.Sink.Span.File)
				break
			}
		}
		if strings.Contains(u.Sink.Text, "innerHTML") && scriptReexecution(*u) {
			c.ModelFacts = append(c.ModelFacts, "script_reexecution: "+u.Sink.Text+" at "+u.Sink.Span.File)
		}
		if u.Sink.Kind == "html_response" {
			for _, e := range u.Context {
				if e.Kind == "render_markup_context" {
					c.ModelFacts = append(c.ModelFacts, "claim_output="+e.Text)
				}
			}
		}
		u.Completeness = c
	}
}

// scriptReexecution reports client code that, after the HTML sink, creates new
// script elements to run scripts the inserted markup carried.
func scriptReexecution(u analysis.CandidateUse) bool {
	for _, e := range u.Context {
		if e.Span.File != u.Sink.Span.File || e.Span.StartByte > u.Sink.Span.StartByte || e.Span.EndByte < u.Sink.Span.EndByte {
			continue
		}
		after := e.Text
		if i := strings.Index(after, u.Sink.Text); i >= 0 {
			after = after[i:]
			if strings.Contains(after, `createElement("script")`) || strings.Contains(after, `createElement('script')`) {
				return true
			}
		}
	}
	return false
}

// navigationSink reports a client sink text that navigates the browser.
func navigationSink(text string) bool {
	for _, p := range []string{"location.href", "location =", "location.assign(", "location.replace(", "window.open(", "router.push(", "router.replace("} {
		if strings.Contains(text, p) {
			return true
		}
	}
	return false
}
