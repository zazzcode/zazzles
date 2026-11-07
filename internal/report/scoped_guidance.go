package report

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/zazzcode/zazzles/internal/analysis"
)

func scopedGuidance(u analysis.CandidateUse, f analysis.Finding) Guidance {
	at := fmt.Sprintf("%s:%d", u.Sink.Span.File, u.Sink.Span.StartLine)
	if f.RecordType == "protection" {
		if u.Kind == "input_validation_candidate" && u.Check != nil {
			return Guidance{Title: "Preserve the enforced field constraints", Actions: []string{"Preserve the rejecting guard and return behavior for " + strings.Join(u.Check.Fields, ", ") + " at " + at + ". Exact policy: " + u.Check.Validation, "Test direct HTTP requests for each declared constraint and assert rejection occurs before a sensitive side effect. Do not infer SQL/XSS protection or stronger unstated requirements from this field-policy result."}, ExampleStatus: "no repair proposed for a protected field-policy claim"}
		}
		if u.Kind == "command_execution_candidate" {
			return Guidance{Title: "Preserve the constrained process invocation", Actions: []string{"Preserve at " + at + " the fixed trusted executable, the disabled shell and the rejecting guard that terminates before " + u.Sink.Text + ". Keep operands as separate arguments and keep the finite set of permitted values that cannot be option or shell syntax.", "Keep regression tests for every rejected value and for each branch or invocation that reaches this call; a constraint on one operand or branch never protects another."}, ExampleStatus: "no repair proposed for a protected claim"}
		}
		action := "Preserve the demonstrated protection at " + at + " for this exact operation: " + u.Sink.Text
		if u.XSS != nil {
			action = "Preserve escaping for " + u.Sink.Text + " at " + at + " in " + u.XSS.OutputContext + ". Do not add a trust bypass or disable the verified renderer's autoescape."
		}
		if u.Kind == "sql_query_candidate" {
			action = "Preserve the SQL text/data separation at " + at + ": " + u.Sink.Text + ". Keep values in the driver's separate parameter operand; do not move them into interpolated SQL."
		}
		return Guidance{Title: "Preserve the verified protection", Actions: []string{action, "Keep a regression test with HTML-significant or SQL-significant input, as appropriate to this claim. Input-validation requirements are assessed separately."}, ExampleStatus: "no repair proposed for a protected claim"}
	}
	if f.RecordType != "finding" {
		return investigationGuidance(u, at)
	}
	if u.Kind == "command_execution_candidate" {
		return commandFindingGuidance(u, at)
	}
	if u.Kind == "input_validation_candidate" && u.Check != nil {
		return Guidance{Title: "Enforce the declared field policy on the server", Actions: []string{
			"At " + at + ", validate " + strings.Join(u.Check.Fields, ", ") + " before using or persisting it. Enforce these exact source-declared constraints: " + fieldPolicyText(u),
			"Reject a direct HTTP request that violates each declared constraint and return before any side effect. Reuse an existing applicable server validator when available; browser attributes alone do not enforce this policy.",
			"Test direct requests bypassing the form, including missing, empty, malformed and boundary values relevant to the declared policy, plus a valid request. Assert rejected requests cause no persistence or other sensitive side effect.",
		}, ExampleStatus: "no automatic patch; preserve application-specific response and validation semantics"}
	}
	if u.Kind == "sql_query_candidate" && u.APIModel != nil && u.APIModel.Library == "sqlite3" {
		return sqliteGuidance(u, at)
	}
	if u.XSS != nil {
		return renderingGuidance(u, at)
	}
	g := guidance(u)
	g.Actions = append([]string{"Change the observed operation at " + at + ": " + u.Sink.Text}, g.Actions...)
	if filepath.Ext(u.Sink.Span.File) == ".py" {
		g.Example = ""
		g.ExampleStatus = "no verified source-derived replacement available"
		if u.Kind == "log_sink_candidate" {
			g.Actions = []string{"At " + at + ", remove the identified credential/personal-data operand from " + u.Sink.Text + ". Retain a constant event name and an allow-list of non-sensitive fields.", "Capture the emitted log in a test and assert that neither the original value nor any substring of it is present; test every branch that reaches this call."}
		}
	}
	return g
}
func investigationGuidance(u analysis.CandidateUse, at string) Guidance {
	g := Guidance{Title: "Resolve the specific claim blockers", ExampleStatus: "no patch proposed while the claim is inconclusive", Actions: []string{"Investigate the operation at " + at + ": " + u.Sink.Text + ". Its current Review status does not establish a code defect."}}
	gaps := append([]analysis.Gap{}, u.Assessment.BlockingGaps...)
	if u.Completeness != nil {
		gaps = append(gaps, u.Completeness.Blockers...)
	}
	seen := map[string]bool{}
	for _, gap := range gaps {
		key := gap.Kind + gap.Detail
		if seen[key] {
			continue
		}
		seen[key] = true
		g.Actions = append(g.Actions, fmt.Sprintf("Resolve %s at %s:%d: %s", gap.Kind, gap.At.File, gap.At.StartLine, gap.Detail))
		if len(g.Actions) >= 6 {
			break
		}
	}
	if u.XSS != nil && u.XSS.StorageKey != "" && !u.XSS.OriginResolved {
		g.Actions = append(g.Actions, "Trace the exact persisted field "+u.XSS.StorageKey+" from its writing entry to this read. Supply the write, read and intervening transformation/renderer evidence before labeling this stored-output claim protected.")
	}
	if u.Assessment.Status == "completed" && u.Assessment.FindingStatus == "needs_evidence" {
		detail := "Reconcile the semantic assessment with this exact source claim: " + u.Assessment.Reason
		if u.XSS != nil {
			detail += fmt.Sprintf(" Answers: context=%s; encoding=%s; sanitizer=%s; all paths protected=%s; exposure=%s. Static context=%s, protection=%s. Do not infer a code repair from contradictory answers.", u.Assessment.Answers["output_context"], u.Assessment.Answers["encoding_adequacy"], u.Assessment.Answers["sanitizer_effectiveness"], u.Assessment.Answers["xss_all_paths_protected"], u.Assessment.Answers["xss_exposure"], u.XSS.OutputContext, u.XSS.Protection)
		}
		g.Actions = append(g.Actions, detail)
	}
	if len(g.Actions) == 1 {
		g.Actions = append(g.Actions, "Identify the actual field requirement and the enforced guard before this operation, including rejection/return behavior and any helper body. Assess that requirement separately from the destination's protection.")
	}
	return g
}
func renderingGuidance(u analysis.CandidateUse, at string) Guidance {
	g := Guidance{Title: "Repair this HTML output", ExampleStatus: "source-derived candidate; review intended output semantics and test before applying"}
	for _, e := range u.Context {
		if e.Kind == "event_registration" && u.XSS.OutputContext == "html_text" {
			g.Actions = []string{"At " + at + ", replace the raw HTML construction in " + u.Sink.Text + " with DOM node construction and textContent when the intended output is text.", "If HTML is required, use a verified HTML sanitizer appropriate to this output context before inserting the event-derived value. Event names, input validation and message-origin checks do not encode HTML.", "Test the registered callback with HTML-significant event input and assert the intended text or sanitized DOM. Preserve separate tests for each registration of a shared callback."}
			g.ExampleStatus = "no automatic patch; review intended DOM output and callback semantics"
			return g
		}
	}
	if filepath.Ext(u.Sink.Span.File) == ".py" && (u.Sink.Kind == "html_return" || u.Sink.Kind == "html_response") && u.XSS.OutputContext == "html_text" {
		compiled := false
		for _, d := range u.Dependencies {
			for _, e := range d.Transfers {
				compiled = compiled || e.Kind == "template_source" || e.Kind == "template_render" || e.Kind == "template_compile"
			}
		}
		if !compiled {
			g.Actions = []string{"At " + at + ", HTML-encode the inserted request text before combining it with the returned HTML or HTMLResponse. Use an appropriate text encoder such as Python html.escape; retain the surrounding constant markup.", "If this output moves into a template, pass the value separately to a verified autoescaping template instead of concatenating it into HTML or template source.", "Test HTML-significant input through this generated route and each factory context; assert that the supplied markup is displayed as text. Keep raw, escaped and unresolved callback paths separate."}
			g.ExampleStatus = "no automatic patch; preserve intended response and output context"
			return g
		}
	}
	if strings.Contains(u.Sink.Text, "{{") && strings.Contains(u.Sink.Text, "|") && u.XSS.OutputContext != "script" && u.XSS.OutputContext != "url" {
		replacement := jinjaSafeFilter.ReplaceAllString(u.Sink.Text, "")
		if replacement != u.Sink.Text {
			g.Actions = []string{"At " + at + ", replace the raw template expression " + u.Sink.Text + " with " + replacement + " so the verified template engine escapes this value in " + u.XSS.OutputContext + ".", "Add a rendering test with quotes, angle brackets and ampersands; assert that the output remains text and cannot close its current attribute or element."}
			g.Example = replacement
			return g
		}
	}
	if match := jqueryListAppend.FindStringSubmatch(u.Sink.Text); len(match) > 0 {
		g.Actions = []string{"At " + at + ", build the list item as a DOM node and set its text from " + match[2] + ". The current string concatenation feeds that input to jQuery's HTML parser.", "Keep the existing list container and event flow. Test that an input containing an HTML tag is displayed literally and does not create another element."}
		g.Example = match[1] + ".append($('<li>').text(" + match[2] + "));"
		return g
	}
	ext := filepath.Ext(u.Sink.Span.File)
	if ext == ".ejs" && strings.Contains(u.Sink.Text, "<%-") {
		if strings.Contains(u.Sink.Text, "marked(") {
			g.Actions = []string{"At " + at + ", preserve the intended Markdown rendering, then sanitize the generated HTML with a maintained HTML sanitizer before sending it to the raw EJS output " + u.Sink.Text + ".", "If the output should be plain text, use EJS's escaped <%= ... %> output instead. Sanitizer presence or an old Markdown sanitize option alone does not establish protection; review its version, options and ordering after Markdown rendering.", "Test raw markup and dangerous link URLs against the final rendered HTML. Keep both request-to-storage write paths and escaped edit-form outputs in regression coverage."}
		} else {
			g.Actions = []string{"At " + at + ", use EJS's escaped <%= ... %> output when this value is intended as text, rather than raw <%- ... %> output.", "If HTML is required, sanitize it with an appropriate HTML sanitizer before raw output. Preserve the surrounding template and the exact attribute/text context.", "Test quotes, angle brackets, ampersands and any URL scheme constraints relevant to this output context."}
		}
		g.ExampleStatus = "no automatic patch; preserve intended template and Markdown semantics"
		return g
	}
	if (ext == ".hbs" || ext == ".handlebars") && strings.Contains(u.Sink.Text, "{{{") {
		replacement := strings.ReplaceAll(strings.ReplaceAll(u.Sink.Text, "{{{", "{{"), "}}}", "}}")
		g.Actions = []string{"At " + at + ", use escaped Handlebars output " + replacement + " when the value should be text. Raw triple-brace output requires separately sanitized HTML.", "Retain verified renderer configuration and inspect render options and helpers; escaping one field does not secure request-controlled template configuration.", "Test the exact output context with quotes, angle brackets and ampersands."}
		return g
	}
	if ext != ".py" {
		g.Actions = []string{"At " + at + ", encode the untrusted value for the established " + u.XSS.OutputContext + " HTML output context before passing it to " + u.Sink.Text + ".", "Use a constant autoescaping template with data passed separately when appropriate. If markup is intentionally allowed, use a verified context-appropriate sanitizer after rendering or transformation.", "Test the final rendered output with HTML-significant input and preserve separate tests for URL, script and attribute contexts; HTML text escaping is not a universal protection."}
		return g
	}
	g.Actions = []string{"At " + at + ", stop placing the source value into the HTML/template source consumed by " + u.Sink.Text + ".", "Use a constant template with the source value as a separate variable and explicitly enable context-appropriate autoescaping. Merely moving a value to Template.render does not enable Jinja autoescape.", "Test the same source-to-output path with HTML-significant input; retain a separate test for template-expression input so fixing template-source injection is not mistaken for fixing XSS."}
	return g
}

func fieldPolicyText(u analysis.CandidateUse) string {
	var text []string
	if u.Completeness != nil {
		for _, e := range u.Completeness.Evidence["field_policy"] {
			text = append(text, e.Text)
		}
	}
	return strings.Join(text, "; ")
}
