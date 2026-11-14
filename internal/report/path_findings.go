package report

import (
	"fmt"
	"strings"

	"github.com/zazzcode/zazzles/internal/analysis"
)

func describePath(u analysis.CandidateUse, f *analysis.Finding) {
	f.Title = "File path needs review"
	f.Summary = "Scan identified a request-derived value reaching a filesystem operation. Whether it can select a file outside the intended location has not been established as a defect or as protected."
	if u.Path != nil {
		f.Summary = fmt.Sprintf("Scan identified a request-derived value reaching the path operand of %s (%s) under the declared %s assumption. Traversal, containment control and coverage are assessed as separate facets; write content and options are not path sources.", u.Path.Operation, u.Path.Role, u.Path.Platform)
	}
}

// pathFlowSummary names the request-derived value, the construction and any
// source-established base of the first flow that is a witness for the record.
func pathFlowSummary(u analysis.CandidateUse) string {
	if u.Path == nil {
		return ""
	}
	for _, p := range u.Path.Paths {
		if p.Protection != "raw" && p.Protection != "guarded" {
			continue
		}
		text := "the value " + u.Dependencies[p.Dependency].Source.Text + " reaches the path operand"
		if p.Operand == analysis.PathSlotArchive {
			text = "the request-supplied archive " + u.Dependencies[p.Dependency].Source.Text + " supplies entry names that are written under the destination"
			if e := u.Path.Extractor; e != nil {
				text += " by " + e.Library + " (" + strings.ReplaceAll(e.Assessment, "_", " ") + ", declared " + e.Declared + ")"
			}
			return text
		}
		if len(p.Transforms) > 0 {
			text += " through " + strings.Join(p.Transforms, " then ")
		}
		if p.Root != "" {
			text += " with the base " + p.Root + " (a join or resolve of a base is not a containment check)"
		}
		return text
	}
	return ""
}

// confirmPath promotes a gated path assessment to a finding and names the
// operation, role and the source-established flow.
func confirmPath(u analysis.CandidateUse, f *analysis.Finding) {
	f.RecordType, f.Status = "finding", "confirmed_vulnerability"
	f.Title = "Path traversal supported by source analysis"
	if isArchiveExtraction(u) {
		f.Title = "Path traversal through archive extraction (Zip Slip) supported by source analysis"
	}
	f.Summary = "A request-derived value reaches the path operand of " + u.Path.Operation + " (" + u.Path.Role + ") with no enforced containment (CWE-22): " + pathFlowSummary(u) + ". This is a static source judgment under the declared " + u.Path.Platform + " assumption, not runtime exploitation, symbolic-link or filesystem-state analysis, or independent Findings Review."
	f.Uncertainty += " The platform assumption is " + u.Path.Platform + "; Windows path semantics are not modeled. Unresolved sibling paths, if any, remain separate blocking or coverage records."
}

// pathSinkLabel names the file operation by the head of its call, not by an entire
// multi-line callback.
func pathSinkLabel(u analysis.CandidateUse) string {
	text := strings.TrimSpace(u.Sink.Text)
	head, _, multiline := strings.Cut(text, "\n")
	head = strings.TrimSpace(head)
	if len(head) > 90 {
		head, multiline = head[:90], true
	}
	if multiline {
		head += " …"
	}
	return head
}

// isArchiveExtraction reports the Zip Slip variant: archive entry names, not a
// path argument, are the attacker-controlled components.
func isArchiveExtraction(u analysis.CandidateUse) bool {
	return u.Path != nil && u.Path.Extractor != nil
}

// confirmWeakPath reports a weak containment control: poor practice, not a proven exploit.
func confirmWeakPath(u analysis.CandidateUse, f *analysis.Finding) {
	f.RecordType, f.Status = "finding", "poor_practice"
	f.Title = "Weak path containment (poor practice)"
	f.Summary = "A request-derived value reaches the path operand of " + u.Path.Operation + " (" + u.Path.Role + ") behind a control that does not establish containment (CWE-22): " + pathFlowSummary(u) + ". The control is a prefix comparison without a separator boundary, a '..' text test or a separator-only test. Replace it with an allow-list or a path-component-boundary check on the resolved path. This is a static construction-practice finding, not a confirmed exploit."
	f.Uncertainty += " Whether a sibling directory, a decoded value or a bare '..' component passes the control depends on the filesystem layout and inputs, which are not inferred."
}

func pathGuidance() Guidance {
	return Guidance{Title: "Keep request data from selecting an arbitrary file", Actions: []string{
		"Prefer selecting the file by a trusted identifier (a finite allow-list of known names or a stored record id) instead of accepting a path.",
		"Otherwise resolve the final path and verify it stays inside the trusted directory at a path-component boundary (a separator-bounded prefix, a path.relative or os.path.commonpath check) before the file operation, rejecting on failure. A join, resolve or normalize call, a '..' blacklist and a prefix comparison without a separator are not containment.",
		"If symbolic links inside the directory must not be followed, resolve with realpath before comparing and account for races between the check and the use.",
	}, ExampleStatus: "not_generated; directory layout, allowed names and tests are application-specific"}
}

func pathFindingGuidance(u analysis.CandidateUse, at string) Guidance {
	if isArchiveExtraction(u) && u.Path.Extractor.Assessment == "caller_entry_path" {
		return Guidance{Title: "Contain each archive entry before writing", Actions: []string{
			"At " + at + ", validate the effective path built from the archive entry name before " + pathSinkLabel(u) + ". Reading ZIP metadata does not contain the caller's filesystem writes.",
			"Resolve the final destination and enforce a path-component boundary against the extraction root; reject escaping paths. A substring includes(root) test is not containment.",
			"Add a regression archive with '../' entry names and verify no writes escape the destination; decide how symbolic-link entries and races are handled.",
		}, ExampleStatus: "no automatic patch; no verified fix is exported"}
	}
	if isArchiveExtraction(u) {
		return Guidance{Title: "Validate archive entry names before extraction", Actions: []string{
			"At " + at + ", do not extract entries from a request-supplied archive with " + pathSinkLabel(u) + " unless the extractor validates entry names: upgrade " + u.Path.Extractor.Library + " to a release that rejects names escaping the destination, or extract entry by entry.",
			"For each entry resolve destination + entry name and require the result to stay inside the destination at a path-component boundary (a separator-bounded prefix check, not a substring test), reject absolute and '..' names, and decide how symbolic-link entries are handled.",
			"Add a regression test with an archive containing '../' entries and assert nothing is written outside the destination.",
		}, ExampleStatus: "no automatic patch; no verified fix is exported"}
	}
	g := pathGuidance()
	operand := "the request-derived path operand"
	if u.Path != nil {
		for _, p := range u.Path.Paths {
			if p.Protection == "raw" || p.Protection == "guarded" {
				operand = "the path built from " + u.Dependencies[p.Dependency].Source.Text
				break
			}
		}
	}
	g.Title = "Contain this file operation"
	g.Actions = append([]string{"At " + at + ", constrain " + operand + " before " + pathSinkLabel(u) + ". Do not rely on path.join, path.resolve, os.path.join or normalization alone, a '..' text check, a try/except around the call, or an error response after the read."}, g.Actions...)
	g.ExampleStatus = "no automatic patch; no verified fix is exported"
	return g
}
