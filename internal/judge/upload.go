package judge

import (
	"fmt"
	"strings"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
)

// applyUploadPolicy classifies an unrestricted-upload claim (CWE-434,
// close-findings-gaps D-21). Confirmed needs a client-chosen extension, no
// server-side type control, a served destination and consistent answers.
// Protected needs a generated name with a fixed, allow-listed or
// content-derived extension, or a destination that is not served, with
// complete coverage. Anything else is Review.
func applyUploadPolicy(use analysis.CandidateUse, a *analysis.Assessment) {
	a.FindingStatus, a.Protection = "needs_evidence", "uncertain"
	a.BlockingGaps = nil
	add := func(kind, detail string) {
		a.BlockingGaps = append(a.BlockingGaps, analysis.Gap{Kind: "upload_" + kind, Detail: detail, At: use.Sink.Span})
	}
	f, c := use.Upload, use.Completeness
	if a.QuestionVersion != analysispacks.UploadProtocol {
		add("protocol_missing", "Versioned upload answers are required.")
	}
	if f == nil || c == nil || c.ClaimKind != "upload" || use.APIModel == nil || use.APIModel.ID != f.ContractID {
		add("claim_missing", "Source-backed upload facts, a verified upload contract and completeness are required.")
		a.Reason = "The upload claim lacks source-backed facts or a verified operation contract."
		return
	}
	if err := f.Validate(len(use.Dependencies), len(use.Context)); err != nil {
		add("facts_invalid", err.Error())
	}
	roles := append([]string{"input_source", "sink_binding", "invoked_callable", "control_flow", "upload_operand"}, c.Required...)
	if use.Components != nil {
		roles = append(roles, use.Components.Required...)
	}
	seen := map[string]bool{}
	for _, role := range roles {
		if !seen[role] && len(c.Evidence[role]) == 0 {
			add("evidence_missing", role)
		}
		seen[role] = true
	}
	ans := a.Answers
	var contradictions []string
	contradict := func(format string, args ...any) {
		contradictions = append(contradictions, fmt.Sprintf(format, args...))
	}
	has := func(kind string) bool {
		for _, k := range f.TypeControls {
			if k.Kind == kind {
				return true
			}
		}
		return false
	}
	switch ans["type_restriction"] {
	case "none":
		if len(f.TypeControls) > 0 {
			contradict("type restriction none although a type control is recorded")
		}
	case "client_declared_only":
		if !has(analysis.UploadClientDeclaredType) || f.ServerTypeControl() {
			contradict("client_declared_only requires a recorded client-declared type check and no server-side type control")
		}
	case "extension_allow_list":
		if !has(analysis.UploadExtensionAllowList) && f.ExtensionOrigin != "allow_listed" {
			contradict("extension_allow_list without a recorded extension allow-list")
		}
	case "content_check":
		if !has(analysis.UploadContentSniff) {
			contradict("content_check without a recorded content check")
		}
	case "re_encoded":
		if !has(analysis.UploadReEncode) {
			contradict("re_encoded without a recorded re-encode")
		}
	}
	switch ans["execution_exposure"] {
	case "served_executable":
		if f.DestinationServed != "yes" {
			contradict("served_executable although the destination is not established as served (%s)", f.DestinationServed)
		}
		if f.ExtensionOrigin != "client" {
			contradict("served_executable although the stored extension is not client-chosen (%s)", f.ExtensionOrigin)
		}
	case "not_served":
		if f.DestinationServed == "yes" {
			contradict("not_served although the destination is under the document root")
		}
	}
	blockers := append([]analysis.Gap{}, a.BlockingGaps...)
	blockers = append(blockers, c.Blockers...)
	if len(contradictions) > 0 {
		a.BlockingGaps = append(blockers, analysis.Gap{Kind: "upload_answers_inconsistent", Detail: strings.Join(contradictions, "; "), At: use.Sink.Span})
		a.Reason = "Upload answers contradict the source-backed facts; raw answers are retained and no status is claimed from them."
		return
	}
	a.BlockingGaps = blockers
	if len(blockers) > 0 {
		a.Reason = "Claim-relevant upload evidence is incomplete; raw answers are retained."
		return
	}
	unrestricted := ans["type_restriction"] == "none" || ans["type_restriction"] == "client_declared_only"
	if unrestricted && !f.ServerTypeControl() && f.ExtensionOrigin == "client" && f.DestinationServed == "yes" && ans["execution_exposure"] == "served_executable" {
		a.FindingStatus, a.Protection = "confirmed_vulnerability", "insufficient"
		a.Reason = "The stored file keeps a client-chosen extension, no server-side type control precedes the " + f.Operation + " write, and the destination is under the document root, so an uploaded executable file can be requested (CWE-434). This is a static judgment, not runtime exploitation."
		return
	}
	generated := f.StoredName == "server_generated" && (f.ExtensionOrigin == "fixed" || f.ExtensionOrigin == "allow_listed" || f.ExtensionOrigin == "content_derived")
	restricted := ans["type_restriction"] == "re_encoded" || ans["type_restriction"] == "content_check" || ans["type_restriction"] == "extension_allow_list"
	fixed := f.StoredName == "server_generated" && f.ExtensionOrigin == "fixed"
	if ans["protection_coverage"] == "complete" && ans["execution_exposure"] != "served_executable" && (fixed || generated && restricted || f.DestinationServed == "no" && ans["execution_exposure"] == "not_served") {
		a.FindingStatus, a.Protection = "protected_for_claim", "sufficient"
		a.Reason = "A server-generated name with a constrained extension, or a destination outside the served tree, with complete coverage supports protection of this upload against executable-file storage only."
		return
	}
	a.Reason = "The upload assessment is inconclusive: a type control's adequacy, the destination or the coverage is not established."
}
