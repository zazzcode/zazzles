package judge

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
)

// Resolution question versions. A changed wording or choice set takes a new
// version, and the owning family protocol is bumped with it.
const (
	FlowGapQuestionVersion      = "flow-gap-v2"
	WitnessQuestionVersion      = "witness-citation-v2"
	BypassQuestionVersion       = "bypass-citation-v2"
	StoredOriginQuestionVersion = "stored-origin-v2"
)

// resolvePrefix marks a request question that asks about one point the
// scanner could not resolve. Its companion citation question ends in citeSuffix.
const (
	resolvePrefix = "resolve_"
	citeSuffix    = "_cite"
)

// maxFlowGapQuestions bounds the flow-gap questions of one record; a record
// with more resolvable gaps than this is not resolvable (D-7).
const maxFlowGapQuestions = 4

// maxCiteChoices bounds the offered chains of one citation question.
const maxCiteChoices = 6

// flowGapKinds are the flow blockers W2 asks about: code the scanner stops at
// but a reader can follow.
var flowGapKinds = map[string]bool{
	"python_comprehension_unresolved": true,
	"python_call_unresolved":          true,
	"python_dispatch_unresolved":      true,
	"php_value_unresolved":            true,
	"php_loop_unresolved":             true,
	"transfer_limit":                  true,
	"unknown_transfer":                true,
}

// flowGapFamilies are the families whose policy reads flow-gap resolutions.
var flowGapFamilies = map[string]bool{"path": true, "sql": true}

// FlowGapChoices is the answer protocol of a flow-gap question (D-3).
func FlowGapChoices() []map[string]string {
	return []map[string]string{
		{"value": "value_preserved", "description": "The request value passes through the named span and continues toward the sink still request-controlled: copied, projected, split, joined, concatenated or returned without a check that limits it."},
		{"value": "value_constrained", "description": "The value continues, but the span checks, filters, converts or selects it against a fixed set, so only constrained values continue."},
		{"value": "value_replaced", "description": "The span replaces the value with one the request does not control, or the value does not continue toward the sink through this span."},
		{"value": "cannot_tell", "description": "The supplied source does not show how the span treats the value."},
	}
}

// StoredOriginChoices is the answer protocol of a stored-origin question (D-4).
func StoredOriginChoices() []map[string]string {
	return []map[string]string{
		{"value": "request_write_cited", "description": "One of the listed writes stores a request-controlled value into the column this record reads; cite that write."},
		{"value": "no_request_write_in_evidence", "description": "None of the listed writes stores a request-controlled value into the column this record reads."},
		{"value": "cannot_tell", "description": "The listed writes and read query do not show whether a request value reaches the column read."},
	}
}

// resolutionAsk is one resolution question pair planned for a record.
type resolutionAsk struct {
	name, version string
	gap           string // asked gap ID, "" for a witness or bypass citation
	blocker       *analysis.Gap
	answer        *question // nil when the family's own answer is the claim
	cite          question
}

func familyOf(u analysis.CandidateUse) string { return analysispacks.FamilySlugForKind(u.Kind) }

// overlapsDependency reports that a gap's span overlaps an item of a
// dependency's source-to-sink chain.
func overlapsDependency(g analysis.Gap, d analysis.Dependency, sink analysis.Evidence) bool {
	for _, e := range append(append([]analysis.Evidence{d.Source}, d.Transfers...), sink) {
		if g.At.File == e.Span.File && g.At.StartByte < e.Span.EndByte && e.Span.StartByte < g.At.EndByte {
			return true
		}
	}
	return false
}

// flowGapBlockers returns the record's flow blockers that W2 asks about, in
// record order, or nil when the family has no flow-gap question.
func flowGapBlockers(u analysis.CandidateUse) []analysis.Gap {
	if u.Completeness == nil || !flowGapFamilies[familyOf(u)] {
		return nil
	}
	var out []analysis.Gap
	for _, g := range u.Completeness.Blockers {
		if !flowGapKinds[g.Kind] {
			continue
		}
		for _, d := range u.Dependencies {
			if overlapsDependency(g, d, u.Sink) {
				out = append(out, g)
				break
			}
		}
	}
	if len(out) > maxFlowGapQuestions {
		return nil
	}
	return out
}

// resolvable reports whether a scanner blocker has a resolution question
// for this record. It is the single predicate behind both question building
// and the send gate (D-7).
func resolvable(u analysis.CandidateUse, g analysis.Gap) bool {
	for _, f := range flowGapBlockers(u) {
		if f == g {
			return true
		}
	}
	if g.Kind == "storage_origin_unresolved" && storedOriginAskable(u) {
		return true
	}
	return false
}

// storedOriginAskable reports a record whose stored origin an answer could
// change (W3b, D-4): a family that reads the answer, and either a listed
// non-literal write the model could cite or every store closed, so that no
// request write would support protection. A census of literal writes only in
// a store that is not closed leaves nothing to decide, and the record is
// gated (D-7).
func storedOriginAskable(u analysis.CandidateUse) bool {
	if f := familyOf(u); f != "xss" && f != "sql" {
		return false
	}
	if u.StoredOrigin == nil || len(u.StoredOrigin.Stores) == 0 {
		return false
	}
	for _, s := range u.StoredOrigin.Stores {
		for _, w := range s.Writes {
			if !w.Literal {
				return true
			}
		}
	}
	return allStoresClosed(u)
}

// fixingBlockers returns the scanner blockers that fix the record's outcome
// whatever the model answers. Path-scoped families keep a sibling witness
// standing beside a blocker on another dependency, so only their global
// blockers fix the outcome; logging ignores completeness blockers and
// validation has its own gate.
func fixingBlockers(u analysis.CandidateUse) []analysis.Gap {
	if u.Completeness == nil {
		return nil
	}
	switch familyOf(u) {
	case "sql", "nosql", "xss":
		return u.Completeness.Blockers
	case "path", "command", "ssrf", "code", "redirect":
		var out []analysis.Gap
		for _, g := range u.Completeness.Blockers {
			touches := false
			for _, d := range u.Dependencies {
				touches = touches || gapTouchesCommandDependency(g, d)
			}
			if !touches {
				out = append(out, g)
			}
		}
		return out
	}
	return nil
}

// BlockerUnresolvable prefixes the not-run reason of a record the send gate
// kept from the judge.
const BlockerUnresolvable = "blocker_unresolvable"

// resolutionGate settles, before any request, a record with a scanner
// blocker that fixes its outcome and has no resolution question: no answer
// could change it, so it is not sent (D-7). A record whose fixing blockers
// all have questions is judged with them.
func resolutionGate(u analysis.CandidateUse) (analysis.Assessment, bool) {
	if !AssessableUse(u) || validationUse(u) {
		return analysis.Assessment{}, false
	}
	var open []analysis.Gap
	kinds := map[string]bool{}
	for _, g := range fixingBlockers(u) {
		if !resolvable(u, g) {
			open = append(open, g)
			kinds[g.Kind] = true
		}
	}
	if len(open) == 0 {
		return analysis.Assessment{}, false
	}
	names := make([]string, 0, len(kinds))
	for k := range kinds {
		names = append(names, k)
	}
	sort.Strings(names)
	return analysis.Assessment{Status: "not_run", FindingStatus: "needs_evidence", Protection: "uncertain",
		Reason:       BlockerUnresolvable + ": " + strings.Join(names, ", ") + " fixes this record's outcome and has no resolution question; no model answer could change it, so no request was sent",
		BlockingGaps: open}, true
}

// chainChoice renders an ID chain as a citation choice.
func chainChoice(x *wireIndex, ids []string) map[string]string {
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		item, ok := x.evidence[id]
		if !ok {
			item = x.gaps[id]
			parts = append(parts, fmt.Sprintf("%s [unresolved %s] %s:%d", id, item.kind, item.file, item.start))
			continue
		}
		text := strings.Join(strings.Fields(item.text), " ")
		if len(text) > 60 {
			text = text[:57] + "..."
		}
		parts = append(parts, fmt.Sprintf("%s %q %s:%d", id, text, item.file, item.start))
	}
	return map[string]string{"value": strings.Join(ids, ">"), "description": strings.Join(parts, " -> ")}
}

func noneChoice(why string) map[string]string {
	return map[string]string{"value": citeNone, "description": why}
}

// gapChain is dependency i's chain with the asked gap inserted after the
// first item it overlaps.
func gapChain(x *wireIndex, i int, gap string) []string {
	chain := x.chains[i]
	g := x.gaps[gap]
	at := len(chain) - 2
	for k, id := range chain {
		if e, ok := x.evidence[id]; ok && e.overlaps(g) {
			at = min(k, len(chain)-2)
			break
		}
	}
	if at < 0 {
		return nil
	}
	out := append([]string{}, chain[:at+1]...)
	out = append(out, gap)
	return append(out, chain[at+1:]...)
}

// resolutionAsks plans the record's resolution questions from its compacted
// request; gapIDs maps gapKey to gN.
func resolutionAsks(u analysis.CandidateUse, wire map[string]any, gapIDs map[string]string) []resolutionAsk {
	x, err := indexWire(wire)
	if err != nil {
		return nil
	}
	var asks []resolutionAsk
	for _, g := range flowGapBlockers(u) {
		id := gapIDs[gapKey(g)]
		if id == "" {
			continue
		}
		blocker := g
		choices := []map[string]string{}
		for i := range x.chains {
			if x.touches(id, i) && len(choices) < maxCiteChoices {
				if chain := gapChain(x, i, id); chain != nil {
					choices = append(choices, chainChoice(x, chain))
				}
			}
		}
		choices = append(choices, noneChoice("No offered chain carries the value you assessed, or you answered cannot_tell."))
		name := resolvePrefix + "flow_" + id
		answer := question{name: name, choices: FlowGapChoices(), instructions: fmt.Sprintf("The scanner could not follow the request value through the span of gap %s (%s: %s). Using only the supplied source excerpts, say what that span does to the request value on its way to the sink operand. Judge only this span; other gaps, guards and the final verdict are separate questions. Choose value_preserved only when the source shows the value continuing request-controlled; choose value_constrained for a check, filter, conversion or selection against a fixed set; choose cannot_tell when the source does not show it.", id, g.Kind, g.Detail)}
		asks = append(asks, resolutionAsk{name: name, version: FlowGapQuestionVersion, gap: id, blocker: &blocker, answer: &answer,
			cite: question{name: name + citeSuffix, choices: choices, instructions: fmt.Sprintf("Cite the ordered evidence chain, from request source through %s to the sink, that carries the value you assessed in %s. Each choice lists eN evidence rows and the gap in order. Choose none when you answered cannot_tell or no offered chain carries that value.", id, name)}})
	}
	if storedOriginAskable(u) && u.Completeness != nil {
		so, _ := wire["stored_origin"].(map[string]any)
		stores, _ := so["stores"].([]any)
		for _, g := range u.Completeness.Blockers {
			id := gapIDs[gapKey(g)]
			if g.Kind != "storage_origin_unresolved" || id == "" {
				continue
			}
			blocker := g
			choices := []map[string]string{}
			for _, st := range stores {
				store, _ := st.(map[string]any)
				writes, _ := store["writes"].([]any)
				for _, w := range writes {
					write, _ := w.(map[string]any)
					eid, _ := write["evidence"].(string)
					if literal, _ := write["literal"].(bool); !literal && eid != "" && len(choices) < maxCiteChoices && !hasChoice(choices, eid) {
						choices = append(choices, chainChoice(x, []string{eid}))
					}
				}
			}
			choices = append(choices, noneChoice("You did not answer request_write_cited."))
			name := resolvePrefix + "stored_" + id
			answer := question{name: name, choices: StoredOriginChoices(), instructions: fmt.Sprintf("Gap %s: the scanner could not establish where the stored value this record reads comes from. use.stored_origin lists, for each storage key read, every write the scanner found (literal marks writes whose values are all source literals), whether the read query is static, whether the store is closed and its schema, plus the read queries. Judge only whether a request-controlled value can be written into the stored column this record reads, from the listed writes alone. Do not assume writes that are not listed.", id)}
			asks = append(asks, resolutionAsk{name: name, version: StoredOriginQuestionVersion, gap: id, blocker: &blocker, answer: &answer,
				cite: question{name: name + citeSuffix, choices: choices, instructions: "If you answered request_write_cited, cite the one listed write that stores a request-controlled value into the column read. Choose none otherwise."}})
		}
	}
	switch familyOf(u) {
	case "path":
		if f := u.Path; f != nil && !pathHasWitness(u) {
			choices := []map[string]string{}
			for _, flow := range f.Paths {
				if flow.Dependency >= 0 && flow.Dependency < len(x.chains) && len(choices) < maxCiteChoices {
					choices = append(choices, chainChoice(x, x.chains[flow.Dependency]))
				}
			}
			if len(choices) > 0 {
				choices = append(choices, noneChoice("You did not answer vulnerable, or no offered chain carries a request value to the path operand without a containing control."))
				name := resolvePrefix + "witness"
				asks = append(asks, resolutionAsk{name: name, version: WitnessQuestionVersion,
					cite: question{name: name + citeSuffix, choices: choices, instructions: "If you answered path_traversal vulnerable, cite the ordered evidence chain from the request source to the file operation along which the request value reaches the path operand with no control that contains it. The scanner did not establish such a path itself, so it checks the chain you cite. Choose none otherwise."}})
			}
		}
	case "command":
		// D-2: the only guarded path cites itself; its question is not sent.
		if _, implied := impliedBypassPath(u); u.Command != nil && !implied {
			f := u.Command
			choices := []map[string]string{}
			for _, p := range f.Paths {
				if p.Protection == "guarded" && p.Dependency >= 0 && p.Dependency < len(x.chains) && len(choices) < maxCiteChoices {
					choices = append(choices, chainChoice(x, x.chains[p.Dependency]))
				}
			}
			if len(choices) > 0 {
				choices = append(choices, noneChoice("You did not answer bypass_identified."))
				name := resolvePrefix + "bypass"
				asks = append(asks, resolutionAsk{name: name, version: BypassQuestionVersion,
					cite: question{name: name + citeSuffix, choices: choices, instructions: "If you answered guard_bypass bypass_identified, cite the ordered evidence chain that carries the bypassing request value through the guard to the command operand. Choose none otherwise."}})
			}
		}
	}
	if f := familyOf(u); f == "path" || f == "sql" || f == "command" || f == "xss" {
		if ask := neededAsk(u); ask != nil {
			asks = append(asks, *ask)
		}
	}
	return asks
}

// resolutionQuestions flattens the planned asks into request questions.
func resolutionQuestions(asks []resolutionAsk) []question {
	var out []question
	for _, a := range asks {
		if a.answer != nil {
			out = append(out, *a.answer)
		}
		// A choice question needs two options; a citation with only none
		// offers nothing to cite.
		if a.cite.name != "" && len(a.cite.choices) >= 2 {
			out = append(out, a.cite)
		}
	}
	return out
}

// requestQuestions returns the questions a request carried: the family's
// own questions followed by the resolution questions read from the request
// itself, so decoding and replay use exactly what was sent.
func requestQuestions(use analysis.CandidateUse, payload []byte) []question {
	base := questionsFor(use)
	return append(base, payloadResolutionQuestions(payload)...)
}

func payloadResolutionQuestions(payload []byte) []question {
	var envelope struct {
		Questions json.RawMessage `json:"questions"`
	}
	if json.Unmarshal(payload, &envelope) != nil || len(envelope.Questions) == 0 {
		return nil
	}
	var out []question
	if envelope.Questions[0] == '[' {
		var list []struct {
			Name         string              `json:"name"`
			Instructions string              `json:"instructions"`
			Choices      []map[string]string `json:"choices"`
		}
		if json.Unmarshal(envelope.Questions, &list) != nil {
			return nil
		}
		for _, q := range list {
			if strings.HasPrefix(q.Name, resolvePrefix) {
				out = append(out, question{name: q.Name, instructions: q.Instructions, choices: q.Choices})
			}
		}
		return out
	}
	var byName map[string]struct {
		Instructions string            `json:"instructions"`
		Criteria     map[string]string `json:"criteria"`
	}
	if json.Unmarshal(envelope.Questions, &byName) != nil {
		return nil
	}
	names := []string{}
	for name := range byName {
		if strings.HasPrefix(name, resolvePrefix) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		q := byName[name]
		values := make([]string, 0, len(q.Criteria))
		for v := range q.Criteria {
			values = append(values, v)
		}
		sort.Strings(values)
		choices := []map[string]string{}
		for _, v := range values {
			choices = append(choices, map[string]string{"value": v, "description": q.Criteria[v]})
		}
		out = append(out, question{name: name, instructions: q.Instructions, choices: choices})
	}
	return out
}

// resolveAnswers records every resolution answer of a completed request and
// verifies its citation against the request that was sent.
func resolveAnswers(use analysis.CandidateUse, payload []byte, answers map[string]string, provider, model string) []analysis.Resolution {
	wire, err := requestUse(payload)
	if err != nil {
		return nil
	}
	x, err := indexWire(wire)
	if err != nil {
		return nil
	}
	var out []analysis.Resolution
	for _, q := range payloadResolutionQuestions(payload) {
		if strings.HasSuffix(q.name, citeSuffix) || q.name == neededQuestion {
			continue
		}
		out = append(out, resolveOne(use, x, q.name, answers, provider, model))
	}
	for _, q := range payloadResolutionQuestions(payload) {
		base := strings.TrimSuffix(q.name, citeSuffix)
		if !strings.HasSuffix(q.name, citeSuffix) || answers[base] != "" {
			continue
		}
		out = append(out, resolveOne(use, x, base, answers, provider, model)) // citation-only: witness or bypass
	}
	return out
}

func resolveOne(use analysis.CandidateUse, x *wireIndex, name string, answers map[string]string, provider, model string) analysis.Resolution {
	r := analysis.Resolution{Question: name, Answer: answers[name], Provider: provider, Model: model}
	asked := ""
	switch {
	case strings.HasPrefix(name, resolvePrefix+"flow_"):
		r.QuestionVersion = FlowGapQuestionVersion
		asked = strings.TrimPrefix(name, resolvePrefix+"flow_")
		r.Blocker = matchBlocker(use, x, asked)
	case strings.HasPrefix(name, resolvePrefix+"stored_"):
		r.QuestionVersion = StoredOriginQuestionVersion
		r.Blocker = matchBlocker(use, x, strings.TrimPrefix(name, resolvePrefix+"stored_"))
	case name == resolvePrefix+"witness":
		r.QuestionVersion, r.Answer = WitnessQuestionVersion, answers["path_traversal"]
	case name == resolvePrefix+"bypass":
		r.QuestionVersion, r.Answer = BypassQuestionVersion, answers["guard_bypass"]
	}
	r.Citation = parseCitation(answers[name+citeSuffix])
	if len(r.Citation) == 0 {
		r.Rejection = "no citation"
		return r
	}
	if r.QuestionVersion == StoredOriginQuestionVersion {
		r.CitedSpans, r.Rejection = verifyWriteCitation(use, x, r.Citation)
	} else {
		var c citation
		c, r.Rejection = verifyCitation(x, r.Citation, asked)
		r.CitedSpans = c.spans
		if r.Rejection == "" {
			d := c.dependency
			r.Dependency = &d
		}
	}
	r.Verified = r.Rejection == ""
	return r
}

// matchBlocker finds the record blocker that request gap id names.
func matchBlocker(use analysis.CandidateUse, x *wireIndex, id string) *analysis.Gap {
	g, ok := x.gaps[id]
	if !ok || use.Completeness == nil {
		return nil
	}
	for _, b := range use.Completeness.Blockers {
		if b.Kind == g.kind && b.At.File == g.file && b.At.StartLine == g.start && b.At.EndLine == g.end {
			copy := b
			return &copy
		}
	}
	return nil
}

// ImpliedSinglePath is the citation of a bypass the scanner bound to the
// record's only guarded path (D-1); no model citation was asked.
const ImpliedSinglePath = "implied_single_path"

// impliedBypassPath returns the dependency of the record's only guarded
// command path when its chain has no scanner gap. A bypass answer can then
// name no other chain, so the scanner binds it without a citation question.
func impliedBypassPath(u analysis.CandidateUse) (int, bool) {
	f := u.Command
	if f == nil || familyOf(u) != "command" {
		return -1, false
	}
	dep, guarded := -1, 0
	for _, p := range f.Paths {
		if p.Protection == "guarded" {
			guarded++
			dep = p.Dependency
		}
	}
	if guarded != 1 || dep < 0 || dep >= len(u.Dependencies) {
		return -1, false
	}
	if u.Completeness != nil {
		for _, g := range u.Completeness.Blockers {
			if gapTouchesCommandDependency(g, u.Dependencies[dep]) {
				return -1, false
			}
		}
	}
	return dep, true
}

// impliedBypassResolution records the scanner's binding of a bypass answer to
// the record's only guarded path.
func impliedBypassResolution(u analysis.CandidateUse, a *analysis.Assessment, dep int) analysis.Resolution {
	d := u.Dependencies[dep]
	spans := []analysis.Span{d.Source.Span}
	for _, e := range d.Transfers {
		spans = append(spans, e.Span)
	}
	spans = append(spans, u.Sink.Span)
	return analysis.Resolution{Question: resolvePrefix + "bypass", QuestionVersion: BypassQuestionVersion, Answer: a.Answers["guard_bypass"],
		Citation: []string{ImpliedSinglePath}, CitedSpans: spans, Dependency: &dep, Verified: true, Verifier: "scanner", Discharged: true,
		Provider: a.Provider, Model: a.Model}
}

// rejectedCitation reports a model citation of the question that the
// verifier rejected; the scanner never overrides it.
func rejectedCitation(a *analysis.Assessment, name string) bool {
	for _, r := range a.Resolutions {
		if r.Question == name && len(r.Citation) > 0 && !r.Verified {
			return true
		}
	}
	return false
}

// verifiedResolution returns the record's verified resolution of a question
// with the given answer, or nil.
func verifiedResolution(a *analysis.Assessment, name, answer string) *analysis.Resolution {
	for i := range a.Resolutions {
		r := &a.Resolutions[i]
		if r.Question == name && r.Verified && (answer == "" || r.Answer == answer) {
			return r
		}
	}
	return nil
}

// dischargeFlowGaps removes from blockers each flow gap whose flow-gap
// resolution is value_preserved with a verified chain, marks those
// resolutions discharged and returns the remaining blockers and the
// discharged gaps.
func dischargeFlowGaps(a *analysis.Assessment, blockers []analysis.Gap) (remaining, discharged []analysis.Gap) {
	for _, g := range blockers {
		resolved := false
		if flowGapKinds[g.Kind] {
			for i := range a.Resolutions {
				r := &a.Resolutions[i]
				if r.QuestionVersion == FlowGapQuestionVersion && r.Verified && r.Answer == "value_preserved" && r.Blocker != nil && *r.Blocker == g {
					r.Discharged, resolved = true, true
				}
			}
		}
		if resolved {
			discharged = append(discharged, g)
		} else {
			remaining = append(remaining, g)
		}
	}
	return remaining, discharged
}

// citedDependency returns the dependency index a verified citation follows,
// or -1. Request dependencies keep the record's dependency order.
func citedDependency(r *analysis.Resolution) int {
	if r == nil || !r.Verified || r.Dependency == nil {
		return -1
	}
	return *r.Dependency
}

// pathHasWitness reports that the scanner's own facts already support a
// vulnerable path answer: an independent unsafe witness or weak controls only.
func pathHasWitness(u analysis.CandidateUse) bool {
	f := u.Path
	if f == nil {
		return false
	}
	python := strings.HasSuffix(u.Sink.Span.File, ".py")
	for _, flow := range f.Paths {
		if unsafeWitness(f, flow, python) {
			return true
		}
	}
	return weakControlsOnly(f)
}

// verifyWriteCitation checks a stored-origin citation: one cited write that
// was in the request and is a non-literal write of a key the record reads.
func verifyWriteCitation(use analysis.CandidateUse, x *wireIndex, cite []string) ([]analysis.Span, string) {
	if len(cite) != 1 {
		return nil, "a stored-origin citation names exactly one write"
	}
	e, ok := x.evidence[cite[0]]
	if !ok {
		return nil, "cited ID " + cite[0] + " was not in the request"
	}
	if use.StoredOrigin != nil {
		for _, s := range use.StoredOrigin.Stores {
			for _, w := range s.Writes {
				sp := w.Evidence.Span
				if !w.Literal && sp.File == e.file && sp.StartLine == e.start && sp.EndLine == e.end {
					return []analysis.Span{e.span()}, ""
				}
			}
		}
	}
	return []analysis.Span{e.span()}, "cited item " + cite[0] + " is not a non-literal write of a stored key this record reads"
}

// modelResolvedNote states which blockers a verified model resolution
// discharged, for the record's reason.
func modelResolvedNote(discharged []analysis.Gap) string {
	kinds := []string{}
	for _, g := range discharged {
		kinds = append(kinds, g.Kind)
	}
	return "Model-resolved: the decision model answered value_preserved with a verified evidence chain for " + strings.Join(kinds, ", ") + "; the resolution and its cited spans are recorded on the assessment."
}

// splitResolutionAnswers moves resolution answers out of the family answer
// map: they are recorded as Resolutions, and Answers keeps the family's own
// question protocol.
func splitResolutionAnswers(a *analysis.Assessment) {
	for name := range a.Answers {
		if strings.HasPrefix(name, resolvePrefix) {
			delete(a.Answers, name)
		}
	}
	for name := range a.AnswerDetails {
		if strings.HasPrefix(name, resolvePrefix) {
			delete(a.AnswerDetails, name)
		}
	}
}

func hasChoice(choices []map[string]string, value string) bool {
	for _, c := range choices {
		if c["value"] == value {
			return true
		}
	}
	return false
}

// dischargeStoredOrigin applies a stored-origin resolution (W3b, D-4). A
// verified cited request write removes the storage_origin_unresolved
// blockers: the record is a stored-flow finding candidate. An answer of
// no_request_write_in_evidence counts only when the scanner holds the
// coverage fact, every key's store closed; it then supports protection.
func dischargeStoredOrigin(use analysis.CandidateUse, a *analysis.Assessment, blockers []analysis.Gap) (remaining []analysis.Gap, cited, closedNoWrite bool) {
	var r *analysis.Resolution
	for i := range a.Resolutions {
		if a.Resolutions[i].QuestionVersion == StoredOriginQuestionVersion {
			r = &a.Resolutions[i]
		}
	}
	if r == nil {
		return blockers, false, false
	}
	switch {
	case r.Answer == "request_write_cited" && r.Verified:
		cited = true
	case r.Answer == "no_request_write_in_evidence" && allStoresClosed(use):
		closedNoWrite = true
	default:
		return blockers, false, false
	}
	r.Discharged = true
	for _, g := range blockers {
		if g.Kind != "storage_origin_unresolved" {
			remaining = append(remaining, g)
		}
	}
	return remaining, cited, closedNoWrite
}

func allStoresClosed(u analysis.CandidateUse) bool {
	if u.StoredOrigin == nil || len(u.StoredOrigin.Stores) == 0 {
		return false
	}
	for _, s := range u.StoredOrigin.Stores {
		if s.ClosedStore != "closed" {
			return false
		}
	}
	return true
}

// storedResolution returns the record's stored-origin resolution, or nil.
func storedResolution(a *analysis.Assessment) *analysis.Resolution {
	for i := range a.Resolutions {
		if a.Resolutions[i].QuestionVersion == StoredOriginQuestionVersion {
			return &a.Resolutions[i]
		}
	}
	return nil
}
