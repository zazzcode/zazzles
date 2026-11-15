package judge

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/zazzcode/zazzles/internal/analysis"
)

// requestLimit is the largest provider request the client sends. Tests lower it
// to exercise the budget; production code never changes it.
var requestLimit = 64 << 10

// evidenceTooLarge prefixes the reason of a record whose blocking and path
// evidence alone exceed the request limit. It is a stable, greppable code.
const evidenceTooLarge = "evidence_too_large"

// gateRoles are evidence roles a scanner gate reads besides a claim's required
// roles. The budget never sheds them, so the model sees what the gate weighs.
var gateRoles = map[string]bool{
	"input_source": true, "sink_binding": true, "invoked_callable": true, "control_flow": true,
	"invocation_binding": true, "path_operands": true, "field_policy": true, "conditional_value": true,
	"sql_all_inputs_hex": true, "selector_type_guard": true, "selector_path_string": true,
	"allowlist_definition": true, "path_conditions": true,
}

// controlKinds are evidence kinds that record a control on a value or path.
// They are path evidence wherever they appear, so the budget never sheds them.
var controlKinds = map[string]bool{
	"branch_precondition": true, "branch_true_precondition": true, "branch_false_precondition": true, "branch_alternative": true,
	"guard_test": true, "conditional_test": true, "conditional_false_test": true, "exception_precondition": true, "condition": true,
	"terminating_guard": true, "enclosing_guard": true, "allowlist_definition": true,
}

type spanKey struct {
	file, hash string
	start, end int
}

func keyOf(e analysis.Evidence) spanKey {
	return spanKey{e.Span.File, e.SHA256, e.Span.StartByte, e.Span.EndByte}
}

func contains(outer spanKey, inner analysis.Span) bool {
	return outer.file == inner.File && outer.start <= inner.StartByte && outer.end >= inner.EndByte && outer.end > outer.start
}

// sheddable is one context span the budget may leave out, with its order key.
type sheddable struct {
	key       spanKey
	kind      string
	bytes     int
	contained bool // text wholly inside another kept item: omitting it loses no source
	otherFile bool
	distance  int
}

// budgetUse returns a reduced copy of use whose context leaves out the fewest
// whole evidence items, in a fixed order, needed for fit(use) to hold. Blocking
// and path evidence is never removed. The second result lists what was left out,
// in shedding order; the reduced copy states the same list in a coverage gap.
// When nothing more can be shed and fit still fails, the reduced copy is returned
// with every sheddable item left out, and the caller applies the floor.
func budgetUse(use analysis.CandidateUse, fit func(analysis.CandidateUse) bool) (analysis.CandidateUse, []analysis.EvidenceOmission) {
	keep := map[spanKey]bool{}
	keep[keyOf(use.Sink)] = true
	pathSpans := []analysis.Span{use.Sink.Span}
	for _, d := range use.Dependencies {
		keep[keyOf(d.Source)] = true
		pathSpans = append(pathSpans, d.Source.Span)
		for _, t := range d.Transfers {
			keep[keyOf(t)] = true
			pathSpans = append(pathSpans, t.Span)
		}
	}
	for _, e := range use.ControlEdges {
		keep[keyOf(e.From)], keep[keyOf(e.To)] = true, true
	}
	decisive := map[string]bool{}
	if c := use.Completeness; c != nil {
		for _, role := range c.Required {
			decisive[role] = true
		}
		for _, g := range c.Blockers {
			pathSpans = append(pathSpans, g.At)
		}
	}
	if use.Components != nil {
		for _, role := range use.Components.Required {
			decisive[role] = true
		}
	}
	for role := range gateRoles {
		decisive[role] = true
	}
	for _, i := range indexedContext(use) {
		if i >= 0 && i < len(use.Context) {
			keep[keyOf(use.Context[i])] = true
		}
	}
	candidates := map[spanKey]analysis.Evidence{}
	consider := func(e analysis.Evidence, decisiveRole bool) {
		k := keyOf(e)
		if decisiveRole || controlKinds[e.Kind] {
			keep[k] = true
			return
		}
		if _, ok := candidates[k]; !ok {
			candidates[k] = e
		}
	}
	for _, e := range use.Context {
		consider(e, false)
	}
	if c := use.Completeness; c != nil {
		for role, items := range c.Evidence {
			for _, e := range items {
				consider(e, decisive[role])
			}
		}
	}
	all := append([]analysis.Evidence{use.Sink}, use.Context...)
	if c := use.Completeness; c != nil {
		for _, items := range c.Evidence {
			all = append(all, items...)
		}
	}
	var order []sheddable
	for k, e := range candidates {
		if keep[k] {
			continue
		}
		onPath := false
		for _, s := range pathSpans {
			onPath = onPath || contains(k, s)
		}
		if onPath {
			continue
		}
		item := sheddable{key: k, kind: e.Kind, bytes: len(e.Text)}
		item.otherFile = k.file != use.Sink.Span.File
		if !item.otherFile {
			item.distance = k.start - use.Sink.Span.EndByte
			if k.end < use.Sink.Span.StartByte {
				item.distance = use.Sink.Span.StartByte - k.end
			}
			if item.distance < 0 {
				item.distance = 0
			}
		}
		for _, o := range all {
			other := keyOf(o)
			if other != k && other.hash == k.hash && o.Text != "" && contains(other, analysis.Span{File: k.file, StartByte: k.start, EndByte: k.end}) {
				item.contained = true
				break
			}
		}
		order = append(order, item)
	}
	sort.Slice(order, func(i, j int) bool {
		a, b := order[i], order[j]
		if a.contained != b.contained {
			return a.contained
		}
		if a.otherFile != b.otherFile {
			return a.otherFile
		}
		if a.otherFile && a.bytes != b.bytes {
			return a.bytes > b.bytes
		}
		if !a.otherFile && a.distance != b.distance {
			return a.distance > b.distance
		}
		if a.key.file != b.key.file {
			return a.key.file < b.key.file
		}
		if a.key.start != b.key.start {
			return a.key.start < b.key.start
		}
		if a.key.end != b.key.end {
			return a.key.end < b.key.end
		}
		return a.kind < b.kind
	})
	// A contained item never changes which source text is supplied, so the
	// lossless prefix is always taken before a lossy item is considered.
	dropped := map[spanKey]bool{}
	var omitted []analysis.EvidenceOmission
	reduced := use
	for _, item := range order {
		dropped[item.key] = true
		omitted = append(omitted, analysis.EvidenceOmission{Kind: item.kind, Span: spanOf(item.key, candidates[item.key].Span), Bytes: item.bytes, Lossless: item.contained})
		reduced = withoutContext(use, dropped, omitted)
		if fit(reduced) {
			return reduced, omitted
		}
	}
	return reduced, omitted
}

func spanOf(k spanKey, s analysis.Span) analysis.Span {
	s.File, s.StartByte, s.EndByte = k.file, k.start, k.end
	return s
}

// indexedContext lists the use.Context positions that family facts reference.
func indexedContext(use analysis.CandidateUse) []int {
	var out []int
	if f := use.Command; f != nil {
		for _, o := range f.Operands {
			out = append(out, o.Context...)
		}
		for _, p := range f.Paths {
			out = append(out, p.Controls...)
		}
	}
	if f := use.Path; f != nil {
		for _, o := range f.Operands {
			out = append(out, o.Context...)
		}
		for _, g := range f.Guards {
			out = append(out, g.Context)
		}
		if f.Extractor != nil {
			out = append(out, f.Extractor.Context)
		}
	}
	if f := use.Outbound; f != nil {
		for _, p := range f.Paths {
			out = append(out, p.Controls...)
		}
	}
	return out
}

// withoutContext copies use without the dropped spans in Context and in
// non-decisive roles, remaps every context index held by family facts, and adds
// the omission gap. The input use is never modified.
func withoutContext(use analysis.CandidateUse, dropped map[spanKey]bool, omitted []analysis.EvidenceOmission) analysis.CandidateUse {
	out := use
	remap := make([]int, len(use.Context))
	out.Context = nil
	for i, e := range use.Context {
		remap[i] = -1
		if !dropped[keyOf(e)] {
			remap[i] = len(out.Context)
			out.Context = append(out.Context, e)
		}
	}
	mapAll := func(items []int) []int {
		if items == nil {
			return nil
		}
		next := make([]int, len(items))
		for i, v := range items {
			next[i] = remap[v]
		}
		return next
	}
	if f := use.Command; f != nil {
		copyFacts := *f
		copyFacts.Operands = append([]analysis.CommandOperand(nil), f.Operands...)
		for i := range copyFacts.Operands {
			copyFacts.Operands[i].Context = mapAll(f.Operands[i].Context)
		}
		copyFacts.Paths = append([]analysis.CommandPath(nil), f.Paths...)
		for i := range copyFacts.Paths {
			copyFacts.Paths[i].Controls = mapAll(f.Paths[i].Controls)
		}
		out.Command = &copyFacts
	}
	if f := use.Path; f != nil {
		copyFacts := *f
		copyFacts.Operands = append([]analysis.PathOperand(nil), f.Operands...)
		for i := range copyFacts.Operands {
			copyFacts.Operands[i].Context = mapAll(f.Operands[i].Context)
		}
		copyFacts.Guards = append([]analysis.PathGuard(nil), f.Guards...)
		for i := range copyFacts.Guards {
			copyFacts.Guards[i].Context = remap[f.Guards[i].Context]
		}
		if f.Extractor != nil {
			ex := *f.Extractor
			ex.Context = remap[ex.Context]
			copyFacts.Extractor = &ex
		}
		out.Path = &copyFacts
	}
	if f := use.Outbound; f != nil {
		copyFacts := *f
		copyFacts.Paths = append([]analysis.CommandPath(nil), f.Paths...)
		for i := range copyFacts.Paths {
			copyFacts.Paths[i].Controls = mapAll(f.Paths[i].Controls)
		}
		out.Outbound = &copyFacts
	}
	gap := omissionGap(use.Sink.Span, omitted)
	if c := use.Completeness; c != nil {
		copyC := *c
		copyC.Evidence = map[string][]analysis.Evidence{}
		for role, items := range c.Evidence {
			var kept []analysis.Evidence
			for _, e := range items {
				if !dropped[keyOf(e)] {
					kept = append(kept, e)
				}
			}
			if len(kept) > 0 || len(items) == 0 {
				copyC.Evidence[role] = kept
			}
		}
		copyC.Coverage = append(append([]analysis.Gap{}, c.Coverage...), gap)
		out.Completeness = &copyC
	} else {
		out.Gaps = append(append([]analysis.Gap{}, use.Gaps...), gap)
	}
	return out
}

// omissionGap states every omitted item so the model can weigh what it did not see.
func omissionGap(at analysis.Span, omitted []analysis.EvidenceOmission) analysis.Gap {
	kinds := map[string]int{}
	total, lossless := 0, 0
	spans := make([]string, 0, len(omitted))
	for _, o := range omitted {
		kinds[o.Kind]++
		spans = append(spans, fmt.Sprintf("%s:%d-%d", o.Span.File, o.Span.StartLine, o.Span.EndLine))
		if o.Lossless {
			lossless++
			continue
		}
		total += o.Bytes
	}
	names := make([]string, 0, len(kinds))
	for k := range kinds {
		names = append(names, fmt.Sprintf("%s x%d", k, kinds[k]))
	}
	sort.Strings(names)
	return analysis.Gap{Kind: "evidence_omitted_for_size", At: at, Detail: fmt.Sprintf(
		"%d context evidence item(s) (%s) were left out so the request fits the %d-byte limit; %d of them only repeat source text still supplied in another item, and the others remove %d source bytes. None is dependency, control or required evidence; the scanner still holds them. Omitted spans: %s. Do not treat omitted context as absent protection or absent risk.",
		len(omitted), strings.Join(names, ", "), requestLimit, lossless, total, strings.Join(spans, ", "))}
}

// sectionSizes reports request bytes by section of the encoded evidence so an
// over-limit reason shows where the size is.
func sectionSizes(payload []byte) string {
	var outer map[string]json.RawMessage
	if json.Unmarshal(payload, &outer) != nil {
		return ""
	}
	var text string
	for _, field := range []string{"input", "state"} {
		if raw, ok := outer[field]; ok && json.Unmarshal(raw, &text) == nil {
			break
		}
	}
	var inner map[string]json.RawMessage
	if json.Unmarshal([]byte(text), &inner) != nil {
		return ""
	}
	var use map[string]json.RawMessage
	_ = json.Unmarshal(inner["use"], &use)
	type part struct {
		name string
		size int
	}
	var parts []part
	for k, v := range use {
		parts = append(parts, part{k, len(v)})
	}
	for k, v := range inner {
		if k != "use" {
			parts = append(parts, part{k, len(v)})
		}
	}
	sort.Slice(parts, func(i, j int) bool {
		if parts[i].size != parts[j].size {
			return parts[i].size > parts[j].size
		}
		return parts[i].name < parts[j].name
	})
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		out = append(out, fmt.Sprintf("%s %d", p.name, p.size))
	}
	return strings.Join(out, ", ")
}
