package judge

import (
	"encoding/json"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
)

func TestCompactBundleIsLossless(t *testing.T) {
	e := analysis.Evidence{Kind: "operation", Text: "g0", SHA256: "snapshot", Span: analysis.Span{File: "source.py", StartLine: 1, EndLine: 1, EndByte: 2}}
	gap := analysis.Gap{Kind: "unknown_guard", Detail: "guard is not established", At: e.Span}
	u := analysis.CandidateUse{Sink: e, Context: []analysis.Evidence{e}, Gaps: []analysis.Gap{gap, gap}, Completeness: &analysis.Completeness{Blockers: []analysis.Gap{gap}, Coverage: []analysis.Gap{gap}, Evidence: map[string][]analysis.Evidence{"operation": {e}}}}
	bundle := wireBundle(u)
	packed, err := compactBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	normalize := func(v any) map[string]any {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		var out map[string]any
		if err := json.Unmarshal(b, &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	want, got := normalize(bundle), normalize(packed)
	schema := got["compact_wire"].(map[string]any)
	sources := schema["sources"].([]any)
	gaps := schema["gaps"].([]any)
	details := schema["gap_details"].([]any)
	location := func(source any, coords []any) (map[string]any, string) {
		p := sources[int(source.(float64))].([]any)
		return map[string]any{"file": p[0], "start_line": coords[0], "end_line": coords[1]}, ""
	}
	evidence := []any{}
	for _, item := range got["evidence"].([]any) {
		row := item.([]any)
		span, _ := location(row[1], row[2:4])
		e := map[string]any{"kind": row[0], "span": span, "text": row[4]}
		if row[5] != nil {
			e["text_ref"] = row[5]
			e["start_column"] = row[6]
			e["end_column"] = row[7]
		}
		evidence = append(evidence, e)
	}
	got["evidence"] = evidence
	excerpts := []any{}
	for _, item := range got["source_excerpts"].([]any) {
		row := item.([]any)
		span, _ := location(row[0], row[1:3])
		excerpts = append(excerpts, map[string]any{"kind": "source_excerpt", "span": span, "text": row[3]})
	}
	got["source_excerpts"] = excerpts
	var restore func(any) any
	restore = func(v any) any {
		switch x := v.(type) {
		case []any:
			for i := range x {
				if ref, ok := x[i].(string); ok && strings.HasPrefix(ref, "g") {
					if id, err := strconv.Atoi(ref[1:]); err == nil && id >= 0 && id < len(gaps) {
						row := gaps[id].([]any)
						span, _ := location(row[2], row[3:5])
						x[i] = map[string]any{"kind": row[0], "detail": details[int(row[1].(float64))], "at": span}
						continue
					}
				}
				x[i] = restore(x[i])
			}
		case map[string]any:
			for k, value := range x {
				x[k] = restore(value)
			}
		}
		return v
	}
	// Only gap collections contain gN references. A real source literal "g0"
	// must remain source text rather than being reinterpreted as metadata.
	for _, key := range []string{"blocking_gaps", "coverage_gaps"} {
		got[key] = restore(got[key])
	}
	invocation := got["invocation"].(map[string]any)
	for _, key := range []string{"entry_gaps", "dispatch_gaps", "context_gaps"} {
		if v, ok := invocation[key]; ok {
			invocation[key] = restore(v)
		}
	}
	delete(got, "compact_wire")
	delete(want, "trace_graph")
	var omitProvenance func(any)
	omitProvenance = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			delete(x, "sha256")
			delete(x, "start_byte")
			delete(x, "end_byte")
			for _, item := range x {
				omitProvenance(item)
			}
		case []any:
			for _, item := range x {
				omitProvenance(item)
			}
		}
	}
	omitProvenance(want)
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("compact bundle failed exact reconstruction\nwant=%v\ngot=%v", want, got)
	}
	again, err := compactBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(normalize(packed), normalize(again)) {
		t.Fatal("compaction order changed")
	}
}
