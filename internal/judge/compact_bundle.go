package judge

import (
	"encoding/json"
	"fmt"
	"sort"
)

// Compaction keeps record order, roles, executable source, gaps and references.
// Snapshot hashes and byte coordinates stay in local provenance; excerpt columns
// distinguish nodes sharing a line in the model-facing projection.
func compactBundle(bundle any) (any, error) {
	out, _, err := compactBundleIDs(bundle)
	return out, err
}

// compactBundleIDs compacts the bundle and also returns each gap's request ID
// (gN) keyed by gapKey, so resolution questions can name the gap they ask about.
func compactBundleIDs(bundle any) (map[string]any, map[string]string, error) {
	raw, err := json.Marshal(bundle)
	if err != nil {
		return nil, nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, nil, err
	}
	sources := []any{}
	sourceIDs := map[string]int{}
	source := func(file, hash any) int {
		key := fmt.Sprint(file)
		if i, ok := sourceIDs[key]; ok {
			return i
		}
		i := len(sources)
		sourceIDs[key] = i
		sources = append(sources, []any{file})
		return i
	}
	span := func(s map[string]any) []any {
		return []any{s["start_line"], s["end_line"]}
	}
	evidence := []any{}
	for _, item := range out["evidence"].([]any) {
		e := item.(map[string]any)
		s := e["span"].(map[string]any)
		row := []any{e["kind"], source(s["file"], e["sha256"])}
		row = append(row, span(s)...)
		row = append(row, e["text"], e["text_ref"], e["start_column"], e["end_column"])
		evidence = append(evidence, row)
	}
	out["evidence"] = evidence
	excerpts := []any{}
	for _, item := range out["source_excerpts"].([]any) {
		e := item.(map[string]any)
		s := e["span"].(map[string]any)
		row := []any{source(s["file"], e["sha256"])}
		row = append(row, span(s)...)
		row = append(row, e["text"])
		excerpts = append(excerpts, row)
	}
	out["source_excerpts"] = excerpts
	gaps := []any{}
	gapIDs := map[string]string{}
	details := []any{}
	detailIDs := map[string]int{}
	var visit func(any) any
	visit = func(value any) any {
		switch v := value.(type) {
		case []any:
			for i := range v {
				v[i] = visit(v[i])
			}
			return v
		case map[string]any:
			if len(v) == 3 && v["kind"] != nil && v["detail"] != nil && v["at"] != nil {
				key := gapKey(v)
				if id, ok := gapIDs[key]; ok {
					return id
				}
				detail := v["detail"].(string)
				di, ok := detailIDs[detail]
				if !ok {
					di = len(details)
					detailIDs[detail] = di
					details = append(details, detail)
				}
				s := v["at"].(map[string]any)
				row := []any{v["kind"], di, source(s["file"], "")}
				row = append(row, span(s)...)
				id := fmt.Sprintf("g%d", len(gaps))
				gapIDs[key] = id
				gaps = append(gaps, row)
				return id
			}
			// These coordinates identify snapshots locally; model evidence uses lines.
			delete(v, "start_byte")
			delete(v, "end_byte")
			delete(v, "sha256")
			keys := make([]string, 0, len(v))
			for k := range v {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				v[k] = visit(v[k])
			}
			return v
		}
		return value
	}
	// Dependencies retain storage keys and transfer order; control_edges retain
	// all explicit edge kinds. trace_graph is derived from these exact witnesses.
	delete(out, "trace_graph")
	visit(out)
	out["compact_wire"] = map[string]any{
		"sources": sources, "gap_details": details, "gaps": gaps,
		"evidence_columns": []string{"kind", "source_index", "start_line", "end_line", "text", "text_ref", "start_column", "end_column"},
		"excerpt_columns":  []string{"source_index", "start_line", "end_line", "text"},
		"gap_columns":      []string{"kind", "detail_index", "source_index", "start_line", "end_line"},
		"source_columns":   []string{"file"},
	}
	return out, gapIDs, nil
}

// gapKey is the compaction key of a gap: its generic JSON form, which is the
// form the compactor sees.
func gapKey(g any) string {
	raw, _ := json.Marshal(g)
	var v any
	_ = json.Unmarshal(raw, &v)
	key, _ := json.Marshal(v)
	return string(key)
}
