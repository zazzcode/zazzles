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

// Structural factoring (judge-request-size-reduction D-3) is the last
// projection step, after resolution questions and citation chains are built
// from the unfactored rows. Both reductions are reversible: expandStructure
// restores the version 7 rows and dependencies exactly.

// v7EvidenceColumns is the evidence row order before D-3; factoredColumns
// puts text last so a row can end at its last non-empty column.
var (
	v7EvidenceColumns = []string{"kind", "source_index", "start_line", "end_line", "text", "text_ref", "start_column", "end_column"}
	factoredColumns   = []string{"kind", "source_index", "start_line", "end_line", "text_ref", "start_column", "end_column", "text"}
)

// minSharedTail is the shortest transfer run stated once for several dependencies.
const minSharedTail = 4

// factorStructure reorders evidence rows, trims trailing empty columns and
// states shared transfer tails once. The bundle is rewritten in place.
func factorStructure(bundle map[string]any) map[string]any {
	cw, _ := bundle["compact_wire"].(map[string]any)
	if rows, ok := bundle["evidence"].([]any); ok && cw != nil {
		for i, r := range rows {
			row, _ := r.([]any)
			if len(row) != len(v7EvidenceColumns) {
				continue
			}
			out := append(append(append([]any{}, row[:4]...), row[5:]...), row[4])
			for len(out) > 4 && (out[len(out)-1] == nil || out[len(out)-1] == "") {
				out = out[:len(out)-1]
			}
			rows[i] = out
		}
		cw["evidence_columns"] = factoredColumns
	}
	deps, _ := bundle["dependencies"].([]any)
	chains := make([][]any, len(deps))
	for i, d := range deps {
		dep, _ := d.(map[string]any)
		chains[i], _ = dep["transfers"].([]any)
	}
	tails := sharedTails(chains)
	if len(tails) == 0 {
		return bundle
	}
	stated := []any{}
	for n, tail := range tails {
		stated = append(stated, tail.run)
		for _, i := range tail.deps {
			dep := deps[i].(map[string]any)
			dep["transfers"] = append(append([]any{}, chains[i][:len(chains[i])-len(tail.run)]...), fmt.Sprintf("t%d", n))
		}
	}
	bundle["shared_transfer_tails"] = stated
	return bundle
}

type sharedTail struct {
	run  []any
	deps []int
}

// sharedTails picks transfer suffixes shared by two or more dependencies, the
// one that saves the most references first, until none of minSharedTail or
// more remains. Ties go to the longer run, then the earliest dependency.
func sharedTails(chains [][]any) []sharedTail {
	done := make([]bool, len(chains))
	var out []sharedTail
	for {
		best, bestSave := sharedTail{}, 0
		for i, chain := range chains {
			if done[i] {
				continue
			}
			for n := len(chain); n >= minSharedTail; n-- {
				run := chain[len(chain)-n:]
				members := []int{i}
				for j := i + 1; j < len(chains); j++ {
					if !done[j] && hasSuffix(chains[j], run) {
						members = append(members, j)
					}
				}
				if len(members) < 2 {
					continue
				}
				if save := (len(members) - 1) * (n - 1); save > bestSave || save == bestSave && n > len(best.run) {
					best, bestSave = sharedTail{run: run, deps: members}, save
				}
			}
		}
		if bestSave == 0 {
			return out
		}
		for _, i := range best.deps {
			done[i] = true
		}
		out = append(out, best)
	}
}

func hasSuffix(chain, run []any) bool {
	if len(chain) < len(run) {
		return false
	}
	tail := chain[len(chain)-len(run):]
	for k := range run {
		if tail[k] != run[k] {
			return false
		}
	}
	return true
}

// expandStructure reverses factorStructure: rows return to the version 7
// column order with their empty columns ("" for text, null otherwise), and
// each tN transfer reference is replaced by its shared run.
func expandStructure(bundle map[string]any) map[string]any {
	cw, _ := bundle["compact_wire"].(map[string]any)
	if cols, _ := cw["evidence_columns"].([]any); len(cols) == len(factoredColumns) && cols[len(cols)-1] == "text" {
		rows, _ := bundle["evidence"].([]any)
		for i, r := range rows {
			row, _ := r.([]any)
			full := make([]any, len(factoredColumns))
			copy(full, row)
			if full[7] == nil {
				full[7] = ""
			}
			rows[i] = append(append(append([]any{}, full[:4]...), full[7]), full[4:7]...)
		}
		columns := make([]any, len(v7EvidenceColumns))
		for i, c := range v7EvidenceColumns {
			columns[i] = c
		}
		cw["evidence_columns"] = columns
	}
	tails, _ := bundle["shared_transfer_tails"].([]any)
	if len(tails) == 0 {
		return bundle
	}
	deps, _ := bundle["dependencies"].([]any)
	for _, d := range deps {
		dep, _ := d.(map[string]any)
		transfers, _ := dep["transfers"].([]any)
		if len(transfers) == 0 {
			continue
		}
		var n int
		if ref, ok := transfers[len(transfers)-1].(string); ok {
			if _, err := fmt.Sscanf(ref, "t%d", &n); err == nil && n >= 0 && n < len(tails) && ref == fmt.Sprintf("t%d", n) {
				run, _ := tails[n].([]any)
				dep["transfers"] = append(append([]any{}, transfers[:len(transfers)-1]...), run...)
			}
		}
	}
	delete(bundle, "shared_transfer_tails")
	return bundle
}
