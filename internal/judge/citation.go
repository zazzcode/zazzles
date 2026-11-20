package judge

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/zazzcode/zazzles/internal/analysis"
)

// wireItem is one evidence row (eN) or gap row (gN) of a compacted request.
type wireItem struct {
	kind, file, text string
	start, end       int
}

func (w wireItem) span() analysis.Span {
	return analysis.Span{File: w.file, StartLine: w.start, EndLine: w.end}
}

// overlaps reports a shared file and an overlapping line range.
func (w wireItem) overlaps(o wireItem) bool {
	return w.file == o.file && w.start <= o.end && o.start <= w.end
}

// wireIndex is the citation view of one request: its item IDs, its
// source-to-sink dependency chains and its scanner edges. It is built from
// the compacted request the model received, so a citation is checked against
// exactly what was sent.
type wireIndex struct {
	evidence map[string]wireItem
	gaps     map[string]wireItem
	// chains[i] is dependency i: source, transfers in order, then the sink.
	chains [][]string
	sink   string
	edges  map[[2]string]bool
}

// indexWire reads a compacted request bundle (the "use" object).
func indexWire(use map[string]any) (*wireIndex, error) {
	x := &wireIndex{evidence: map[string]wireItem{}, gaps: map[string]wireItem{}, edges: map[[2]string]bool{}}
	cw, _ := use["compact_wire"].(map[string]any)
	if cw == nil {
		return nil, errors.New("request has no compact_wire table")
	}
	var files []string
	sources, _ := cw["sources"].([]any)
	for _, s := range sources {
		row, _ := s.([]any)
		file := ""
		if len(row) > 0 {
			file, _ = row[0].(string)
		}
		files = append(files, file)
	}
	file := func(v any) string {
		i := intOf(v)
		if i >= 0 && i < len(files) {
			return files[i]
		}
		return ""
	}
	excerpts, _ := use["source_excerpts"].([]any)
	rows, _ := use["evidence"].([]any)
	for i, r := range rows {
		row, _ := r.([]any)
		if len(row) < 5 {
			continue
		}
		kind, _ := row[0].(string)
		text, _ := row[4].(string)
		if text == "" && len(row) > 7 {
			// Deduplicated evidence carries its text as a reference into
			// source_excerpts; a citation label must show the same code.
			ref, _ := row[5].(string)
			text = excerptText(excerpts, ref, intOf(row[2]), intOf(row[3]), intOf(row[6]), intOf(row[7]))
		}
		x.evidence[fmt.Sprintf("e%d", i)] = wireItem{kind: kind, file: file(row[1]), start: intOf(row[2]), end: intOf(row[3]), text: text}
	}
	gaps, _ := cw["gaps"].([]any)
	for i, r := range gaps {
		row, _ := r.([]any)
		if len(row) < 5 {
			continue
		}
		kind, _ := row[0].(string)
		x.gaps[fmt.Sprintf("g%d", i)] = wireItem{kind: kind, file: file(row[2]), start: intOf(row[3]), end: intOf(row[4])}
	}
	x.sink, _ = use["sink_evidence"].(string)
	deps, _ := use["dependencies"].([]any)
	for _, d := range deps {
		dep, _ := d.(map[string]any)
		chain := []string{}
		if src, ok := dep["source"].(string); ok {
			chain = append(chain, src)
		}
		transfers, _ := dep["transfers"].([]any)
		for _, t := range transfers {
			if id, ok := t.(string); ok {
				chain = append(chain, id)
			}
		}
		chain = append(chain, x.sink)
		// Shared evidence is one row, so a chain can name an ID twice; the
		// cited form names each item once, in first-seen order.
		seen := map[string]bool{}
		unique := chain[:0:0]
		for _, id := range chain {
			if !seen[id] {
				seen[id] = true
				unique = append(unique, id)
			}
		}
		chain = unique
		for i := 0; i+1 < len(chain); i++ {
			x.edges[[2]string{chain[i], chain[i+1]}] = true
		}
		x.chains = append(x.chains, chain)
	}
	edges, _ := use["control_edges"].([]any)
	for _, e := range edges {
		edge, _ := e.(map[string]any)
		from, _ := edge["from"].(string)
		to, _ := edge["to"].(string)
		if from != "" && to != "" {
			x.edges[[2]string{from, to}] = true
		}
	}
	return x, nil
}

// requestUse extracts the compacted "use" bundle from a provider request, with
// its factored rows and shared transfer tails expanded (D-3), so a citation
// is checked against the chains the request states.
func requestUse(payload []byte) (map[string]any, error) {
	var envelope map[string]any
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return nil, err
	}
	input, _ := envelope["input"].(string)
	if input == "" {
		input, _ = envelope["state"].(string)
	}
	var body struct {
		Use map[string]any `json:"use"`
	}
	if err := json.Unmarshal([]byte(input), &body); err != nil || body.Use == nil {
		return nil, errors.New("request has no use bundle")
	}
	return expandStructure(body.Use), nil
}

func intOf(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	}
	return -1
}

// touches reports that gap overlaps an item of dependency chain i.
func (x *wireIndex) touches(gap string, i int) bool {
	g, ok := x.gaps[gap]
	if !ok || i < 0 || i >= len(x.chains) {
		return false
	}
	for _, id := range x.chains[i] {
		if e, ok := x.evidence[id]; ok && e.overlaps(g) {
			return true
		}
	}
	return false
}

// precedes reports that a comes before b in dependency chain i.
func (x *wireIndex) precedes(i int, a, b string) bool {
	at := -1
	for k, id := range x.chains[i] {
		if id == a && at < 0 {
			at = k
		}
		if id == b && at >= 0 && k > at {
			return true
		}
	}
	return false
}

// bridges reports that gap overlaps a, c or an item between them in
// dependency chain i: the bridged hop is the one the gap stands for.
func (x *wireIndex) bridges(i int, a, c, gap string) bool {
	g := x.gaps[gap]
	inside := false
	for _, id := range x.chains[i] {
		if id == a {
			inside = true
		}
		if inside {
			if e, ok := x.evidence[id]; ok && e.overlaps(g) {
				return true
			}
		}
		if id == c {
			return false
		}
	}
	return false
}

// citation is a verified chain: its spans and the dependency it follows.
type citation struct {
	spans      []analysis.Span
	dependency int
}

// verifyCitation is the one citation check for every family (D-1, D-2). A
// chain is verified when every ID was in the request, it runs from a
// dependency source to the sink, no ID repeats, and each hop is a scanner
// edge or a bridge through the asked gap within a dependency that gap
// touches. asked is the gap ID the question asked about, or "" when the
// question asked for a witness over scanner edges only. It returns the
// rejection reason, or "" when the chain verifies.
func verifyCitation(x *wireIndex, cite []string, asked string) (citation, string) {
	out := citation{dependency: -1}
	if x == nil {
		return out, "the request could not be indexed"
	}
	if len(cite) == 0 {
		return out, "empty citation"
	}
	seen := map[string]bool{}
	gapAt := -1
	for i, id := range cite {
		if seen[id] {
			return out, "cited ID " + id + " repeats"
		}
		seen[id] = true
		if e, ok := x.evidence[id]; ok {
			out.spans = append(out.spans, e.span())
			continue
		}
		g, ok := x.gaps[id]
		if !ok {
			return out, "cited ID " + id + " was not in the request"
		}
		if id != asked {
			return out, "cited gap " + id + " is not the gap the question asked about"
		}
		out.spans = append(out.spans, g.span())
		gapAt = i
	}
	if asked != "" && gapAt < 0 {
		return out, "chain skips the asked gap " + asked
	}
	if gapAt == 0 || gapAt == len(cite)-1 {
		return out, "the asked gap must lie between two cited evidence items"
	}
	if cite[len(cite)-1] != x.sink {
		return out, "chain does not end at the sink evidence"
	}
	for i, chain := range x.chains {
		if len(chain) == 0 || chain[0] != cite[0] || out.dependency >= 0 || gapAt >= 0 && !x.touches(asked, i) {
			continue
		}
		in := map[string]bool{}
		for _, id := range chain {
			in[id] = true
		}
		all := true
		for _, id := range cite {
			all = all && (in[id] || id == asked)
		}
		if all || gapAt < 0 {
			out.dependency = i
		}
	}
	if out.dependency < 0 {
		if gapAt >= 0 {
			return out, "chain does not start at the source of a dependency the asked gap touches"
		}
		return out, "chain does not start at a dependency source"
	}
	for i := 0; i+1 < len(cite); i++ {
		a, b := cite[i], cite[i+1]
		if b == asked {
			c := cite[i+2]
			if !x.precedes(out.dependency, a, c) || !x.bridges(out.dependency, a, c, asked) {
				return out, fmt.Sprintf("hop %s>%s>%s through the asked gap does not bridge items of the gap's dependency in order", a, b, c)
			}
			i++ // the bridge covers a>gap>c
			continue
		}
		if !x.edges[[2]string{a, b}] {
			return out, fmt.Sprintf("hop %s>%s is neither a scanner edge nor the asked gap", a, b)
		}
	}
	return out, ""
}

// parseCitation splits a citation choice value ("e1>g0>e4") into IDs; "none"
// and "" are an empty citation.
func parseCitation(value string) []string {
	if value == "" || value == citeNone {
		return nil
	}
	return strings.Split(value, ">")
}

const citeNone = "none"

// excerptText cuts an evidence item's text out of the source excerpt its
// text_ref names: lines start..end of the excerpt, the first from column sc
// and the last to column ec (one-based, exclusive end; first-line columns are
// relative to the excerpt's text start).
func excerptText(excerpts []any, ref string, start, end, sc, ec int) string {
	var n int
	if _, err := fmt.Sscanf(ref, "s%d", &n); err != nil || n < 0 || n >= len(excerpts) {
		return ""
	}
	row, _ := excerpts[n].([]any)
	if len(row) < 4 {
		return ""
	}
	first := intOf(row[1])
	body, _ := row[3].(string)
	lines := strings.Split(body, "\n")
	from, to := start-first, end-first
	if from < 0 || to >= len(lines) || from > to {
		return ""
	}
	out := make([]string, 0, to-from+1)
	for i := from; i <= to; i++ {
		line := []rune(lines[i])
		lo, hi := 0, len(line)
		if i == from && sc > 0 {
			lo = min(sc-1, len(line))
		}
		if i == to && ec > 0 {
			hi = min(max(ec-1, lo), len(line))
		}
		out = append(out, string(line[lo:hi]))
	}
	return strings.Join(out, "\n")
}
