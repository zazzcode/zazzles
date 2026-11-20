package judge

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/internal/pipeline"
)

// inventoryIdentifier matches a hash-based identifier as the request carries
// it: a <kind>:v1:<64 hex> value, or an entry instance_id value (whose last
// segment is a 64-hex digest), inside the escaped input string.
var inventoryIdentifier = regexp.MustCompile(`[a-z_]+:v1:[0-9a-f]{64}|instance_id\\":\\"[^\\"]*`)

// TestRequestInventory (judge-request-size-reduction D-1) builds every planned
// request of one sample offline and writes one TSV row per request to
// ZAZZLES_INVENTORY_OUT. It needs ZAZZLES_SAMPLE and never sends a request.
//
// Columns: record_id, kind, sink (file:line), entry_file, group_key (empty
// for a single request; "<key> (path_group_cap)" for a group beyond the cap),
// request_bytes (the request as sent; above the limit for evidence_too_large),
// whole_bytes (the record's unbudgeted, ungrouped request), excerpt_bytes
// (source_excerpts text), identifier_bytes (hash-based identifiers),
// question_bytes (the encoded questions array), notice_bytes (size-notice gap
// details), lossy_omitted_bytes, omitted_items, resolution_dropped and
// signature (the record's equivalence signature).
func TestRequestInventory(t *testing.T) {
	root := os.Getenv("ZAZZLES_SAMPLE")
	if root == "" {
		t.Skip("set ZAZZLES_SAMPLE to a clean sample checkout and ZAZZLES_INVENTORY_OUT to a TSV path")
	}
	out := os.Getenv("ZAZZLES_INVENTORY_OUT")
	if out == "" {
		t.Fatal("set ZAZZLES_INVENTORY_OUT to the TSV path to write")
	}
	r, err := pipeline.Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	c, err := New("openai", "fixture-model", "synthetic-test-key")
	if err != nil {
		t.Fatal(err)
	}
	entries := map[string]string{}
	for _, e := range r.Entries {
		entries[e.ID] = e.Location.Span.File
	}
	rows := []string{strings.Join([]string{"record_id", "kind", "sink", "entry_file", "group_key", "request_bytes", "whole_bytes", "excerpt_bytes", "identifier_bytes", "question_bytes", "notice_bytes", "lossy_omitted_bytes", "omitted_items", "resolution_dropped", "signature"}, "\t")}
	var sizes []int
	records, over, groupRequests, nearLimit := 0, 0, 0, 0
	total := 0
	signatures := map[string]bool{}
	sums := map[string]int{}
	for _, u := range r.Uses {
		if !AssessableUse(u) {
			continue
		}
		records++
		whole, err := c.payloadForm(u, true)
		if err != nil {
			t.Fatalf("%s: %v", u.ID, err)
		}
		signature, err := c.EquivalenceSignature(u)
		if err != nil {
			signature = "error:" + u.ID
		}
		signatures[signature] = true
		trace, err := c.Preview(u)
		if err != nil {
			t.Fatalf("%s: %v", u.ID, err)
		}
		row := func(key string, t DecisionTrace) {
			m := inventoryMeasure(t)
			lossy, items, dropped := 0, 0, false
			for _, o := range t.EvidenceOmissions {
				if o.Kind == "resolution_questions" {
					dropped = true
					continue
				}
				items++
				if !o.Lossless {
					lossy += o.Bytes
				}
			}
			sizes = append(sizes, t.RequestBytes)
			total += t.RequestBytes
			if t.RequestBytes > requestLimit*9/10 {
				nearLimit++
			}
			sums["excerpt"] += m.excerpt
			sums["identifier"] += m.identifier
			sums["question"] += m.question
			sums["notice"] += m.notice
			sums["lossy"] += lossy
			rows = append(rows, strings.Join([]string{u.ID, u.Kind, fmt.Sprintf("%s:%d", u.Sink.Span.File, u.Sink.Span.StartLine), entries[u.EntryID], key,
				fmt.Sprint(t.RequestBytes), fmt.Sprint(len(whole)), fmt.Sprint(m.excerpt), fmt.Sprint(m.identifier), fmt.Sprint(m.question), fmt.Sprint(m.notice),
				fmt.Sprint(lossy), fmt.Sprint(items), fmt.Sprint(dropped), signature}, "\t"))
		}
		if len(whole) > requestLimit {
			over++
		}
		if len(trace.Groups) == 0 {
			row("", trace)
			continue
		}
		groups, _ := c.planPathGroups(u)
		for i, g := range trace.Groups {
			groupRequests++
			row(groups[i].key, g)
		}
		for i := maxPathGroups; i < len(groups); i++ {
			row(groups[i].key+" ("+pathGroupCap+")", DecisionTrace{})
		}
	}
	if err := os.WriteFile(out, []byte(strings.Join(rows, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sort.Ints(sizes)
	pct := func(p int) int {
		if len(sizes) == 0 {
			return 0
		}
		return sizes[(len(sizes)-1)*p/100]
	}
	t.Logf("records=%d requests=%d over_limit_records=%d group_requests=%d total_bytes=%d median=%d p95=%d largest=%d near_limit=%d excerpt=%d identifier=%d question=%d notice=%d lossy_omitted=%d classes=%d",
		records, len(sizes), over, groupRequests, total, pct(50), pct(95), pct(100), nearLimit, sums["excerpt"], sums["identifier"], sums["question"], sums["notice"], sums["lossy"], len(signatures))
}

type inventoryParts struct{ excerpt, identifier, question, notice int }

// inventoryMeasure splits one request into the parts the inventory reports.
// Columns are found by name, so the measure reads every evidence version.
func inventoryMeasure(t DecisionTrace) inventoryParts {
	var m inventoryParts
	if len(t.Request) == 0 {
		return m
	}
	for _, id := range inventoryIdentifier.FindAll(t.Request, -1) {
		if v, ok := bytes.CutPrefix(id, []byte(`instance_id\":\"`)); ok {
			id = v
		}
		m.identifier += len(id)
	}
	var envelope struct {
		Questions json.RawMessage `json:"questions"`
	}
	_ = json.Unmarshal(t.Request, &envelope)
	m.question = len(envelope.Questions)
	use, err := requestUse(t.Request)
	if err != nil {
		return m
	}
	cw, _ := use["compact_wire"].(map[string]any)
	column := func(name, key string) int {
		cols, _ := cw[name].([]any)
		for i, c := range cols {
			if c == key {
				return i
			}
		}
		return -1
	}
	if i := column("excerpt_columns", "text"); i >= 0 {
		rows, _ := use["source_excerpts"].([]any)
		for _, r := range rows {
			if row, _ := r.([]any); i < len(row) {
				s, _ := row[i].(string)
				m.excerpt += len(s)
			}
		}
	}
	kind, detail := column("gap_columns", "kind"), column("gap_columns", "detail_index")
	details, _ := cw["gap_details"].([]any)
	gaps, _ := cw["gaps"].([]any)
	seen := map[int]bool{}
	for _, g := range gaps {
		row, _ := g.([]any)
		if kind < 0 || detail < 0 || kind >= len(row) || detail >= len(row) {
			continue
		}
		k, _ := row[kind].(string)
		d := intOf(row[detail])
		if (k == "evidence_omitted_for_size" || k == "path_group_omitted") && !seen[d] && d >= 0 && d < len(details) {
			seen[d] = true
			s, _ := details[d].(string)
			m.notice += len(s)
		}
	}
	return m
}
