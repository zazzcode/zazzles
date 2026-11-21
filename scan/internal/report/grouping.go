package report

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

// sinkGroupKey is one presented row: records of one kind at one sink span
// with one presented status. Records with different statuses never share a
// group, so a group cannot hide a finding behind a Review row or the reverse.
type sinkGroupKey struct {
	kind, file string
	start, end int
	status     string
}

// groupSinks folds records that describe one sink into one representative row
// per kind, sink span and presented status. Findings stay parallel to uses: a
// folded record keeps its finding, marked grouped_into, and renderers skip it;
// canonical JSON keeps every record and judgment. The first record in report
// order represents its group and lists the others in grouped_use_ids.
//
// Outbound observations keep their own rule: only non-request destinations
// fold, and their summary text is unchanged. Request-derived destinations stay
// separate records.
func groupSinks(r *analysis.AnalysisReport) {
	first := map[sinkGroupKey]int{}
	var order []sinkGroupKey
	for i := range r.Findings {
		if i >= len(r.Uses) {
			break
		}
		u := r.Uses[i]
		if u.Sink.Span.File == "" || u.Kind == "outbound_http_candidate" && (u.Outbound == nil || u.Outbound.DestinationOrigin == analysis.DestinationRequest) {
			continue
		}
		k := sinkGroupKey{u.Kind, u.Sink.Span.File, u.Sink.Span.StartByte, u.Sink.Span.EndByte, r.Findings[i].Status}
		if u.Kind == "outbound_http_candidate" {
			k.status = "" // observations group by call site alone, as before
		}
		j, seen := first[k]
		if !seen {
			first[k] = i
			order = append(order, k)
			continue
		}
		r.Findings[i].GroupedInto = r.Findings[j].ID
		r.Findings[j].GroupedUseIDs = append(r.Findings[j].GroupedUseIDs, u.ID)
	}
	for _, k := range order {
		j := first[k]
		n := len(r.Findings[j].GroupedUseIDs)
		if n == 0 {
			continue
		}
		if k.kind == "outbound_http_candidate" {
			r.Findings[j].Summary += fmt.Sprintf(" %d entries reach this one call; they are reported as one observation (grouped_use_ids lists the other %d records).", n+1, n)
			continue
		}
		members := append([]int{j}, groupMembers(r, r.Findings[j].GroupedUseIDs)...)
		entries := map[string]bool{}
		origins := map[string]int{}
		for _, m := range members {
			entries[r.Uses[m].EntryID] = true
			for _, kind := range memberOrigins(r.Uses[m]) {
				origins[kind]++
			}
		}
		r.Findings[j].Summary += fmt.Sprintf(" This row stands for %d records from %d entries that reach this sink with status %s (grouped_use_ids lists the other %d; each keeps its own evidence and judgment in JSON). Origins across them: %s.", n+1, len(entries), k.status, n, originSummary(origins))
	}
}

// groupMembers returns the use indexes of the grouped record IDs.
func groupMembers(r *analysis.AnalysisReport, ids []string) []int {
	want := map[string]bool{}
	for _, id := range ids {
		want[id] = true
	}
	var out []int
	for i, u := range r.Uses {
		if want[u.ID] {
			out = append(out, i)
		}
	}
	return out
}

// memberOrigins names each distinct dependency origin kind of one record.
func memberOrigins(u analysis.CandidateUse) []string {
	seen := map[string]bool{}
	var out []string
	for _, d := range u.Dependencies {
		kind := d.Source.Kind
		if kind == "" {
			kind = "unknown"
		}
		if !seen[kind] {
			seen[kind] = true
			out = append(out, kind)
		}
	}
	if len(out) == 0 {
		out = []string{"none"}
	}
	return out
}

func originSummary(origins map[string]int) string {
	var kinds []string
	for k := range origins {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	var parts []string
	for _, k := range kinds {
		parts = append(parts, fmt.Sprintf("%s in %d", strings.ReplaceAll(k, "_", " "), origins[k]))
	}
	return strings.Join(parts, ", ")
}

// sinkGroupFingerprint identifies a grouped SARIF result by kind and sink span,
// so the result stays one alert as entries reaching the sink change.
func sinkGroupFingerprint(u analysis.CandidateUse) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%d|%d", u.Kind, u.Sink.Span.File, u.Sink.Span.StartByte, u.Sink.Span.EndByte)))
	return hex.EncodeToString(sum[:16])
}
