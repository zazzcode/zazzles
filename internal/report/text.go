package report

import (
	"fmt"
	"io"
	"sort"

	"github.com/zazzcode/zazzles/internal/analysis"
)

// Text renders entry coverage and the same contextual finding statuses as other exports.
func Text(w io.Writer, r *analysis.AnalysisReport) {
	Enrich(r)
	fmt.Fprintf(w, "entries: %d result records: %d\n", len(r.Entries), len(r.Uses))
	entries := append([]analysis.EntryPoint(nil), r.Entries...)
	sort.Slice(entries, func(i, j int) bool {
		a, b := EntryLabel(entries[i]), EntryLabel(entries[j])
		if a != b {
			return a < b
		}
		return entries[i].ID < entries[j].ID
	})
	seen := map[string]bool{}
	for _, e := range entries {
		seen[e.ID] = true
		v := entryDetails(r, e)
		fmt.Fprintf(w, "entry %s %s [%s] %s:%d\n", e.ID, v.Label, e.Kind, e.Location.Span.File, e.Location.Span.StartLine)
		for _, d := range v.Details {
			fmt.Fprintf(w, "  %s: %s\n", d.Label, d.Value)
		}
		for _, g := range r.EntryGaps(e.ID) {
			fmt.Fprintf(w, "  gap %s: %s\n", g.Kind, g.Detail)
		}
	}
	for i, u := range r.Uses {
		if !seen[u.EntryID] {
			fmt.Fprintf(w, "entry %s: unresolved entry association\n", u.EntryID)
			seen[u.EntryID] = true
		}
		f := r.Findings[i]
		if f.GroupedInto != "" {
			continue
		}
		fmt.Fprintf(w, "%s: %s [%s]\n%s\nentry=%s context=%s %s %s:%d sources=%d gaps=%d judge=%s\n", f.RecordType, f.Title, f.Status, f.Summary, u.EntryID, u.InvocationContextID, u.Kind, u.Sink.Span.File, u.Sink.Span.StartLine, len(u.Dependencies), len(u.Gaps), u.Assessment.Status)
		fmt.Fprintf(w, "assessment=%s (%s) blocking=%d linked=%d\n", f.AssessmentState, assessmentLabel(f.AssessmentState), len(f.BlockingEvidence), len(f.LinkedUseIDs))
		if u.Check != nil {
			fmt.Fprintf(w, "check=%s finding=%s protection=%s blockers=%d\n", u.Check.ID, u.Assessment.FindingStatus, u.Assessment.Protection, len(u.Assessment.BlockingGaps))
		}
	}
	for _, m := range r.CheckMatches {
		fmt.Fprintf(w, "check %s entry=%s context=%s uses=%d\n", m.CheckID, m.EntryID, m.InvocationContextID, m.UseCount)
	}
	for _, p := range r.Practice {
		at := ""
		if len(p.Evidence) > 0 {
			at = fmt.Sprintf("%s:%d", p.Evidence[0].Span.File, p.Evidence[0].Span.StartLine)
		}
		fmt.Fprintf(w, "practice %s [%s] %s %s: %s\n", p.Check, p.Status, at, p.Title, p.Detail)
	}
	for _, g := range r.Gaps {
		fmt.Fprintf(w, "gap %s %s:%d %s\n", g.Kind, g.At.File, g.At.StartLine, g.Detail)
	}
}
