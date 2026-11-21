package report

import (
	"fmt"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

func relatedLocations(use analysis.CandidateUse) []any {
	out := []any{}
	seen := map[string]bool{}
	for _, e := range use.Context {
		key := fmt.Sprintf("%s:%d:%d", e.Span.File, e.Span.StartByte, e.Span.EndByte)
		if seen[key] || e.Span.File == "" {
			continue
		}
		seen[key] = true
		loc := location(e.Span, e.Kind)
		loc["id"] = len(out)
		out = append(out, loc)
	}
	return out
}

func checkedDependency(d analysis.Dependency, use analysis.CandidateUse) bool {
	if use.Check == nil {
		return true
	}
	return analysis.MatchesFields(d, use.Check.Fields)
}

func codeFlows(report *analysis.AnalysisReport, use analysis.CandidateUse) []any {
	out := []any{}
	for _, dep := range use.Dependencies {
		if !checkedDependency(dep, use) {
			continue
		}
		records := []analysis.Evidence{}
		for _, e := range report.Entries {
			if e.HTTP != nil && e.ID == use.EntryID {
				records = append(records, analysis.Evidence{Kind: "inbound_route", Span: e.HTTPRoute().Registration})
				break
			}
		}
		records = append(records, dep.Source)
		records = append(records, dep.Transfers...)
		records = append(records, use.Sink)
		locations := []any{}
		seen := map[string]bool{}
		for _, e := range records {
			if e.Span.File == "" {
				continue
			}
			key := fmt.Sprintf("%s:%d:%d", e.Span.File, e.Span.StartByte, e.Span.EndByte)
			if seen[key] {
				continue
			}
			seen[key] = true
			locations = append(locations, map[string]any{"location": location(e.Span, e.Kind), "executionOrder": len(locations), "properties": map[string]any{"scan.sha256": e.SHA256}})
		}
		if len(locations) > 0 {
			out = append(out, map[string]any{"message": map[string]string{"text": "Possible local source-to-use dependency path; not a runtime trace or a complete execution path."}, "threadFlows": []any{map[string]any{"locations": locations}}})
		}
	}
	return out
}
