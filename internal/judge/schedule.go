package judge

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
)

// AssessableUse reports whether the candidate has a model assessment.
func AssessableUse(u analysis.CandidateUse) bool {
	return !analysispacks.ObservationOnly(u.Kind) && u.Kind != "xss_data_candidate"
}

func securitySinkPriority(u analysis.CandidateUse) int {
	if !AssessableUse(u) {
		return 2
	}
	if u.Kind == "input_validation_candidate" {
		return 1
	}
	return 0
}

// ScheduleOptions bounds assessment calls and records exact per-candidate traces.
type ScheduleOptions struct {
	Limit                         int
	SkippedFamilies, OnlyFamilies []string
	SaveTrace                     func(string, DecisionTrace) error
}

// AssessScheduled assesses stable priority groups, reusing only completed equivalent
// decisions. It returns true when a requested assessment or trace is incomplete.
func (c *Client) AssessScheduled(ctx context.Context, report *analysis.AnalysisReport, opts ScheduleOptions) bool {
	report.SkippedFamilies, report.OnlyFamilies = opts.SkippedFamilies, opts.OnlyFamilies
	order := make([]int, len(report.Uses))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(i, j int) bool {
		return securitySinkPriority(report.Uses[order[i]]) < securitySinkPriority(report.Uses[order[j]])
	})
	type decision struct {
		id    string
		trace DecisionTrace
	}
	completed := map[string]decision{}
	calls, derived, contexts := 0, 0, 0
	failed := false
	for _, i := range order {
		u := &report.Uses[i]
		family := analysispacks.FamilySlugForKind(u.Kind)
		if containsFamily(opts.SkippedFamilies, family) || len(opts.OnlyFamilies) > 0 && !containsFamily(opts.OnlyFamilies, family) {
			flag, names := "--skip-family", opts.SkippedFamilies
			if len(opts.OnlyFamilies) > 0 {
				flag, names = "--only-family", opts.OnlyFamilies
			}
			u.Assessment = analysis.Assessment{Status: "not_run", Reason: fmt.Sprintf("%s analyzer not used for this run (%s %s)", family, flag, strings.Join(names, ","))}
			continue
		}
		if !AssessableUse(*u) {
			u.Assessment = c.Assess(ctx, *u)
			failed = true
			continue
		}
		contexts++
		signature, err := c.EquivalenceSignature(*u)
		var trace DecisionTrace
		if previous, ok := completed[signature]; err == nil && ok {
			trace, err = c.Preview(*u)
			if err == nil {
				trace.Response, trace.ResponseBytes, trace.HTTPStatus = previous.trace.Response, previous.trace.ResponseBytes, previous.trace.HTTPStatus
				u.Assessment = c.Replay(*u, trace)
				if u.Assessment.Status == "completed" {
					u.Assessment.DeduplicatedFrom = previous.id
					u.Assessment.Usage = nil
					derived++
				}
			}
		} else if calls >= opts.Limit {
			u.Assessment = analysis.Assessment{Status: "not_run", Reason: "judge request limit reached"}
		} else {
			u.Assessment, trace = c.AssessTrace(ctx, *u)
			// Failed preflight and zero-call size limits do not spend HTTP slots.
			if trace.HTTPStatus != 0 || trace.RequestBytes > 0 && trace.RequestBytes <= requestLimit && !strings.HasPrefix(u.Assessment.Reason, "judge limit:") {
				calls++
			}
			if err == nil && u.Assessment.Status == "completed" {
				completed[signature] = decision{u.ID, trace}
			}
		}
		if u.Assessment.Status != "completed" {
			failed = true
		}
		if opts.SaveTrace != nil && len(trace.Request) > 0 {
			if err := opts.SaveTrace(u.ID, trace); err != nil {
				report.Limitations = append(report.Limitations, "Decision trace not saved: "+err.Error())
				failed = true
			}
		}
	}
	if len(opts.SkippedFamilies) > 0 || len(opts.OnlyFamilies) > 0 {
		report.Limitations = append(report.Limitations, "Analyzer family selection: skipped ["+strings.Join(opts.SkippedFamilies, ",")+"], only ["+strings.Join(opts.OnlyFamilies, ",")+"]. Excluded records remain unassessed; existing deterministic findings are retained. This scope choice is not an assessment.")
	}
	report.Limitations = append(report.Limitations, fmt.Sprintf("Judged %d distinct candidate signatures across %d total entry contexts (%d derived across equivalent entry contexts).", len(completed), contexts, derived))
	return failed
}

func containsFamily(names []string, family string) bool {
	for _, name := range names {
		if name == family {
			return true
		}
	}
	return false
}
