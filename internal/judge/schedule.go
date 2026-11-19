package judge

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

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
	Limit int
	// Concurrency caps in-flight assessment requests; 0 or less means 1.
	Concurrency                   int
	SkippedFamilies, OnlyFamilies []string
	SaveTrace                     func(string, DecisionTrace) error
}

// planned is one assessable candidate after the offline plan pass.
type planned struct {
	index      int // into report.Uses
	rank       int // position in priority order
	use        analysis.CandidateUse
	signature  string
	shares     bool // signature computed; the candidate may reuse or record a decision
	preview    DecisionTrace
	previewErr error
	spends     bool    // reaches HTTP if dispatched with the limiter open
	slot       bool    // assigned a request slot by the plan pass
	offline    *result // pre-dispatch outcome of a candidate that cannot reach HTTP
}

// result is one assessment attempt. halts records that this attempt stopped the limiter.
type result struct {
	assessment analysis.Assessment
	trace      DecisionTrace
	halts      bool
}

// AssessScheduled assesses stable priority groups, reusing only completed equivalent
// decisions. It returns true when a requested assessment or trace is incomplete.
//
// It runs in three passes. The plan pass is offline and sequential: it groups
// candidates by equivalence signature and assigns request slots in priority
// order before any request starts. Dispatch sends each group's leader through a
// pool of opts.Concurrency workers, in waves: a group whose leader did not
// complete promotes its next member into a remaining slot. Finalization then
// walks priority order alone, replaying members, applying limit and halt
// outcomes, saving traces, and writing limitations, so output never depends on
// completion order. With Concurrency 1 it reproduces the serial scheduler.
func (c *Client) AssessScheduled(ctx context.Context, report *analysis.AnalysisReport, opts ScheduleOptions) bool {
	report.SkippedFamilies, report.OnlyFamilies = opts.SkippedFamilies, opts.OnlyFamilies
	n := max(opts.Concurrency, 1)
	if c.limiter != nil {
		c.limiter.useConcurrency(n)
	}
	order := make([]int, len(report.Uses))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(i, j int) bool {
		return securitySinkPriority(report.Uses[order[i]]) < securitySinkPriority(report.Uses[order[j]])
	})
	startHalted := c.limiter.haltReason() != ""
	groups, early := c.plan(ctx, report, order, opts)
	results := c.waves(ctx, groups, opts.Limit, n)
	return c.finalize(ctx, report, order, opts, groups, early, results, startHalted)
}

// familyExclusion returns the not-run assessment for a family this run excludes.
func familyExclusion(u analysis.CandidateUse, opts ScheduleOptions) (analysis.Assessment, bool) {
	family := analysispacks.FamilySlugForKind(u.Kind)
	if !containsFamily(opts.SkippedFamilies, family) && (len(opts.OnlyFamilies) == 0 || containsFamily(opts.OnlyFamilies, family)) {
		return analysis.Assessment{}, false
	}
	flag, names := "--skip-family", opts.SkippedFamilies
	if len(opts.OnlyFamilies) > 0 {
		flag, names = "--only-family", opts.OnlyFamilies
	}
	return analysis.Assessment{Status: "not_run", Reason: fmt.Sprintf("%s analyzer not used for this run (%s %s)", family, flag, strings.Join(names, ","))}, true
}

// plan is the offline, sequential pass. It settles excluded and non-assessable
// candidates, groups the rest by signature in priority order, predicts which
// attempts reach HTTP (Preview plus the size and TPM preflight), and assigns
// request slots to group leaders in priority order until opts.Limit. It starts
// no goroutine and sends nothing.
func (c *Client) plan(ctx context.Context, report *analysis.AnalysisReport, order []int, opts ScheduleOptions) (groups [][]planned, early map[int]analysis.Assessment) {
	early = map[int]analysis.Assessment{}
	bySignature := map[string]int{}
	for rank, i := range order {
		u := report.Uses[i]
		if a, excluded := familyExclusion(u, opts); excluded {
			early[i] = a
			continue
		}
		if a, fixed := sendGate(u, opts); fixed {
			early[i] = a
			continue
		}
		if !AssessableUse(u) {
			early[i] = c.Assess(ctx, u) // observation records return before any request
			continue
		}
		p := planned{index: i, rank: rank, use: u}
		var err error
		p.signature, err = c.EquivalenceSignature(u)
		p.shares = err == nil
		p.preview, p.previewErr = c.Preview(u)
		// Failed preflight and zero-call size limits do not spend HTTP slots.
		p.spends = p.previewErr == nil && p.preview.RequestBytes > 0 && p.preview.RequestBytes <= requestLimit && !c.limiter.oversized(p.preview.RequestBytes)
		if !p.spends {
			a, trace := c.AssessTrace(ctx, u) // returns before transport: payload, size or TPM refusal
			p.offline = &result{assessment: a, trace: trace}
		}
		g, ok := bySignature[p.signature]
		if !ok || !p.shares {
			g = len(groups)
			groups = append(groups, nil)
			if p.shares {
				bySignature[p.signature] = g
			}
		}
		groups[g] = append(groups[g], p)
	}
	// Slots go to each group's first spending member, in priority order.
	var leaders []*planned
	for g := range groups {
		if m := nextSpender(groups[g], 0); m >= 0 {
			leaders = append(leaders, &groups[g][m])
		}
	}
	sort.Slice(leaders, func(i, j int) bool { return leaders[i].rank < leaders[j].rank })
	for k := 0; k < len(leaders) && k < opts.Limit; k++ {
		leaders[k].slot = true
	}
	return groups, early
}

// nextSpender returns the first member at or after from that reaches HTTP, or -1.
func nextSpender(group []planned, from int) int {
	for m := from; m < len(group); m++ {
		if group[m].spends {
			return m
		}
	}
	return -1
}

// waves dispatches slotted leaders, then promotes the next spending member of
// each group whose dispatched member did not complete, while unassigned slots
// remain and the limiter is open. Results are keyed by use index.
func (c *Client) waves(ctx context.Context, groups [][]planned, limit, n int) map[int]result {
	results := map[int]result{}
	free := limit
	type cursor struct{ group, member int }
	var wave []cursor
	for g := range groups {
		for m := range groups[g] {
			if groups[g][m].slot {
				wave = append(wave, cursor{g, m})
				free--
			}
		}
	}
	for len(wave) > 0 {
		sort.Slice(wave, func(i, j int) bool {
			return groups[wave[i].group][wave[i].member].rank < groups[wave[j].group][wave[j].member].rank
		})
		leaders := make([]planned, len(wave))
		for k, at := range wave {
			leaders[k] = groups[at.group][at.member]
		}
		for index, r := range c.dispatch(ctx, leaders, n) {
			results[index] = r
		}
		if c.limiter.haltReason() != "" || ctx.Err() != nil {
			break
		}
		var next []cursor
		for _, at := range wave {
			if results[groups[at.group][at.member].index].assessment.Status == "completed" {
				continue
			}
			if m := nextSpender(groups[at.group], at.member+1); m >= 0 && free > 0 {
				groups[at.group][m].slot = true
				next = append(next, cursor{at.group, m})
				free--
			}
		}
		wave = next
	}
	return results
}

// dispatch sends leaders, in the given order, through at most n workers.
func (c *Client) dispatch(ctx context.Context, leaders []planned, n int) map[int]result {
	jobs := make(chan planned)
	out := make(map[int]result, len(leaders))
	var mu sync.Mutex
	var wg sync.WaitGroup
	for w := 0; w < min(n, len(leaders)); w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {
				before := c.limiter.haltReason()
				a, trace := c.AssessTrace(ctx, p.use)
				r := result{assessment: a, trace: trace, halts: before == "" && c.limiter.haltReason() != ""}
				mu.Lock()
				out[p.index] = r
				mu.Unlock()
			}
		}()
	}
	for _, p := range leaders {
		jobs <- p
	}
	close(jobs)
	wg.Wait()
	return out
}

// finalize walks priority order alone. It replays equivalent members, applies
// the request cap and halt outcomes, saves traces and writes limitations in
// that order. It never sends a request: a candidate that needs an attempt the
// plan did not dispatch either cannot reach HTTP (closed limiter, canceled
// context, preflight refusal) or receives the request-limit outcome.
func (c *Client) finalize(ctx context.Context, report *analysis.AnalysisReport, order []int, opts ScheduleOptions, groups [][]planned, early map[int]analysis.Assessment, results map[int]result, halted bool) bool {
	byIndex := map[int]*planned{}
	for g := range groups {
		for m := range groups[g] {
			byIndex[groups[g][m].index] = &groups[g][m]
		}
	}
	attempt := func(p *planned) result {
		if r, ok := results[p.index]; ok {
			return r
		}
		if p.offline != nil && !halted {
			return *p.offline
		}
		if !p.spends || halted || ctx.Err() != nil {
			a, trace := c.AssessTrace(ctx, p.use) // returns before transport
			return result{assessment: a, trace: trace}
		}
		return result{assessment: analysis.Assessment{Status: "not_run", Reason: "judge request limit reached"}}
	}
	type decision struct {
		id    string
		trace DecisionTrace
	}
	completed := map[string]decision{}
	calls, derived, contexts, undecidable, unresolvable := 0, 0, 0, 0, 0
	failed := false
	for _, i := range order {
		u := &report.Uses[i]
		if a, ok := early[i]; ok {
			u.Assessment = a
			_, excluded := familyExclusion(*u, opts)
			_, fixed := sendGate(*u, opts)
			if _, v := validationGate(*u, opts); v {
				undecidable++
			} else if fixed {
				unresolvable++
			}
			if !excluded && !fixed {
				failed = true
			}
			continue
		}
		p := byIndex[i]
		contexts++
		var trace DecisionTrace
		if previous, ok := completed[p.signature]; p.shares && ok {
			trace = p.preview
			if p.previewErr == nil {
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
			r := attempt(p)
			u.Assessment, trace = r.assessment, r.trace
			if trace.HTTPStatus != 0 || trace.RequestBytes > 0 && trace.RequestBytes <= requestLimit && !strings.HasPrefix(u.Assessment.Reason, "judge limit:") {
				calls++
			}
			if p.shares && u.Assessment.Status == "completed" {
				completed[p.signature] = decision{u.ID, trace}
			}
			halted = halted || r.halts
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
	if sent, unresolved, capped := c.followUps(ctx, report, order, opts, calls); sent+unresolved+capped > 0 {
		report.Limitations = append(report.Limitations, fmt.Sprintf("Evidence follow-ups: %d sent beside %d assessment requests (cap %d%%, %d); %d named items the snapshot did not resolve exactly; %d over the cap (follow_up_cap_reached).", sent, calls, FollowUpShare, calls*FollowUpShare/100, unresolved, capped))
	}
	if len(opts.SkippedFamilies) > 0 || len(opts.OnlyFamilies) > 0 {
		report.Limitations = append(report.Limitations, "Analyzer family selection: skipped ["+strings.Join(opts.SkippedFamilies, ",")+"], only ["+strings.Join(opts.OnlyFamilies, ",")+"]. Excluded records remain unassessed; existing deterministic findings are retained. This scope choice is not an assessment.")
	}
	if undecidable > 0 {
		report.Limitations = append(report.Limitations, fmt.Sprintf("%d validation records were not sent to the judge: their field-policy gate lacks required evidence, so no answer could change their Review outcome (%s).", undecidable, ValidationUndecidable))
	}
	if unresolvable > 0 {
		report.Limitations = append(report.Limitations, fmt.Sprintf("%d records were not sent to the judge: a scanner blocker fixes their Review outcome and has no resolution question, so no answer could change it (%s).", unresolvable, BlockerUnresolvable))
	}
	report.Limitations = append(report.Limitations, fmt.Sprintf("Judged %d distinct candidate signatures across %d total entry contexts (%d derived across equivalent entry contexts).", len(completed), contexts, derived))
	return failed
}

// sendGate settles a record no answer could change before any request: the
// validation decidability gate, then the resolution gate (D-7).
func sendGate(u analysis.CandidateUse, opts ScheduleOptions) (analysis.Assessment, bool) {
	if a, fixed := validationGate(u, opts); fixed {
		return a, true
	}
	return resolutionGate(u)
}

func containsFamily(names []string, family string) bool {
	for _, name := range names {
		if name == family {
			return true
		}
	}
	return false
}
