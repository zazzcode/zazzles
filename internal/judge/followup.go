package judge

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
)

// NeededEvidenceQuestionVersion versions the one-evidence-request question (W5).
const NeededEvidenceQuestionVersion = "needed-evidence-v1"

// neededQuestion is the request question through which the model names one
// missing item (D-6).
const neededQuestion = resolvePrefix + "needed"

// FollowUpShare caps follow-ups at this percentage of a scan's assessment
// requests (owner decision, §11 Q3).
const FollowUpShare = 25

// followUpKind is the context evidence kind of the item a follow-up carries;
// its presence marks a follow-up request, which never asks for more.
const followUpKind = "follow_up_evidence"

const maxNeededChoices = 4

// symbolGaps maps gap kinds whose detail names an unresolved symbol to the
// kind of item that would resolve it.
var symbolGaps = map[string]string{
	"input_helper_unresolved": "helper_body",
	"unknown_transfer":        "helper_body",
	"python_call_unresolved":  "helper_body",
	"unknown_call_result":     "helper_body",
	"recursive_helper":        "helper_body",
	"unknown_value":           "value_definition",
	"python_value_unresolved": "value_definition",
	"php_value_unresolved":    "value_definition",
	"middleware_unresolved":   "middleware",
}

var symbolName = regexp.MustCompile(`^\$?[A-Za-z_][\w]*(?:\.[A-Za-z_]\w*)*`)

// neededChoices offers the symbols the scanner itself names in the record's
// gaps, by kind and symbol, plus none. Labels never come from the model.
func neededChoices(u analysis.CandidateUse) []map[string]string {
	if u.Completeness == nil {
		return nil
	}
	for _, e := range u.Context {
		if e.Kind == followUpKind {
			return nil // a follow-up never asks for a second one
		}
	}
	seen := map[string]bool{}
	var out []map[string]string
	for _, g := range append(append([]analysis.Gap{}, u.Completeness.Blockers...), u.Completeness.Coverage...) {
		kind, ok := symbolGaps[g.Kind]
		if !ok {
			continue
		}
		_, tail, found := strings.Cut(g.Detail, ": ")
		if !found {
			continue
		}
		symbol := symbolName.FindString(strings.TrimSpace(tail))
		if symbol == "" || seen[kind+":"+symbol] || len(out) >= maxNeededChoices {
			continue
		}
		seen[kind+":"+symbol] = true
		out = append(out, map[string]string{"value": kind + ":" + symbol, "description": fmt.Sprintf("Ask for the %s of %s (%s at %s:%d).", strings.ReplaceAll(kind, "_", " "), symbol, g.Kind, g.At.File, g.At.StartLine)})
	}
	if len(out) == 0 {
		return nil
	}
	return append(out, map[string]string{"value": citeNone, "description": "No single missing item would change your answers, or the needed item is not listed."})
}

func neededAsk(u analysis.CandidateUse) *resolutionAsk {
	choices := neededChoices(u)
	if choices == nil {
		return nil
	}
	q := question{name: neededQuestion, choices: choices, instructions: "If exactly one listed item that the supplied evidence lacks (a helper body, a value definition or a middleware) would let you answer a question you answered unknown or uncertain, choose it; the scanner may send one follow-up with that item's source. Otherwise choose none."}
	return &resolutionAsk{name: neededQuestion, version: NeededEvidenceQuestionVersion, answer: &q}
}

// neededFollowUp reads the model's evidence request from its answers.
func neededFollowUp(answers map[string]string) *analysis.FollowUp {
	v := answers[neededQuestion]
	kind, symbol, ok := strings.Cut(v, ":")
	if v == "" || v == citeNone || !ok {
		return nil
	}
	return &analysis.FollowUp{Kind: kind, Symbol: symbol, Status: "requested"}
}

// contractAnswersFollowUp returns the guard whose contract on the record
// already describes a requested helper body (D-3), or "". A language
// built-in such as String.prototype.match has no body in any snapshot.
func contractAnswersFollowUp(u analysis.CandidateUse, kind, symbol string) string {
	if kind != "helper_body" {
		return ""
	}
	return analysispacks.GuardContractMember(u, symbol)
}

// snapshot resolves symbols in the scanned files whose bytes match the snapshot.
type snapshot struct {
	files []censusFile
}

type censusFile struct {
	path, sha string
	src       []byte
}

func newSnapshot(report *analysis.AnalysisReport) *snapshot {
	s := &snapshot{}
	seen := map[string]bool{}
	for _, f := range report.Files {
		if seen[f.Span.File] || report.Root == "" {
			continue
		}
		seen[f.Span.File] = true
		src, err := os.ReadFile(filepath.Join(report.Root, f.Span.File))
		if err != nil || fmt.Sprintf("%x", sha256.Sum256(src)) != f.SHA256 {
			continue
		}
		s.files = append(s.files, censusFile{f.Span.File, f.SHA256, src})
	}
	sort.Slice(s.files, func(i, j int) bool { return s.files[i].path < s.files[j].path })
	return s
}

// resolve returns the one definition of symbol's final name in files of the
// record's language, or false when there is none or more than one.
func (s *snapshot) resolve(kind, symbol, language string) (analysis.Evidence, bool) {
	name := symbol[strings.LastIndex(symbol, ".")+1:]
	name = strings.TrimPrefix(name, "$")
	q := regexp.QuoteMeta(name)
	var def *regexp.Regexp
	switch language {
	case ".py":
		if kind == "value_definition" {
			def = regexp.MustCompile(`(?m)^[ \t]*` + q + `\s*=[^=]`)
		} else {
			def = regexp.MustCompile(`(?m)^[ \t]*(?:async\s+)?def\s+` + q + `\s*\(`)
		}
	case ".php":
		if kind == "value_definition" {
			def = regexp.MustCompile(`(?m)^[ \t]*\$` + q + `\s*=[^=]`)
		} else {
			def = regexp.MustCompile(`(?m)^[ \t]*(?:(?:public|private|protected|static)\s+)*function\s+&?` + q + `\s*\(`)
		}
	default:
		def = regexp.MustCompile(`(?m)^[ \t]*(?:export\s+)?(?:(?:async\s+)?function\s*\*?\s*` + q + `\s*\(|(?:const|let|var)\s+` + q + `\s*=)`)
	}
	var hits []analysis.Evidence
	for _, f := range s.files {
		if !sameLanguage(f.path, language) {
			continue
		}
		for _, loc := range def.FindAllIndex(f.src, -1) {
			hits = append(hits, definitionEvidence(f, loc[0], language))
		}
	}
	if len(hits) != 1 {
		return analysis.Evidence{}, false
	}
	return hits[0], true
}

func sameLanguage(path, language string) bool {
	ext := filepath.Ext(path)
	switch language {
	case ".py", ".php":
		return ext == language
	}
	return ext == ".js" || ext == ".ts" || ext == ".jsx" || ext == ".tsx" || ext == ".mjs" || ext == ".cjs"
}

// definitionEvidence covers a definition from its line through its body:
// balanced braces for JS/TS and PHP, the indented block for Python; at most
// 60 lines.
func definitionEvidence(f censusFile, start int, language string) analysis.Evidence {
	for start > 0 && f.src[start-1] != '\n' {
		start--
	}
	end, lines := start, 0
	if language == ".py" {
		indent := len(f.src[start:]) - len(strings.TrimLeft(string(f.src[start:]), " \t"))
		for end < len(f.src) && lines < 60 {
			next := strings.IndexByte(string(f.src[end:]), '\n')
			if next < 0 {
				end = len(f.src)
				break
			}
			end += next + 1
			lines++
			rest := string(f.src[end:])
			line, _, _ := strings.Cut(rest, "\n")
			if strings.TrimSpace(line) != "" && len(line)-len(strings.TrimLeft(line, " \t")) <= indent {
				break
			}
		}
	} else {
		depth, opened := 0, false
		for ; end < len(f.src) && lines < 60; end++ {
			switch f.src[end] {
			case '{':
				depth++
				opened = true
			case '}':
				depth--
			case '\n':
				lines++
			}
			if opened && depth == 0 {
				end++
				break
			}
		}
	}
	text := string(f.src[start:end])
	return analysis.Evidence{Kind: followUpKind, Text: strings.TrimRight(text, "\n"), SHA256: f.sha,
		Span: analysis.Span{File: f.path, StartLine: strings.Count(string(f.src[:start]), "\n") + 1, EndLine: strings.Count(string(f.src[:start]), "\n") + 1 + strings.Count(strings.TrimRight(text, "\n"), "\n"), StartByte: start, EndByte: start + len(strings.TrimRight(text, "\n"))}}
}

// followUps sends at most one follow-up per record (D-6, W5), in priority
// order, for Review records whose model named one missing item that the
// snapshot resolves exactly. Follow-ups stop at FollowUpShare percent of the
// scan's assessment requests; a record over the cap records
// follow_up_cap_reached. It returns the number sent.
func (c *Client) followUps(ctx context.Context, report *analysis.AnalysisReport, order []int, opts ScheduleOptions, calls int) (sent, unresolved, capped int) {
	limit := calls * FollowUpShare / 100
	var snap *snapshot
	var jobs []planned
	evidence := map[int]analysis.Evidence{}
	for rank, i := range order {
		u := &report.Uses[i]
		f := u.Assessment.FollowUp
		if f == nil || f.Status != "requested" {
			continue
		}
		if u.Assessment.DeduplicatedFrom != "" || u.Assessment.Status != "completed" || u.Assessment.FindingStatus != "needs_evidence" {
			f.Status, f.Reason = "not_sent", "the record is not an assessed Review record"
			continue
		}
		if guard := contractAnswersFollowUp(*u, f.Kind, f.Symbol); guard != "" {
			f.Status, f.Reason = "answered_by_contract", "the "+guard+" guard contract supplied with the request already describes "+f.Symbol
			continue
		}
		if snap == nil {
			snap = newSnapshot(report)
		}
		e, ok := snap.resolve(f.Kind, f.Symbol, filepath.Ext(u.Sink.Span.File))
		if !ok {
			f.Status, f.Reason = "unresolved", "the scanned snapshot has no single exact definition of "+f.Symbol
			unresolved++
			continue
		}
		if len(jobs) >= limit {
			f.Status, f.Reason = "follow_up_cap_reached", fmt.Sprintf("follow-ups are capped at %d%% of the scan's %d assessment requests", FollowUpShare, calls)
			capped++
			continue
		}
		if c.limiter.haltReason() != "" || ctx.Err() != nil {
			f.Status, f.Reason = "failed", "the judge stopped before the follow-up"
			continue
		}
		next := *u
		next.Context = append(append([]analysis.Evidence{}, u.Context...), e)
		evidence[i] = e
		jobs = append(jobs, planned{index: i, rank: rank, use: next})
	}
	if len(jobs) == 0 {
		return 0, unresolved, capped
	}
	results := c.dispatch(ctx, jobs, max(opts.Concurrency, 1))
	for _, p := range jobs {
		u := &report.Uses[p.index]
		r := results[p.index]
		e := evidence[p.index]
		prior := u.Assessment.FollowUp
		if r.trace.HTTPStatus != 0 || r.trace.RequestBytes > 0 {
			sent++
		}
		if opts.SaveTrace != nil && len(r.trace.Request) > 0 {
			if err := opts.SaveTrace(u.ID+"~follow-up", r.trace); err != nil {
				report.Limitations = append(report.Limitations, "Decision trace not saved: "+err.Error())
			}
		}
		if r.assessment.Status != "completed" {
			prior.Status, prior.Evidence, prior.Reason = "failed", &e, r.assessment.Reason
			continue
		}
		next := r.assessment
		for k, v := range u.Assessment.Usage {
			if next.Usage == nil {
				next.Usage = map[string]int64{}
			}
			next.Usage[k] += v
		}
		next.FollowUp = &analysis.FollowUp{Kind: prior.Kind, Symbol: prior.Symbol, Status: "sent", Evidence: &e}
		u.Assessment = next
	}
	return sent, unresolved, capped
}
