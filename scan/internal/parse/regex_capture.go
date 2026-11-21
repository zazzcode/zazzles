package parse

import (
	"regexp"
	"strings"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

// Capture classes as recorded on a regex_capture transform (the classifier
// lives in analysispacks).
const (
	captureAdmitsAny = "admits_any"
	regexCaptureKind = "regex_capture"
)

// ApplyCaptureRule is the deterministic regex-capture rule (close-findings-gaps
// D-6). A guarded shell path whose dependency is the capture of one literal
// expression classified admits_any, and whose every control is only a match
// test of that same expression (beside presence and runtime-type tests), is
// raw: the guard provably passes shell syntax. Any other control keeps it
// guarded; other classes stay guarded and model-judged. shell reports
// whether a path reaches the effective shell-command operand; c's operand
// path summary is refreshed when a path changes.
func ApplyCaptureRule(u *analysis.CandidateUse, c *analysis.Completeness, paths []analysis.CommandPath, shell func(analysis.CommandPath) bool) {
	changed := false
	defer func() {
		if changed && c != nil {
			for i, f := range c.ModelFacts {
				if strings.HasPrefix(f, operandPathFacts) {
					c.ModelFacts[i] = operandPathSummary(u, paths)
				}
			}
		}
	}()
	for i := range paths {
		p := &paths[i]
		if p.Protection != "guarded" || p.Dependency < 0 || p.Dependency >= len(u.Dependencies) || !shell(*p) {
			continue
		}
		dep := u.Dependencies[p.Dependency]
		capture, ok := soleCapture(dep)
		if !ok || capture.Class != captureAdmitsAny || len(p.Controls) == 0 {
			continue
		}
		names := CommandDepNames(dep)
		only := true
		for _, c := range p.Controls {
			if c < 0 || c >= len(u.Context) || !onlyMatchTest(u.Context[c].Text, capture, names) {
				only = false
				break
			}
		}
		if !only {
			continue
		}
		p.Protection = "raw"
		p.Reason = "the only control is a match test of " + capture.Regex + ", whose captured group (" + capture.SubPattern + ") admits any character, including shell syntax; the capture is kept as a transform"
		p.Controls = nil
		changed = true
	}
}

// soleCapture returns the dependency's regex capture when every capture on
// it is of one expression.
func soleCapture(d analysis.Dependency) (analysis.ValueTransform, bool) {
	var out analysis.ValueTransform
	found := false
	for _, t := range d.Transforms {
		if t.Kind != regexCaptureKind {
			continue
		}
		if found && (t.Regex != out.Regex || t.Group != out.Group || t.Pattern != out.Pattern) {
			return analysis.ValueTransform{}, false
		}
		out, found = t, true
	}
	return out, found && out.Regex != ""
}

// onlyMatchTest reports a condition that, with the capture's match tests
// removed, only tests presence or runtime type.
func onlyMatchTest(cond string, capture analysis.ValueTransform, names []string) bool {
	rest := cond
	tested := false
	tests := append([]string{}, capture.Tests...)
	// Longest first so a call text never splits a longer one.
	for i := 1; i < len(tests); i++ {
		for j := i; j > 0 && len(tests[j]) > len(tests[j-1]); j-- {
			tests[j], tests[j-1] = tests[j-1], tests[j]
		}
	}
	for _, t := range tests {
		switch {
		case t == "":
		case PlainIdentifier.MatchString(t):
			// A match object tested for presence (Python `if m:`).
			re := regexp.MustCompile(`(^|[^\w$.])` + regexp.QuoteMeta(t) + `($|[^\w$(.\[])`)
			if re.MatchString(rest) {
				rest = re.ReplaceAllString(rest, "$1$2")
				tested = true
			}
		case strings.Contains(rest, t):
			rest = strings.ReplaceAll(rest, t, "")
			tested = true
		}
	}
	return tested && PresenceOnlyCondition(rest, names)
}
