package langjs

import (
	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/parse"
	"strings"
)

// queryConstraintReview preserves potential contradictions for the judgment gate.
// These witnesses never establish protection by themselves.
func (s *moduleSet) queryConstraintReview(use *analysis.CandidateUse) {
	c := use.Completeness
	if use.Kind == "sql_query_candidate" {
		allHex, count := true, 0
		for _, d := range use.Dependencies {
			if d.SinkSlot != "sql_text" {
				continue
			}
			count++
			hex := false
			for _, e := range d.Transfers {
				if e.Kind != "native_hash_hex" {
					continue
				}
				m := s.modules[e.Span.File]
				if m == nil {
					continue
				}
				if input, _ := nativeHashHex(m, parse.NodeAt(m.tree.RootNode(), e.Span.StartByte, e.Span.EndByte)); input != nil {
					hex = true
				}
			}
			allHex = allHex && hex
		}
		if allHex && count > 0 {
			c.Evidence["sql_all_inputs_hex"] = []analysis.Evidence{use.Sink}
		}
	}
	if use.Kind != "nosql_query_candidate" {
		return
	}
	// A modeled conditional records its test as the arm precondition instead of the
	// whole statement; an unmodeled one keeps the statement.
	tests := append([]analysis.Evidence{}, c.Evidence["control_statement"]...)
	// An arm precondition is a witness only with the polarity that excludes a
	// non-string on this path: a false `!==` test or a true `===` test.
	for _, e := range c.Evidence[branchTruePrecondition] {
		if typeofPolarity(e.Text) == "equal" {
			tests = append(tests, e)
		}
	}
	for _, e := range c.Evidence[branchFalsePrecondition] {
		if typeofPolarity(e.Text) == "not_equal" {
			tests = append(tests, e)
		}
	}
	for _, e := range tests {
		if e.Span.File != use.Sink.Span.File || e.Span.StartByte >= use.Sink.Span.StartByte || !strings.Contains(e.Text, "typeof") {
			continue
		}
		for _, d := range use.Dependencies {
			if strings.Contains(e.Text, d.Source.Text) {
				c.Evidence["selector_type_guard"] = append(c.Evidence["selector_type_guard"], e)
				break
			}
		}
	}
}

// typeofPolarity classifies a single `typeof x === 'string'` style test by its
// comparison; a negated, compound or non-string test is "".
func typeofPolarity(text string) string {
	t := strings.Join(strings.Fields(strings.Trim(strings.TrimSpace(text), "()")), "")
	if strings.ContainsAny(t, "&|!(") && !strings.Contains(t, "!=") || strings.Count(t, "typeof") != 1 || !strings.HasPrefix(t, "typeof") ||
		!(strings.HasSuffix(t, "'string'") || strings.HasSuffix(t, `"string"`)) || strings.Contains(t, "&&") || strings.Contains(t, "||") {
		return ""
	}
	switch {
	case strings.Contains(t, "!==") || strings.Contains(t, "!="):
		return "not_equal"
	case strings.Contains(t, "===") || strings.Contains(t, "=="):
		return "equal"
	}
	return ""
}
