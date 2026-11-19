package analysispacks

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/zazzcode/zazzles/internal/analysis"
)

// GuardContract is the source-backed semantics of one recognised guard on a
// record: which values it accepts, including the edge cases a model must weigh
// to decide whether an accepted value can still alter the protected operation.
// It states what the guard accepts, never whether that is adequate.
type GuardContract struct {
	Guard   string `json:"guard"`
	At      string `json:"at"`
	Text    string `json:"text"`
	Accepts string `json:"accepts"`
}

// guardSemantics are the recognised guards and what each accepts. Semantics
// follow the language references (PHP manual is_numeric/ctype_digit/in_array/
// PCRE anchors, Python re, ECMAScript RegExp), reviewed 2026-11-19.
var guardSemantics = []struct {
	name    string
	pattern *regexp.Regexp
	accepts string
}{
	{"is_numeric", regexp.MustCompile(`\bis_numeric\s*\(`),
		"PHP is_numeric(v) is true for a numeric string: optional leading whitespace, an optional sign, decimal digits with an optional decimal point and an optional exponent (for example '12', '-1.5', '.5', '1e5', ' 7'), and since PHP 8.0 optional trailing whitespace (space, \\t, \\n, \\r, \\v, \\f). Hex, binary and any other character make it false. It checks only the value passed to it; a value assembled later from checked parts is the concatenation of accepted strings plus whatever joins them."},
	{"ctype_digit", regexp.MustCompile(`\bctype_digit\s*\(`),
		"PHP ctype_digit(v) is true only for a non-empty string of the ASCII digits 0-9; whitespace, signs, points and other characters make it false. An int argument is read as an ASCII code (deprecated since PHP 8.1)."},
	{"integer_cast", regexp.MustCompile(`\(int\)|\(integer\)|\bintval\s*\(|\bint\s*\(|\bparseInt\s*\(|\bNumber\s*\(|\babsint\s*\(`),
		"An integer cast or conversion (PHP (int)/intval, Python int(), JavaScript parseInt/Number) yields a number whose decimal text is digits with an optional leading minus (Number can also yield NaN, Infinity, a decimal point or an exponent). The original string is not changed; only the converted value is constrained."},
	{"anchored_regex", regexp.MustCompile(`\bpreg_match\s*\(\s*['"]([^\w\s\\]).*?\^.*?\$.*?['"]|\bre\.(fullmatch|match)\s*\(|/\^[^/]*\$/[a-z]*\s*\.\s*test\s*\(`),
		"A regular expression anchored at both ends accepts only strings its pattern matches as a whole. Edge cases: in PCRE (preg_match) and Python re, $ also matches before a final newline unless the D modifier is set (PCRE) or fullmatch/\\Z is used (Python); a multiline m flag makes ^ and $ match at line breaks; JavaScript $ without the m flag matches only at the end. The accepted set is exactly the pattern's language under those rules."},
	{"regex_match", regexp.MustCompile(`\.match\s*\(|\.test\s*\(|\bpreg_match\s*\(|\bre\.(search|match)\s*\(|\.search\s*\(`),
		"A regular-expression match that is not anchored at both ends accepts every string that contains a match of the pattern somewhere (Python re.match anchors only at the start); characters before or after the matched part, including shell syntax, are not checked. A capture group taken from the match holds only what the group's own sub-pattern allows."},
	{"allow_list", regexp.MustCompile(`\bin_array\s*\(|\.includes\s*\(|\bin\s*[\[\(\{]|\bin\s+\w*(ALLOW|allow|VALID|valid|PERMIT|permit)`),
		"Allow-list membership accepts only values equal to a listed member. PHP in_array without strict=true compares loosely (since PHP 8.0 a numeric string compares numerically, so '1.0' equals 1); Python 'in' on a literal tuple/list/set and JavaScript Array.prototype.includes compare exactly (includes uses SameValueZero). The accepted set is the listed literals under that comparison."},
}

// guardEvidenceKinds are the context roles that carry a dominating or
// enclosing control on a command path.
var guardEvidenceKinds = map[string]bool{"branch_precondition": true, "branch_true_precondition": true, "branch_false_precondition": true, "guard": true, "control": true, "control_statement": true, "path_guard": true}

// GuardContracts returns the contract of every recognised guard on a record's
// controls: the branch preconditions and guard evidence in its context and the
// controls its guarded command paths name. Unrecognised controls have no
// contract; their adequacy stays unknown.
func GuardContracts(use analysis.CandidateUse) []GuardContract {
	candidates := map[int]bool{}
	for i, e := range use.Context {
		if guardEvidenceKinds[e.Kind] {
			candidates[i] = true
		}
	}
	if use.Command != nil {
		for _, p := range use.Command.Paths {
			for _, c := range p.Controls {
				if c >= 0 && c < len(use.Context) {
					candidates[c] = true
				}
			}
		}
	}
	var indexes []int
	for i := range candidates {
		indexes = append(indexes, i)
	}
	sort.Ints(indexes)
	seen := map[string]bool{}
	var out []GuardContract
	for _, i := range indexes {
		e := use.Context[i]
		for _, g := range guardSemantics {
			if !g.pattern.MatchString(e.Text) {
				continue
			}
			at := fmt.Sprintf("%s:%d", e.Span.File, e.Span.StartLine)
			if seen[g.name+"|"+at] || g.name == "regex_match" && seen["anchored_regex|"+at] {
				continue
			}
			seen[g.name+"|"+at] = true
			out = append(out, GuardContract{Guard: g.name, At: at, Text: compactGuardText(e.Text), Accepts: g.accepts})
		}
	}
	return out
}

// GuardContractMember returns the recognised guard on the record whose
// contract describes symbol's final member (for example "item.match" under
// regex_match), or "" when no contract on the record describes it.
func GuardContractMember(use analysis.CandidateUse, symbol string) string {
	member := symbol[strings.LastIndex(symbol, ".")+1:]
	if member == "" {
		return ""
	}
	call := member + "("
	if strings.Contains(symbol, ".") {
		call = "." + call
	}
	for _, c := range GuardContracts(use) {
		for _, g := range guardSemantics {
			if g.name == c.Guard && g.pattern.MatchString(call) {
				return c.Guard
			}
		}
	}
	return ""
}

// GuardedCommandPath reports a request-derived command path whose protection
// is a control the assessment must judge.
func GuardedCommandPath(f *analysis.CommandFacts) bool {
	if f == nil {
		return false
	}
	for _, p := range f.Paths {
		if p.Protection == "guarded" {
			return true
		}
	}
	return false
}

// GuardContractText renders a record's guard contracts for the bypass question.
func GuardContractText(use analysis.CandidateUse) string {
	contracts := GuardContracts(use)
	if len(contracts) == 0 {
		return " No recognised guard contract is supplied for this record: answer guard_semantics_unknown unless no request-derived path is guarded (not_applicable)."
	}
	var parts []string
	for _, c := range contracts {
		parts = append(parts, fmt.Sprintf("%s at %s (%s): %s", c.Guard, c.At, c.Text, c.Accepts))
	}
	return " Recognised guard contracts on this record: " + strings.Join(parts, " | ")
}

func compactGuardText(text string) string {
	text = strings.Join(strings.Fields(text), " ")
	if len(text) > 160 {
		text = text[:160] + "…"
	}
	return text
}
