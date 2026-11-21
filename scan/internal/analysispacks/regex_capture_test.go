package analysispacks

import (
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

// TestRegexCaptureClass (close-findings-gaps AC2, D-5) classifies a capture
// group's sub-pattern by what it can accept.
func TestRegexCaptureClass(t *testing.T) {
	for _, tt := range []struct {
		name, pattern, flavor, flags string
		group                        int
		sub, class, alphabet         string
	}{
		{"dot after a literal admits any", `\!\[alt text\]\((http.*)\s\".*`, FlavorECMAScript, "", 1, "http.*", CaptureAdmitsAny, ""},
		{"explicit host alphabet", `^host:([a-z0-9.-]+)$`, FlavorECMAScript, "", 1, "[a-z0-9.-]+", CaptureExplicitAlphabet, "-.0-9a-z"},
		{"lookbehind is unknown", `^x((?<=x)\w+)$`, FlavorECMAScript, "", 1, `(?<=x)\w+`, CaptureUnknown, ""},
		{"non-whitespace admits any", `^(\S+)$`, FlavorPCRE, "", 1, `\S+`, CaptureAdmitsAny, ""},
		{"non-word admits any", `(\W)`, FlavorPCRE, "", 1, `\W`, CaptureAdmitsAny, ""},
		{"non-digit admits any", `(\D+)`, FlavorPython, "", 1, `\D+`, CaptureAdmitsAny, ""},
		{"negated quote class admits any", `id="([^"]*)"`, FlavorPCRE, "", 1, `[^"]*`, CaptureAdmitsAny, ""},
		{"negated class excluding a separator is unknown", `([^;|&]+)`, FlavorPCRE, "", 1, `[^;|&]+`, CaptureUnknown, ""},
		{"ECMAScript digits", `^(\d+)$`, FlavorECMAScript, "", 1, `\d+`, CaptureExplicitAlphabet, "0-9"},
		{"Python str digits are Unicode", `^(\d+)$`, FlavorPython, "", 1, `\d+`, CaptureExplicitAlphabet, `0-9 and other Unicode decimal digits`},
		{"word class", `(\w+)`, FlavorPCRE, "", 1, `\w+`, CaptureExplicitAlphabet, "0-9A-Z_a-z"},
		{"case-insensitive flag widens the alphabet", `^([a-c]+)$`, FlavorECMAScript, "i", 1, "[a-c]+", CaptureExplicitAlphabet, "A-Ca-c"},
		{"alternation of literals", `^(get|put)$`, FlavorPCRE, "", 1, "get|put", CaptureExplicitAlphabet, "egptu"},
		{"second group after a non-capturing group", `(?:a)(b)(c+)`, FlavorPCRE, "", 2, "c+", CaptureExplicitAlphabet, "c"},
		{"Python named group", `(?P<host>[a-z]+)`, FlavorPython, "", 1, "[a-z]+", CaptureExplicitAlphabet, "a-z"},
		{"ECMAScript named group", `(?<host>[a-z]+)`, FlavorECMAScript, "", 1, "[a-z]+", CaptureExplicitAlphabet, "a-z"},
		{"backreference is unknown", `(a)(\1)`, FlavorPCRE, "", 2, `\1`, CaptureUnknown, ""},
		{"escaped parenthesis is not a group", `\((\d)\)`, FlavorPCRE, "", 1, `\d`, CaptureExplicitAlphabet, "0-9"},
		{"class with non-space admits any", `([\s\S]*)`, FlavorECMAScript, "", 1, `[\s\S]*`, CaptureAdmitsAny, ""},
		{"verbose flag is unsupported", `(a b)`, FlavorPython, "x", 1, "a b", CaptureUnknown, ""},
		{"inline flag is unsupported", `((?i)ab)`, FlavorPCRE, "", 1, "(?i)ab", CaptureUnknown, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			sub, ok := CaptureSubPattern(tt.pattern, tt.group)
			if !ok || sub != tt.sub {
				t.Fatalf("sub-pattern %q %v, want %q", sub, ok, tt.sub)
			}
			got := ClassifyCapture(sub, tt.flavor, tt.flags)
			if got.Class != tt.class || got.Alphabet != tt.alphabet {
				t.Fatalf("class %+v, want %s %q", got, tt.class, tt.alphabet)
			}
		})
	}
	if _, ok := CaptureSubPattern(`(a)`, 2); ok {
		t.Fatal("a missing group has no sub-pattern")
	}
	for _, tt := range []struct{ literal, pattern, flags string }{
		{`'/^img:(http.*)$/'`, `^img:(http.*)$`, ""},
		{`"#^(\d+)$#i"`, `^(\d+)$`, "i"},
		{`'{^([a-z]+)$}x'`, `^([a-z]+)$`, "x"},
	} {
		p, f, ok := PHPRegexLiteral(tt.literal)
		if !ok || p != tt.pattern || f != tt.flags {
			t.Fatalf("PHP literal %s: %q %q %v", tt.literal, p, f, ok)
		}
	}
}

// TestCaptureContractText (D-6): a guarded path that reads a classified
// capture carries the classification in its guard contract text.
func TestCaptureContractText(t *testing.T) {
	use := func(class, alphabet string) analysis.CandidateUse {
		return analysis.CandidateUse{Kind: "command_execution_candidate",
			Dependencies: []analysis.Dependency{{Transforms: []analysis.ValueTransform{{Kind: "regex_capture", At: analysis.Span{File: "a.js", StartLine: 7}, Flavor: FlavorECMAScript, Pattern: "^host:([a-z0-9.-]+)$", Group: 1, SubPattern: "[a-z0-9.-]+", Class: class, Alphabet: alphabet}}}},
			Command:      &analysis.CommandFacts{Paths: []analysis.CommandPath{{Dependency: 0, Operand: analysis.CommandSlotShell, Protection: "guarded"}}}}
	}
	text := GuardContractText(use(CaptureExplicitAlphabet, "-.0-9a-z"))
	if !strings.Contains(text, "regex_capture at a.js:7") || !strings.Contains(text, "only these characters: -.0-9a-z") {
		t.Fatalf("explicit alphabet contract: %q", text)
	}
	if text := GuardContractText(use(CaptureUnknown, "")); !strings.Contains(text, "could not list") {
		t.Fatalf("unknown capture contract: %q", text)
	}
	raw := use(CaptureAdmitsAny, "")
	raw.Command.Paths[0].Protection = "raw"
	if c := GuardContracts(raw); len(c) != 0 {
		t.Fatalf("a raw path has no capture contract: %+v", c)
	}
}
