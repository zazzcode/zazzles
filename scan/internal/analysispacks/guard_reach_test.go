package analysispacks

import (
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

func captureUse(sub, flavor string) analysis.CandidateUse {
	return analysis.CandidateUse{
		Dependencies: []analysis.Dependency{{Transforms: []analysis.ValueTransform{{Kind: "regex_capture", At: analysis.Span{File: "a.php", StartLine: 3}, Flavor: flavor, Pattern: "^(" + sub + ")$", Group: 1, SubPattern: sub, Class: ClassifyCapture(sub, flavor, "").Class}}}},
		Command:      &analysis.CommandFacts{Paths: []analysis.CommandPath{{Dependency: 0, Operand: analysis.CommandSlotShell, Protection: "guarded"}}},
	}
}

// TestShellBypassLimit: a bypass is unsupported only when the scanner lists
// every character the guarded value can hold and none of them lets a value
// add command text of the request's choosing.
func TestShellBypassLimit(t *testing.T) {
	classed := func(protection, class string) analysis.CandidateUse {
		return analysis.CandidateUse{
			Dependencies: []analysis.Dependency{{}},
			Context:      []analysis.Evidence{{Kind: "branch_precondition", Text: "is_numeric( $octet[0] )", Span: analysis.Span{File: "a.php", StartLine: 15}}},
			Command:      &analysis.CommandFacts{Paths: []analysis.CommandPath{{Dependency: 0, Operand: analysis.CommandSlotShell, Protection: protection, Controls: []int{0}, Class: class}}},
		}
	}
	numeric := classed("guarded", analysis.CommandValueNumericString)
	unclassified := classed("guarded", "")
	raw := classed("raw", analysis.CommandValueNumericString)
	for _, tt := range []struct {
		name    string
		use     analysis.CandidateUse
		limited bool
		detail  string
	}{
		{"a numeric string adds only breaks and a sign", numeric, true, "passed PHP is_numeric at a.php:15"},
		{"a numeric string's line break reaches the dot builtin", numeric, true, "or the shell's '.' builtin on a file, whose name is made of the same characters"},
		{"digits hold no shell syntax", classed("guarded", analysis.CommandValueDigits), true, "passed PHP ctype_digit at a.php:15, which holds only the digits 0-9. They hold no character the shell reads as syntax."},
		{"a converted number has no whitespace", classed("guarded", analysis.CommandValueNumber), true, "They can add a leading '-', and nothing else"},
		{"a hostname alphabet adds only a leading hyphen", captureUse(`[a-z0-9.-]+`, FlavorPCRE), true, "They can add a leading '-', and nothing else"},
		{"a word alphabet holds no shell syntax", captureUse(`[a-z0-9.]+`, FlavorPCRE), true, "They hold no character the shell reads as syntax"},
		{"a separator without letters names no command", captureUse(`[0-9;]+`, FlavorPCRE), true, "A second command built from them can only run a program whose name is made of the same characters, if one exists."},
		{"letters without a separator add no command", captureUse(`[a-z ]+`, FlavorPCRE), true, "a word break"},
		{"a variable marker alone substitutes no command", captureUse(`[a-zA-Z$]+`, FlavorPCRE), true, ""},
		{"a separator with letters carries a command", captureUse(`[a-z;]+`, FlavorPCRE), false, ""},
		{"a line break with letters carries a command", captureUse(`[a-z\n]+`, FlavorPCRE), false, ""},
		{"a backtick with letters carries a substitution", captureUse("[a-z`]+", FlavorPCRE), false, ""},
		{"a redirection carries by itself", captureUse(`[0-9>]+`, FlavorPCRE), false, ""},
		{"an unlisted capture is the assessment's call", captureUse(`(?!file:)http[^\s]*`, FlavorECMAScript), false, ""},
		{"a capture that admits any character is not limited", captureUse(`http.*`, FlavorECMAScript), false, ""},
		{"Python Unicode shorthand is not a complete listing", captureUse(`\d+`, FlavorPython), false, ""},
		{"a guarded path the adapter did not classify is not limited", unclassified, false, ""},
		{"a raw path is never limited", raw, false, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			detail, limited := ShellBypassLimit(tt.use, 0)
			if limited != tt.limited || !strings.Contains(detail, tt.detail) {
				t.Fatalf("limited %v detail %q", limited, detail)
			}
		})
	}
	if _, limited := ShellBypassLimit(numeric, 3); limited {
		t.Fatal("an unknown dependency is never limited")
	}
}

// TestShellPathResidue: a guarded shell path whose listed characters still
// break the command is named for a protected record; a path that cannot
// break it, or that the scanner cannot list, adds nothing.
func TestShellPathResidue(t *testing.T) {
	path := func(class string) analysis.CandidateUse {
		return analysis.CandidateUse{
			Dependencies: []analysis.Dependency{{}},
			Command:      &analysis.CommandFacts{Paths: []analysis.CommandPath{{Dependency: 0, Operand: analysis.CommandSlotShell, Protection: "guarded", Class: class}}},
		}
	}
	if got := ShellPathResidue(path(analysis.CommandValueNumericString)); !strings.Contains(got, "Hardening: a value that passed PHP is_numeric still holds") || !strings.Contains(got, "a line break") {
		t.Fatalf("numeric string residue %q", got)
	}
	for _, class := range []string{analysis.CommandValueDigits, analysis.CommandValueNumber, ""} {
		if got := ShellPathResidue(path(class)); got != "" {
			t.Fatalf("class %q residue %q", class, got)
		}
	}
	if got := ShellPathResidue(captureUse(`[a-z;]+`, FlavorPCRE)); got != "" {
		t.Fatalf("a path that carries command text is a finding's matter, not hardening: %q", got)
	}
}
