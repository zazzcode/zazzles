package analysispacks

import (
	"fmt"
	"strings"

	"github.com/zazzcode/zazzles/internal/analysis"
)

// numericClasses lists, for each class of numeric value a PHP adapter path
// can carry, every character the value can hold. The sets were checked
// against PHP 8.6: is_numeric accepts exactly these bytes, and a converted
// number's text has no whitespace.
var numericClasses = map[string]struct{ chars, listing string }{
	analysis.CommandValueNumericString: {"0123456789+-.eE \t\n\r\v\f", "digits, a sign, a decimal point, an exponent marker and leading or trailing whitespace, including a line break"},
	analysis.CommandValueDigits:        {"0123456789", "the digits 0-9"},
	analysis.CommandValueNumber:        {"0123456789+-.EINFA", "the text of a number: digits, a sign, a decimal point and an exponent marker, or INF or NAN"},
}

// acceptedText is the complete set of characters a guarded value can hold,
// stated by the scanner from its own facts.
type acceptedText struct {
	what    string
	listing string
	chars   map[rune]bool
	// numeric values are numeric tokens: their letters are an exponent
	// marker or the fixed words INF and NAN, never a name.
	numeric bool
}

func (a acceptedText) has(chars string) bool {
	for _, r := range chars {
		if a.chars[r] {
			return true
		}
	}
	return false
}

// carriesCommandText reports whether some accepted value can add command text
// of the request's choosing to an unquoted POSIX shell line: a redirection,
// or an operator or substitution together with the letters to name a command.
// A separator alone starts a command whose words are drawn from the same
// characters: the request chooses among names that already exist, not text.
func (a acceptedText) carriesCommandText() bool {
	names := false
	if !a.numeric {
		for r := range a.chars {
			names = names || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z'
		}
	}
	substitution := a.chars['`'] || a.chars['$'] && a.chars['('] && a.chars[')']
	return a.has("<>") || (a.has(";&|\n") || substitution) && names
}

// reach states what the accepted characters can still do to the shell line.
func (a acceptedText) reach() string {
	var can []string
	if a.has("\n") {
		can = append(can, "a line break")
	}
	if a.has(";&|") {
		can = append(can, "a command separator")
	}
	if a.has(" \t") {
		can = append(can, "a word break")
	}
	if a.chars['-'] {
		can = append(can, "a leading '-'")
	}
	if len(can) == 0 {
		return "They hold no character the shell reads as syntax."
	}
	out := "They can add " + strings.Join(can, ", ") + ", and nothing else the shell reads as syntax."
	if a.has(";&|\n") {
		// Checked with sh: `ping 1⏎. 2.3.4` runs the '.' builtin on 2.3.4.
		out += " A second command built from them can only run a program"
		if a.chars['.'] && a.has(" \t") {
			out += ", or the shell's '.' builtin on a file,"
		}
		out += " whose name is made of the same characters, if one exists."
	}
	return out
}

// NumericPathReason words, for the decision model, what a guarded path of a
// numeric class can hold and what that can do to a shell line. The policy
// check reads the same listing.
func NumericPathReason(class string) string {
	a, ok := numericText(class)
	if !ok {
		return "the value passed a numeric check or conversion; the scanner does not list its characters"
	}
	return a.what + ": the value holds only " + a.listing + ". " + a.reach() + " No accepted value names a command, starts a substitution or redirects."
}

func numericText(class string) (acceptedText, bool) {
	c, ok := numericClasses[class]
	if !ok {
		return acceptedText{}, false
	}
	a := acceptedText{listing: c.listing, chars: map[rune]bool{}, numeric: true}
	switch class {
	case analysis.CommandValueNumericString:
		a.what = "passed PHP is_numeric"
	case analysis.CommandValueDigits:
		a.what = "passed PHP ctype_digit"
	default:
		a.what = "converted to a number"
	}
	for _, r := range c.chars {
		a.chars[r] = true
	}
	return a, true
}

// guardedPathText returns the accepted characters of the guarded shell path
// of dependency dep when the scanner can list them completely: the adapter
// classified the value's numeric text, or the operand is a
// regular-expression capture with an explicit alphabet. Any other guard is
// not listed.
func guardedPathText(use analysis.CandidateUse, dep int) (acceptedText, bool) {
	if use.Command == nil || dep < 0 || dep >= len(use.Dependencies) {
		return acceptedText{}, false
	}
	for _, p := range use.Command.Paths {
		if p.Dependency != dep || p.Protection != "guarded" {
			continue
		}
		a, ok := numericText(p.Class)
		if !ok {
			continue
		}
		a.what = "a value that " + a.what
		for _, c := range p.Controls {
			if c >= 0 && c < len(use.Context) {
				a.what += fmt.Sprintf(" at %s:%d", use.Context[c].Span.File, use.Context[c].Span.StartLine)
				break
			}
		}
		return a, true
	}
	a := acceptedText{chars: map[rune]bool{}}
	for _, x := range use.Dependencies[dep].Transforms {
		if x.Kind != "regex_capture" {
			continue
		}
		class, set := classifyCapture(x.SubPattern, x.Flavor, x.Flags)
		if class.Class != CaptureExplicitAlphabet || set == nil {
			return acceptedText{}, false
		}
		for r := range set {
			a.chars[r] = true
		}
		if a.what == "" {
			a.what = fmt.Sprintf("capture group %d of %s at %s:%d", x.Group, compactGuardText(x.Pattern), x.At.File, x.At.StartLine)
		}
	}
	a.listing = formatAlphabet(a.chars)
	return a, a.what != ""
}

// ShellBypassLimit reports that a bypass of the guarded shell path of
// dependency dep is not supported by the scanner's own facts: the path's
// value holds only characters the scanner lists, and no value over them adds
// command text of the request's choosing. The detail names the guard and what
// the characters can still do. It returns false when the characters can carry
// command text or the scanner cannot list them; adequacy then stays the
// assessment's call.
func ShellBypassLimit(use analysis.CandidateUse, dep int) (string, bool) {
	a, ok := guardedPathText(use, dep)
	if !ok || a.carriesCommandText() {
		return "", false
	}
	return "A bypass was identified on a path limited to " + a.what + ", which holds only " + a.listing + ". " + a.reach() + " No accepted value names a command, starts a substitution or redirects, so a bypass that adds command text of the request's choosing is not established.", true
}

// ShellPathResidue reports what the guarded shell paths of a record can still
// add to the command where the scanner lists their characters: a line break
// or separator a protected record should still close. It is empty when no
// listed path can break the command.
func ShellPathResidue(use analysis.CandidateUse) string {
	if use.Command == nil {
		return ""
	}
	for _, p := range use.Command.Paths {
		if p.Protection != "guarded" || p.Operand != analysis.CommandSlotShell {
			continue
		}
		if a, ok := guardedPathText(use, p.Dependency); ok && !a.carriesCommandText() && a.has(";&|\n") {
			return "Hardening: " + a.what + " still holds " + a.listing + ". " + a.reach()
		}
	}
	return ""
}
