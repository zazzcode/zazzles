package judge

import (
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
)

// separatorCapturePHP guards the shell operand with a capture whose listed
// alphabet holds a command separator and letters: an accepted value can add
// a command of the request's choosing.
const separatorCapturePHP = `<?php
$host = $_REQUEST['host'];
if( preg_match( '/^([a-z0-9.; -]+)$/', $host, $m ) ) {
	$cmd = shell_exec( 'ping -c 4 ' . $m[1] );
	echo $cmd;
}
`

// hostCapturePHP guards the same operand with a capture whose listed alphabet
// holds no shell operator, substitution or redirection character.
const hostCapturePHP = `<?php
$host = $_REQUEST['host'];
if( preg_match( '/^([a-z0-9.-]+)$/', $host, $m ) ) {
	$cmd = shell_exec( 'ping -c 4 ' . $m[1] );
	echo $cmd;
}
`

// mixedGuardsPHP puts two guarded paths on one shell operand: a numeric
// check on count and a separator-admitting capture on host.
const mixedGuardsPHP = `<?php
$host = $_REQUEST['host'];
$count = $_REQUEST['count'];
if( is_numeric( $count ) && preg_match( '/^([a-z0-9.; -]+)$/', $host, $m ) ) {
	$cmd = shell_exec( 'ping -c ' . $count . ' ' . $m[1] );
	echo $cmd;
}
`

func bypassAnswers(shell, bypass, coverage string) commandAnswers {
	return commandAnswers{"shell_syntax_protection": shell, "executable_control": "not_applicable", "argument_control": "not_applicable", "guard_bypass": bypass, "protection_coverage": coverage}
}

func impliedResolution(a analysis.Assessment) *analysis.Resolution {
	for i := range a.Resolutions {
		if len(a.Resolutions[i].Citation) == 1 && a.Resolutions[i].Citation[0] == ImpliedSinglePath {
			return &a.Resolutions[i]
		}
	}
	return nil
}

// TestCommandBypassNeedsSupportedConsequence freezes the three source-reviewed
// expectations for a bypass answer on one guarded shell path. The scanner
// binds the path; the consequence the answer asserts must also be possible
// under the accepted characters the scanner itself lists for that path.
func TestCommandBypassNeedsSupportedConsequence(t *testing.T) {
	separator := guardedCommandUse(t, map[string]string{"index.php": separatorCapturePHP})
	host := guardedCommandUse(t, map[string]string{"index.php": hostCapturePHP})
	numeric := guardedCommandUse(t, map[string]string{"index.php": numericGuardPHP})
	opaque := numeric
	opaque.Context = append([]analysis.Evidence(nil), numeric.Context...)
	for i, e := range opaque.Context {
		if strings.Contains(e.Text, "is_numeric") {
			opaque.Context[i].Text = "valid_octets( $octet )"
		}
	}
	opaque.Command = cloneCommand(numeric.Command)
	for i := range opaque.Command.Paths {
		opaque.Command.Paths[i].Class = ""
	}
	for _, tt := range []struct {
		name    string
		use     analysis.CandidateUse
		answers commandAnswers
		status  string
		blocker string
		implied bool
	}{
		{"supported positive: the listed alphabet carries a separator and a command name", separator, bypassAnswers("vulnerable", "bypass_identified", "incomplete"), "confirmed_vulnerability", "", true},
		{"protected control: numeric octets cannot carry command text", numeric, bypassAnswers("vulnerable", "bypass_identified", "incomplete"), "needs_evidence", "command_bypass_unsupported", false},
		{"protected control: a hostname alphabet cannot carry command text", host, bypassAnswers("vulnerable", "bypass_identified", "incomplete"), "needs_evidence", "command_bypass_unsupported", false},
		{"protected control stays protected only on its own answers", numeric, bypassAnswers("protected", "no_bypass", "complete"), "protected_for_claim", "", false},
		{"insufficient evidence: a guard with no contract", opaque, bypassAnswers("vulnerable", "bypass_identified", "incomplete"), "needs_evidence", "command_guard_semantics_unknown", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			a := analysis.Assessment{Status: "completed", QuestionVersion: analysispacks.CommandProtocol, Answers: tt.answers}
			applyCommandPolicy(tt.use, &a)
			if a.FindingStatus != tt.status || tt.blocker != "" && !hasGapKind(a.BlockingGaps, tt.blocker) {
				t.Fatalf("status %s blockers %+v reason %q", a.FindingStatus, a.BlockingGaps, a.Reason)
			}
			if got := impliedResolution(a); (got != nil) != tt.implied {
				t.Fatalf("implied resolution %+v, want %v", got, tt.implied)
			}
			if tt.blocker == "command_bypass_unsupported" && a.ModelResolved() {
				t.Fatal("an unsupported bypass discharges nothing")
			}
		})
	}
}

// TestCommandBypassCitationOfLimitedSibling: with two guarded paths, a
// verified citation confirms only when the cited path itself can carry the
// bypass. The numeric sibling's chain is a valid citation of location and
// order, never of the consequence.
func TestCommandBypassCitationOfLimitedSibling(t *testing.T) {
	mixed := guardedCommandUse(t, map[string]string{"index.php": mixedGuardsPHP})
	numericDep, captureDep := -1, -1
	for _, p := range mixed.Command.Paths {
		if p.Protection != "guarded" {
			t.Fatalf("fixture wants two guarded paths, got %+v", mixed.Command.Paths)
		}
		if p.Class == analysis.CommandValueNumericString {
			numericDep = p.Dependency
		} else {
			captureDep = p.Dependency
		}
	}
	if len(mixed.Command.Paths) != 2 || numericDep < 0 || captureDep < 0 {
		t.Fatalf("fixture wants one numeric and one capture path, got %+v", mixed.Command.Paths)
	}
	cite := func(dep int) []analysis.Resolution {
		return []analysis.Resolution{{Question: resolvePrefix + "bypass", QuestionVersion: BypassQuestionVersion, Answer: "bypass_identified", Citation: []string{"e0", "e1"}, Verified: true, Dependency: &dep}}
	}
	for _, tt := range []struct {
		name    string
		dep     int
		status  string
		blocker string
	}{
		{"citing the capture path stands", captureDep, "confirmed_vulnerability", ""},
		{"citing the numeric sibling stays Review", numericDep, "needs_evidence", "command_bypass_unsupported"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			a := analysis.Assessment{Status: "completed", QuestionVersion: analysispacks.CommandProtocol, Answers: bypassAnswers("vulnerable", "bypass_identified", "incomplete"), Resolutions: cite(tt.dep)}
			applyCommandPolicy(mixed, &a)
			if a.FindingStatus != tt.status || tt.blocker != "" && !hasGapKind(a.BlockingGaps, tt.blocker) {
				t.Fatalf("status %s blockers %+v reason %q", a.FindingStatus, a.BlockingGaps, a.Reason)
			}
			if a.ModelResolved() != (tt.status == "confirmed_vulnerability") {
				t.Fatalf("model-resolved %v for status %s", a.ModelResolved(), a.FindingStatus)
			}
		})
	}
}

func cloneCommand(f *analysis.CommandFacts) *analysis.CommandFacts {
	c := *f
	c.Paths = append([]analysis.CommandPath(nil), f.Paths...)
	return &c
}

const digitsRejectPHP = `<?php
$count = $_GET['count'];
if( !ctype_digit( $count ) ) {
	die( 'bad count' );
}
echo shell_exec( 'ping -c ' . $count . ' 127.0.0.1' );
`

const intvalPHP = `<?php
$count = intval( $_GET['count'] );
echo shell_exec( 'ping -c ' . $count . ' 127.0.0.1' );
`

const hashPHP = `<?php
$name = md5( $_GET['name'], true );
echo shell_exec( 'ls /tmp/' . $name );
`

// TestPHPNumericPathStatesItsCheck: a PHP path guarded by a numeric check or
// conversion cites that check, not the operand it guards, and its reason
// lists the characters that check leaves. A value the adapter cannot list (a
// hash) keeps no class, so its adequacy stays the assessment's call.
func TestPHPNumericPathStatesItsCheck(t *testing.T) {
	for _, tt := range []struct {
		name, source, class, controlKind, controlText, reason, contract string
		limited                                                         bool
	}{
		{"is_numeric condition", numericGuardPHP, analysis.CommandValueNumericString, "branch_precondition", "is_numeric( $octet[0] )", "passed PHP is_numeric: the value holds only digits, a sign, a decimal point, an exponent marker and leading or trailing whitespace, including a line break.", "is_numeric", true},
		{"ctype_digit rejecting branch", digitsRejectPHP, analysis.CommandValueDigits, "branch_false_precondition", "ctype_digit( $count )", "passed PHP ctype_digit: the value holds only the digits 0-9. They hold no character the shell reads as syntax.", "ctype_digit", true},
		{"intval conversion", intvalPHP, analysis.CommandValueNumber, "numeric_conversion", "intval( $_GET['count'] )", "converted to a number: the value holds only the text of a number", "integer_cast", true},
		{"hash output is not listed", hashPHP, "", "command_operand", "'ls /tmp/' . $name", "numeric or non-content value cannot carry shell syntax", "", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			use := guardedCommandUse(t, map[string]string{"index.php": tt.source})
			if len(use.Command.Paths) != 1 || len(use.Command.Paths[0].Controls) != 1 {
				t.Fatalf("want one path citing one control, got %+v", use.Command.Paths)
			}
			p := use.Command.Paths[0]
			control := use.Context[p.Controls[0]]
			if p.Class != tt.class || control.Kind != tt.controlKind || !strings.Contains(control.Text, tt.controlText) || !strings.HasPrefix(p.Reason, tt.reason) {
				t.Fatalf("class %q control %s %q reason %q", p.Class, control.Kind, control.Text, p.Reason)
			}
			seen := 0
			for _, e := range use.Context {
				if e == control {
					seen++
				}
			}
			if seen != 1 {
				t.Fatalf("the cited control appears %d times in the record's context", seen)
			}
			found := tt.contract == ""
			for _, c := range analysispacks.GuardContracts(use) {
				found = found || c.Guard == tt.contract
			}
			if _, limited := analysispacks.ShellBypassLimit(use, p.Dependency); !found || limited != tt.limited {
				t.Fatalf("contract %q supplied %v, limited %v", tt.contract, found, limited)
			}
		})
	}
}

// TestProtectedCommandKeepsItsResidue: a record protected for the claim still
// states what its listed guard lets through, so a line break is not read as a
// clean guard; a guard that lets nothing through adds no note.
func TestProtectedCommandKeepsItsResidue(t *testing.T) {
	for _, tt := range []struct {
		name, source, note string
	}{
		{"is_numeric still admits a line break", numericGuardPHP, "Hardening: a value that passed PHP is_numeric at index.php:5 still holds"},
		{"ctype_digit admits nothing", digitsRejectPHP, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			use := guardedCommandUse(t, map[string]string{"index.php": tt.source})
			a := analysis.Assessment{Status: "completed", QuestionVersion: analysispacks.CommandProtocol, Answers: bypassAnswers("protected", "no_bypass", "complete")}
			applyCommandPolicy(use, &a)
			if a.FindingStatus != "protected_for_claim" || strings.Contains(a.Reason, "Hardening:") != (tt.note != "") || !strings.Contains(a.Reason, tt.note) {
				t.Fatalf("status %s reason %q", a.FindingStatus, a.Reason)
			}
		})
	}
}
