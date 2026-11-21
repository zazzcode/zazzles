package analysispacks

import (
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

func TestCommandGuardContract(t *testing.T) {
	guarded := func(text string) analysis.CandidateUse {
		return analysis.CandidateUse{Kind: "command_execution_candidate",
			Context: []analysis.Evidence{{Kind: "branch_precondition", Text: text, Span: analysis.Span{File: "a.php", StartLine: 4}}},
			Command: &analysis.CommandFacts{Paths: []analysis.CommandPath{{Dependency: 0, Operand: analysis.CommandSlotShell, Protection: "guarded", Controls: []int{0}}}}}
	}
	for _, tt := range []struct {
		text, guard, edge string
	}{
		{"is_numeric( $octet[0] ) && is_numeric( $octet[1] )", "is_numeric", "trailing whitespace"},
		{"ctype_digit($port)", "ctype_digit", "0-9"},
		{"preg_match('/^[a-z0-9.]+$/', $host)", "anchored_regex", "before a final newline"},
		{"re.fullmatch(r'[0-9.]+', host)", "anchored_regex", "fullmatch"},
		{"item.match(imgRegex)", "regex_match", "contains a match"},
		{"in_array($cmd, $allowed)", "allow_list", "strict=true"},
		{"ALLOWED.includes(tool)", "allow_list", "SameValueZero"},
		{"intval($count) > 0", "integer_cast", "digits"},
	} {
		contracts := GuardContracts(guarded(tt.text))
		if len(contracts) == 0 || contracts[0].Guard != tt.guard || !strings.Contains(contracts[0].Accepts, tt.edge) || contracts[0].At != "a.php:4" {
			t.Fatalf("%s: contracts %+v", tt.text, contracts)
		}
		text := GuardContractText(guarded(tt.text))
		if !strings.Contains(text, tt.guard+" at a.php:4") {
			t.Fatalf("%s: rendered contract %q", tt.text, text)
		}
	}
	if c := GuardContracts(guarded("valid_octets($octet)")); len(c) != 0 {
		t.Fatalf("an unrecognised control has no contract: %+v", c)
	}
	if text := GuardContractText(guarded("valid_octets($octet)")); !strings.Contains(text, "guard_semantics_unknown") {
		t.Fatalf("missing contract instruction: %q", text)
	}
	found := false
	for _, q := range CommandQuestions() {
		found = found || q.Name == "guard_bypass"
	}
	if !found || len(CommandChoices("guard_bypass")) != 4 || CommandProtocol != "command-components-v5" {
		t.Fatal("the bypass question and protocol bump are required")
	}
}
