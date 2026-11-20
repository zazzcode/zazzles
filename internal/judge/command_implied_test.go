package judge

import (
	"encoding/json"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
)

// twoGuardedPHP guards two request values with is_numeric before one shell
// command: two guarded request-derived paths on the shell operand.
const twoGuardedPHP = `<?php
$count = $_REQUEST['count'];
$size = $_REQUEST['size'];
if( is_numeric( $count ) && is_numeric( $size ) ) {
	$cmd = shell_exec( 'ping -c ' . $count . ' -s ' . $size . ' 127.0.0.1' );
	echo $cmd;
}
`

func requestQuestionNames(t *testing.T, use analysis.CandidateUse) map[string]bool {
	t.Helper()
	c, err := New("openai", "fixture-model", "synthetic-test-key")
	if err != nil {
		t.Fatal(err)
	}
	payload, err := c.payload(use)
	if err != nil {
		t.Fatal(err)
	}
	var request struct {
		Questions []struct {
			Name string `json:"name"`
		} `json:"questions"`
	}
	if err := json.Unmarshal(payload, &request); err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, q := range request.Questions {
		names[q.Name] = true
	}
	return names
}

// TestCommandImpliedSinglePath (close-findings-gaps AC1, D-1, D-2): a bypass
// on the only guarded path binds to that path without a model citation; two
// guarded paths keep the citation requirement. The single path's guard is
// one whose accepted characters the scanner cannot list, so its adequacy is
// the assessment's call (TestCommandBypassNeedsSupportedConsequence covers
// the listed ones).
func TestCommandImpliedSinglePath(t *testing.T) {
	one := guardedCommandUse(t, map[string]string{"package.json": `{"dependencies":{"express":"4.18.2"}}`, "server.js": lookaheadRegexJS})
	two := guardedCommandUse(t, map[string]string{"index.php": twoGuardedPHP})
	if guarded := len(two.Command.Paths); guarded != 2 {
		t.Fatalf("fixture wants two guarded paths, got %+v", two.Command.Paths)
	}
	answers := func(bypass string) commandAnswers {
		return commandAnswers{"shell_syntax_protection": "vulnerable", "executable_control": "not_applicable", "argument_control": "not_applicable", "guard_bypass": bypass, "protection_coverage": "incomplete"}
	}
	for _, tt := range []struct {
		name    string
		use     analysis.CandidateUse
		bypass  string
		status  string
		blocker string
		implied bool
	}{
		{"one guarded path binds the bypass to itself", one, "bypass_identified", "confirmed_vulnerability", "", true},
		{"two guarded paths without a citation stay Review", two, "bypass_identified", "needs_evidence", "command_guard_semantics_unknown", false},
		{"no_bypass still contradicts a vulnerable answer", one, "no_bypass", "needs_evidence", "command_answers_inconsistent", false},
		{"guard_semantics_unknown stays Review", one, "guard_semantics_unknown", "needs_evidence", "command_guard_semantics_unknown", false},
		{"a rejected model citation is not overridden", one, "bypass_identified", "needs_evidence", "command_guard_semantics_unknown", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			a := analysis.Assessment{Status: "completed", QuestionVersion: analysispacks.CommandProtocol, Answers: answers(tt.bypass)}
			if tt.name == "a rejected model citation is not overridden" {
				a.Resolutions = []analysis.Resolution{{Question: resolvePrefix + "bypass", QuestionVersion: BypassQuestionVersion, Answer: "bypass_identified", Citation: []string{"e0", "e9"}, Rejection: "cited ID e9 was not in the request"}}
			}
			applyCommandPolicy(tt.use, &a)
			if a.FindingStatus != tt.status || tt.blocker != "" && !hasGapKind(a.BlockingGaps, tt.blocker) {
				t.Fatalf("status %s blockers %+v reason %q", a.FindingStatus, a.BlockingGaps, a.Reason)
			}
			var got *analysis.Resolution
			for i := range a.Resolutions {
				if len(a.Resolutions[i].Citation) == 1 && a.Resolutions[i].Citation[0] == ImpliedSinglePath {
					got = &a.Resolutions[i]
				}
			}
			if (got != nil) != tt.implied {
				t.Fatalf("implied resolution %+v, want %v", got, tt.implied)
			}
			if got != nil && (!got.Verified || got.Verifier != "scanner" || !got.Discharged || got.Dependency == nil || *got.Dependency != tt.use.Command.Paths[0].Dependency || got.QuestionVersion != BypassQuestionVersion) {
				t.Fatalf("implied resolution %+v", got)
			}
		})
	}
	if q := requestQuestionNames(t, one); q[resolvePrefix+"bypass"+citeSuffix] || !q["guard_bypass"] {
		t.Fatalf("one guarded path: the citation question is not sent, guard_bypass is: %v", q)
	}
	if q := requestQuestionNames(t, two); !q[resolvePrefix+"bypass"+citeSuffix] {
		t.Fatalf("two guarded paths keep the citation question: %v", q)
	}
}

// TestFollowUpAnsweredByContract (D-3): a follow-up naming a member the guard
// contract table already describes is not sent.
func TestFollowUpAnsweredByContract(t *testing.T) {
	weak := guardedCommandUse(t, map[string]string{"package.json": `{"dependencies":{"express":"4.18.2"}}`, "server.js": lookaheadRegexJS})
	if got := contractAnswersFollowUp(weak, "helper_body", "item.match"); got == "" {
		t.Fatal("item.match is described by the regex_match contract")
	}
	if got := contractAnswersFollowUp(weak, "helper_body", "parseImage"); got != "" {
		t.Fatalf("an application helper is not a contract member: %q", got)
	}
	numeric := guardedCommandUse(t, map[string]string{"index.php": numericGuardPHP})
	if got := contractAnswersFollowUp(numeric, "helper_body", "item.match"); got != "" {
		t.Fatalf("a member with no contract on this record is asked: %q", got)
	}
}
