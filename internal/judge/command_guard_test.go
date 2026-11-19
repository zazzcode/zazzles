package judge

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
	"github.com/zazzcode/zazzles/internal/pipeline"
)

const numericGuardPHP = `<?php
if( isset( $_POST[ 'Submit' ] ) ) {
	$target = $_REQUEST[ 'ip' ];
	$octet = explode( ".", $target );
	if( ( is_numeric( $octet[0] ) ) && ( is_numeric( $octet[1] ) ) && ( is_numeric( $octet[2] ) ) && ( is_numeric( $octet[3] ) ) && ( sizeof( $octet ) == 4 ) ) {
		$target = $octet[0] . '.' . $octet[1] . '.' . $octet[2] . '.' . $octet[3];
		$cmd = shell_exec( 'ping  -c 4 ' . $target );
		echo $cmd;
	}
}
`

const weakRegexJS = `var express = require('express');
var exec = require('child_process').exec;
var app = express();
app.post('/create', function (req, res) {
  var item = req.body.content;
  var imgRegex = /\!\[alt text\]\((http.*)\s\".*/;
  if (typeof (item) == 'string' && item.match(imgRegex)) {
    var url = item.match(imgRegex)[1];
    exec('identify ' + url, function (err, stdout, stderr) {});
  }
  res.send('ok');
});
`

func guardedCommandUse(t *testing.T, files map[string]string) analysis.CandidateUse {
	t.Helper()
	r, err := pipeline.Analyze(writeFixture(t, files), "")
	if err != nil {
		t.Fatal(err)
	}
	uses := commandUsesOf(r)
	if len(uses) != 1 || !analysispacks.GuardedCommandPath(uses[0].Command) {
		t.Fatalf("want one guarded command record, got %d", len(uses))
	}
	return uses[0]
}

func hasGapKind(gaps []analysis.Gap, kind string) bool {
	for _, g := range gaps {
		if g.Kind == kind {
			return true
		}
	}
	return false
}

func TestCommandGuardBypassPolicy(t *testing.T) {
	numeric := guardedCommandUse(t, map[string]string{"index.php": numericGuardPHP})
	weak := guardedCommandUse(t, map[string]string{"package.json": `{"dependencies":{"express":"4.18.2"}}`, "server.js": weakRegexJS})
	// The same guarded path with its guard text replaced by an unrecognised
	// call: no contract is available.
	opaque := numeric
	opaque.Context = append([]analysis.Evidence(nil), numeric.Context...)
	for i, e := range opaque.Context {
		if strings.Contains(e.Text, "is_numeric") {
			opaque.Context[i].Text = "valid_octets( $octet )"
		}
	}
	vulnerable := func(bypass string) commandAnswers {
		return commandAnswers{"shell_syntax_protection": "vulnerable", "executable_control": "not_applicable", "argument_control": "not_applicable", "guard_bypass": bypass, "protection_coverage": "incomplete"}
	}
	for _, tt := range []struct {
		name    string
		use     analysis.CandidateUse
		answers commandAnswers
		status  string
		blocker string
	}{
		{"vulnerable with no_bypass contradicts itself", numeric, vulnerable("no_bypass"), "needs_evidence", "command_answers_inconsistent"},
		{"vulnerable with guard_semantics_unknown stays Review", numeric, vulnerable("guard_semantics_unknown"), "needs_evidence", "command_guard_semantics_unknown"},
		{"weak guard with a named bypass stays a finding", weak, vulnerable("bypass_identified"), "confirmed_vulnerability", ""},
		{"a guard with no contract stays Review", opaque, vulnerable("bypass_identified"), "needs_evidence", "command_guard_semantics_unknown"},
		{"protected with a named bypass contradicts itself", numeric, commandAnswers{"shell_syntax_protection": "protected", "executable_control": "not_applicable", "argument_control": "not_applicable", "guard_bypass": "bypass_identified", "protection_coverage": "complete"}, "needs_evidence", "command_answers_inconsistent"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			a := analysis.Assessment{Status: "completed", QuestionVersion: analysispacks.CommandProtocol, Answers: tt.answers, Resolutions: bypassCitation(tt.use)}
			applyCommandPolicy(tt.use, &a)
			if a.FindingStatus != tt.status || tt.blocker != "" && !hasGapKind(a.BlockingGaps, tt.blocker) {
				t.Fatalf("status %s blockers %+v reason %q", a.FindingStatus, a.BlockingGaps, a.Reason)
			}
		})
	}
}

// The request for a guarded command path carries the guard's contract and the
// bypass question.
func TestCommandGuardRequestCarriesContract(t *testing.T) {
	numeric := guardedCommandUse(t, map[string]string{"index.php": numericGuardPHP})
	var body string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		body = string(raw)
		w.WriteHeader(400)
	}))
	defer server.Close()
	c, err := New("openai", "fixture-model", "synthetic-test-key")
	if err != nil {
		t.Fatal(err)
	}
	c.endpoint = server.URL
	c.Assess(context.Background(), numeric)
	var request struct {
		Questions []struct {
			Name         string `json:"name"`
			Instructions string `json:"instructions"`
		} `json:"questions"`
	}
	if err := json.Unmarshal([]byte(body), &request); err != nil {
		t.Fatal(err)
	}
	for _, q := range request.Questions {
		if q.Name == "guard_bypass" {
			if !strings.Contains(q.Instructions, "is_numeric at index.php:") || !strings.Contains(q.Instructions, "trailing whitespace") {
				t.Fatalf("guard contract missing from the bypass question: %s", q.Instructions)
			}
			return
		}
	}
	t.Fatal("guard_bypass question missing from the request")
}
