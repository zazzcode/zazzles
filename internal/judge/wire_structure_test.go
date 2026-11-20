package judge

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
)

// unfactoredWire is the request bundle before D-3: compacted, with local
// identity, in the version 7 row and dependency form.
func unfactoredWire(t *testing.T, u analysis.CandidateUse) map[string]any {
	t.Helper()
	wire, _, err := compactBundleIDs(wireBundle(u))
	if err != nil {
		t.Fatal(err)
	}
	return localIdentity(wire)
}

// rawSentUse is the use bundle exactly as the request sends it, unexpanded.
func rawSentUse(t *testing.T, u analysis.CandidateUse) map[string]any {
	t.Helper()
	c, _ := New("openai", "fixture-model", "offline")
	payload, err := c.payloadForm(u, true)
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Input string `json:"input"`
	}
	var input struct {
		Use map[string]any `json:"use"`
	}
	if json.Unmarshal(payload, &envelope) != nil || json.Unmarshal([]byte(envelope.Input), &input) != nil {
		t.Fatal("undecodable request")
	}
	return input.Use
}

func cloneWire(t *testing.T, v map[string]any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestWireStructureRoundTrip expands the version 8 rows and dependencies of
// every judge fixture use back to the version 7 form and finds them equal,
// and finds that form is what the request sends.
func TestWireStructureRoundTrip(t *testing.T) {
	c, _ := New("openai", "fixture-model", "offline")
	n, factored := 0, 0
	for _, fu := range judgeFixtureUses(t) {
		if !AssessableUse(fu.use) {
			continue
		}
		v7 := unfactoredWire(t, fu.use)
		sent := factorStructure(cloneWire(t, v7))
		back := expandStructure(cloneWire(t, sent))
		for _, key := range []string{"evidence", "dependencies", "compact_wire"} {
			if !sameJSON(v7[key], back[key]) {
				a, _ := json.Marshal(v7[key])
				b, _ := json.Marshal(back[key])
				t.Fatalf("%s %s: %s does not round-trip:\n%s\n%s", fu.fixture, fu.use.Kind, key, a, b)
			}
		}
		if _, ok := back["shared_transfer_tails"]; ok {
			t.Fatal("expanded form keeps shared_transfer_tails")
		}
		if _, ok := sent["shared_transfer_tails"]; ok {
			factored++
		}
		payload, err := c.payloadForm(fu.use, true)
		if err != nil {
			continue
		}
		var envelope struct {
			Input string `json:"input"`
		}
		_ = json.Unmarshal(payload, &envelope)
		var input struct {
			Use map[string]any `json:"use"`
		}
		_ = json.Unmarshal([]byte(envelope.Input), &input)
		if !sameJSON(input.Use["evidence"], sent["evidence"]) || !sameJSON(input.Use["dependencies"], sent["dependencies"]) {
			t.Fatalf("%s %s: the request does not send the factored form", fu.fixture, fu.use.Kind)
		}
		n++
	}
	if n == 0 {
		t.Fatal("no fixture request built")
	}
	t.Logf("%d fixture requests round-trip; %d state shared transfer tails", n, factored)
}

func TestWireStructureRowsPutTextLast(t *testing.T) {
	use := rawSentUse(t, identityUse())
	raw, _ := json.Marshal(use)
	cw := use["compact_wire"].(map[string]any)
	cols, _ := json.Marshal(cw["evidence_columns"])
	if string(cols) != `["kind","source_index","start_line","end_line","text_ref","start_column","end_column","text"]` {
		t.Fatalf("evidence columns: %s", cols)
	}
	for _, r := range use["evidence"].([]any) {
		row := r.([]any)
		if last := row[len(row)-1]; last == nil || last == "" {
			t.Fatalf("row keeps a trailing empty column: %v", row)
		}
	}
	if strings.Contains(string(raw), `,"",`) || strings.Contains(string(raw), `,""]`) {
		t.Fatalf("empty text placeholder sent: %s", raw)
	}
}

// structureUse has three dependencies that end with the same five transfers
// and one that shares only three of them.
func structureUse() analysis.CandidateUse {
	u := identityUse()
	ev := func(kind string, line int) analysis.Evidence {
		text := fmt.Sprintf("v%d = step(v%d)", line, line-1)
		return analysis.Evidence{Kind: kind, Text: text, Span: analysis.Span{File: "app.js", StartLine: line, EndLine: line, StartByte: line * 100, EndByte: line*100 + len(text)}}
	}
	tail := []analysis.Evidence{ev("assignment", 20), ev("assignment", 21), ev("assignment", 22), ev("assignment", 23), ev("assignment", 24)}
	u.Dependencies = nil
	for i := 0; i < 3; i++ {
		u.Dependencies = append(u.Dependencies, analysis.Dependency{Source: ev("input_source", 10+i), Transfers: append([]analysis.Evidence{ev("assignment", 14+i)}, tail...)})
	}
	u.Dependencies = append(u.Dependencies, analysis.Dependency{Source: ev("input_source", 13), Transfers: append([]analysis.Evidence{ev("assignment", 17)}, tail[2:]...)})
	return u
}

func TestWireStructureSharedTails(t *testing.T) {
	u := structureUse()
	v7 := unfactoredWire(t, u)
	use := rawSentUse(t, u)
	tails, _ := use["shared_transfer_tails"].([]any)
	if len(tails) != 1 || len(tails[0].([]any)) != 5 {
		t.Fatalf("shared tails: %v", use["shared_transfer_tails"])
	}
	deps := use["dependencies"].([]any)
	for i := 0; i < 3; i++ {
		transfers := deps[i].(map[string]any)["transfers"].([]any)
		if len(transfers) != 2 || transfers[1] != "t0" {
			t.Fatalf("dependency %d: %v", i, transfers)
		}
	}
	if transfers := deps[3].(map[string]any)["transfers"].([]any); len(transfers) != 4 {
		t.Fatalf("a three-transfer run was factored: %v", transfers)
	}
	if back := expandStructure(cloneWire(t, use)); !sameJSON(back["dependencies"], v7["dependencies"]) {
		t.Fatal("shared tails do not expand to the original chains")
	}
	payload, _ := (&Client{provider: "openai", model: "fixture-model"}).payloadForm(u, true)
	if !strings.Contains(string(payload), "shared_transfer_tails") || !strings.Contains(string(payload), "tN") {
		t.Fatal("instruction does not state the shared tail schema")
	}
}

// TestWireStructureCitationsReadExpandedChains: the citation index of a
// factored request sees each dependency's full chain.
func TestWireStructureCitationsReadExpandedChains(t *testing.T) {
	u := structureUse()
	c, _ := New("openai", "fixture-model", "offline")
	payload, err := c.payloadForm(u, true)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := requestUse(payload)
	if err != nil {
		t.Fatal(err)
	}
	x, err := indexWire(wire)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := indexWire(unfactoredWire(t, u))
	if !reflect.DeepEqual(x.chains, want.chains) || !reflect.DeepEqual(x.evidence, want.evidence) {
		t.Fatalf("citation index differs:\n%v\n%v", x.chains, want.chains)
	}
}

// TestWireV8RejectsVersion7Trace: a request carries evidence_version 8, and a
// saved trace whose request states version 7 does not replay as exact.
func TestWireV8RejectsVersion7Trace(t *testing.T) {
	c, _ := New("openai", "fixture-model", "offline")
	u := selectedSQLUse(t)
	trace, err := c.Preview(u)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(trace.Request), `\"evidence_version\":8`) {
		t.Fatal("request does not carry evidence_version 8")
	}
	var envelope struct {
		Questions []struct {
			Name    string              `json:"name"`
			Choices []map[string]string `json:"choices"`
		} `json:"questions"`
	}
	if err := json.Unmarshal(trace.Request, &envelope); err != nil {
		t.Fatal(err)
	}
	answers := []map[string]any{}
	for _, q := range envelope.Questions {
		answers = append(answers, map[string]any{"name": q.Name, "type": "choice", "choice": q.Choices[0]["value"]})
	}
	trace.HTTPStatus = 200
	trace.Response, _ = json.Marshal(map[string]any{"model": "fixture-model", "answers": answers})
	if got := c.Replay(u, trace); got.Status != "completed" {
		t.Fatalf("current trace does not replay: %s", got.Reason)
	}
	old := trace
	old.Request = []byte(strings.Replace(string(trace.Request), `\"evidence_version\":8`, `\"evidence_version\":7`, 1))
	if got := c.Replay(u, old); got.Status != "failed" {
		t.Fatalf("version 7 trace replayed: %+v", got)
	}
}
