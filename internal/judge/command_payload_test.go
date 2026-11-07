package judge

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
	"github.com/zazzcode/zazzles/internal/parse"
)

func commandFixtureUse(t *testing.T, language string) analysis.CandidateUse {
	t.Helper()
	sc := commandScenarios()[0] // raw shell text
	src := sc.sources[language]
	r, err := parse.Analyze(writeFixture(t, map[string]string{src.file: src.text}), "")
	if err != nil {
		t.Fatal(err)
	}
	uses := commandUsesOf(r)
	if len(uses) != 1 {
		t.Fatalf("candidates = %d", len(uses))
	}
	return uses[0]
}

func TestCommandPayloadAndReplay(t *testing.T) {
	for _, language := range []string{"javascript", "typescript", "python"} {
		for _, provider := range []string{"openai", "jev"} {
			t.Run(language+"/"+provider, func(t *testing.T) {
				u := commandFixtureUse(t, language)
				c, _ := New(provider, "fixture-model", "never-persist-key")
				trace, err := c.Preview(u)
				if err != nil {
					t.Fatal(err)
				}
				if trace.QuestionVersion != analysispacks.CommandProtocol || trace.RequestDigest == "" || trace.Components == nil || len(trace.Request) > 64<<10 {
					t.Fatalf("provenance: %+v", trace)
				}
				var body map[string]any
				if err := json.Unmarshal(trace.Request, &body); err != nil {
					t.Fatal(err)
				}
				key := "input"
				if provider == "jev" {
					key = "state"
				}
				input := body[key].(string)
				for _, want := range []string{"analysis_components", "zazzles.command.", `"command"`, "\"operation\"", "posix", "command_operands", "execution_configuration", "claim.command", "api.", u.Command.ContractID} {
					if !strings.Contains(input, want) {
						t.Fatalf("selected material missing %q", want)
					}
				}
				for _, bad := range []string{"Cross-site scripting", "## Logging", "`$where`", "Sequelize", "TestCommand", "internal/parse", "never-persist-key", "field_requirement", "DB-API"} {
					if strings.Contains(input, bad) {
						t.Fatalf("unrelated or private material leaked: %q", bad)
					}
				}
				// All four questions with their exact choices, provider-encoded.
				raw, _ := json.Marshal(body)
				for _, q := range analysispacks.CommandQuestions() {
					if !strings.Contains(string(raw), q.Name) {
						t.Fatalf("question %s missing", q.Name)
					}
					for _, choice := range analysispacks.CommandChoices(q.Name) {
						if !strings.Contains(string(raw), choice["value"]) {
							t.Fatalf("choice %s/%s missing", q.Name, choice["value"])
						}
					}
				}
				// Exact replay works; every changed input rejects it.
				stub, calls := commandStub(t, provider, rawShell)
				a, tr := stub.AssessTrace(context.Background(), u)
				if a.FindingStatus != "confirmed_vulnerability" || *calls != 1 {
					t.Fatalf("assessment %+v calls %d", a, *calls)
				}
				if r := stub.Replay(u, tr); r.Status != "completed" || r.FindingStatus != a.FindingStatus {
					t.Fatalf("exact replay: %+v", r)
				}
				mutations := map[string]func(*analysis.CandidateUse){
					"facts":  func(x *analysis.CandidateUse) { f := *x.Command; f.Operation += "x"; x.Command = &f },
					"source": func(x *analysis.CandidateUse) { x.Sink.Text += " "; x.Sink.ModelText = x.Sink.Text },
					"roles": func(x *analysis.CandidateUse) {
						c := *x.Completeness
						c.Required = append(c.Required[:0:0], c.Required...)
						c.Required = append(c.Required, "extra_role")
						x.Completeness = &c
					},
					"component": func(x *analysis.CandidateUse) { s := *x.Components; s.Digest = "changed"; x.Components = &s },
				}
				for name, mutate := range mutations {
					m := u
					mutate(&m)
					if r := stub.Replay(m, tr); r.Status == "completed" {
						t.Fatalf("replay accepted changed %s", name)
					}
				}
				other, _ := New(provider, "another-model", "k")
				if r := other.Replay(u, tr); r.Status == "completed" {
					t.Fatal("replay accepted a different model")
				}
				badProtocol := tr
				badProtocol.QuestionVersion = "command-components-v0"
				if r := stub.Replay(u, badProtocol); r.Status == "completed" {
					t.Fatal("replay accepted a different protocol")
				}
			})
		}
	}
}

func TestCommandPreTransportFailuresMakeNoCalls(t *testing.T) {
	u := commandFixtureUse(t, "javascript")
	for name, mutate := range map[string]func(*analysis.CandidateUse){
		"missing contract":  func(x *analysis.CandidateUse) { x.APIModel = nil },
		"missing selection": func(x *analysis.CandidateUse) { x.Components = nil },
		"failed selection": func(x *analysis.CandidateUse) {
			x.Components = &analysis.ComponentSelection{Failure: "coverage failure"}
		},
		"stale selection": func(x *analysis.CandidateUse) { s := *x.Components; s.Digest = "stale"; x.Components = &s },
	} {
		t.Run(name, func(t *testing.T) {
			m := u
			mutate(&m)
			c, calls := commandStub(t, "openai", rawShell)
			a := c.Assess(context.Background(), m)
			if *calls != 0 || a.Status == "completed" || a.FindingStatus == "confirmed_vulnerability" || a.FindingStatus == "protected_for_claim" {
				t.Fatalf("calls %d assessment %+v", *calls, a)
			}
		})
	}
	// Browser entries have no Node contract: selection fails before any request.
	b := u
	b.EntryKind, b.EntryFacts = "client", nil
	if _, err := analysispacks.ForUse(b); err == nil {
		t.Fatal("browser entry selected a process contract")
	}
}
