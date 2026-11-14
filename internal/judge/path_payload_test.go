package judge

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
)

func TestPathPayloadAndReplay(t *testing.T) {
	for _, fixture := range []struct{ dir, route string }{
		{"typescript/path-traversal", "/v/join-read"},
		{"javascript/path-traversal", "/cjs/read"},
		{"python/path-traversal", "/v/open"},
	} {
		uses, _ := pathUsesByRoute(t, fixture.dir)
		u := uses[fixture.route]
		for _, provider := range []string{"openai", "jev"} {
			t.Run(fixture.dir+"/"+provider, func(t *testing.T) {
				c, _ := New(provider, "fixture-model", "never-persist-key")
				trace, err := c.Preview(u)
				if err != nil {
					t.Fatal(err)
				}
				if trace.QuestionVersion != analysispacks.PathProtocol || trace.RequestDigest == "" || trace.Components == nil || len(trace.Request) > 64<<10 {
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
				for _, want := range []string{"analysis_components", "zazzles.path.", `"path"`, "\"operation\"", "posix", "path_operands", "claim.path", "api.", u.Path.ContractID} {
					if !strings.Contains(input, want) {
						t.Fatalf("selected material missing %q", want)
					}
				}
				// Other families' material, private paths and answer-key labels never enter the request.
				for _, bad := range []string{"Cross-site scripting", "## Logging", "`$where`", "Sequelize", "TestPath", "internal/parse", "never-persist-key", "field_requirement", "shell_syntax_protection", "child_process", "TS-PATH", "FLASK-PATH", "expected_positives", "matrix.json"} {
					if strings.Contains(input, bad) {
						t.Fatalf("unrelated or private material leaked: %q", bad)
					}
				}
				raw, _ := json.Marshal(body)
				for _, q := range analysispacks.PathQuestions() {
					if !strings.Contains(string(raw), q.Name) {
						t.Fatalf("question %s missing", q.Name)
					}
					for _, choice := range analysispacks.PathChoices(q.Name) {
						if !strings.Contains(string(raw), choice["value"]) {
							t.Fatalf("choice %s/%s missing", q.Name, choice["value"])
						}
					}
				}
				// Exact replay works; every changed input rejects it.
				stub, calls := pathStub(t, provider, honestRaw)
				a, tr := stub.AssessTrace(context.Background(), u)
				if a.FindingStatus != "confirmed_vulnerability" || *calls != 1 {
					t.Fatalf("assessment %+v calls %d", a, *calls)
				}
				if r := stub.Replay(u, tr); r.Status != "completed" || r.FindingStatus != a.FindingStatus {
					t.Fatalf("exact replay: %+v", r)
				}
				mutations := map[string]func(*analysis.CandidateUse){
					"facts": func(x *analysis.CandidateUse) { f := *x.Path; f.Operation += "x"; x.Path = &f },
					"flow": func(x *analysis.CandidateUse) {
						f := *x.Path
						f.Paths = append([]analysis.PathFlow{}, x.Path.Paths...)
						f.Paths[0].Protection = "guarded"
						x.Path = &f
					},
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
				badProtocol.QuestionVersion = "path-components-v0"
				if r := stub.Replay(u, badProtocol); r.Status == "completed" {
					t.Fatal("replay accepted a different protocol")
				}
			})
		}
	}
}

func TestPathPreTransportFailuresMakeNoCalls(t *testing.T) {
	uses, _ := pathUsesByRoute(t, "typescript/path-traversal")
	u := uses["/v/join-read"]
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
			c, calls := pathStub(t, "openai", honestRaw)
			a := c.Assess(context.Background(), m)
			if *calls != 0 || a.Status == "completed" || a.FindingStatus == "confirmed_vulnerability" || a.FindingStatus == "protected_for_claim" {
				t.Fatalf("calls %d assessment %+v", *calls, a)
			}
		})
	}
	b := u
	b.EntryKind, b.EntryFacts = "client", nil
	if _, err := analysispacks.ForUse(b); err == nil {
		t.Fatal("browser entry selected a filesystem contract")
	}
}
