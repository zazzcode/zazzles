package judge

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysispacks"
	"github.com/zazzcode/zazzles/internal/pipeline"
)

func TestPythonInputRequestCompatibility(t *testing.T) {
	c, err := New("openai", "fixture-model", "never-persist-test-key")
	if err != nil {
		t.Fatal(err)
	}
	for _, fixture := range []string{"routes", "dynamic-vulnpy", "command-injection", "path-traversal", "outbound"} {
		t.Run(fixture, func(t *testing.T) {
			r, err := pipeline.Analyze("../parse/testdata/python/"+fixture, "")
			if err != nil {
				t.Fatal(err)
			}
			count := 0
			for _, u := range r.Uses {
				if u.InputFacts == nil {
					continue
				}
				if u.Components == nil || u.Components.Failure != "" {
					t.Fatalf("selection failed: %+v", u.Components)
				}
				if analysispacks.ObservationOnly(u.Kind) {
					continue
				}
				old := u
				old.InputFacts = nil
				analysispacks.Attach(&old)
				if !reflect.DeepEqual(u.APIModel, old.APIModel) || !reflect.DeepEqual(questionsFor(u), questionsFor(old)) {
					t.Fatal("changed sink contract/questions")
				}
				fresh, err := c.Preview(u)
				if err != nil {
					t.Fatal(err)
				}
				historical, err := c.Preview(old)
				if err != nil {
					t.Fatal(err)
				}
				if bytes.Equal(fresh.Request, historical.Request) || fresh.RequestDigest == historical.RequestDigest {
					t.Fatal("new input extension missing from effective request")
				}
				var envelope struct{ Input string }
				if err := json.Unmarshal(fresh.Request, &envelope); err != nil {
					t.Fatal(err)
				}
				for _, want := range []string{"input_facts", "source.python-input-v1", "initial_type", "sink_type"} {
					if !strings.Contains(envelope.Input, want) {
						t.Fatalf("wire omits %s", want)
					}
				}
				if strings.Contains(envelope.Input, "source.node-input") {
					t.Fatal("selected Node interpretation for Python")
				}
				// Cover every registered choice for each question under identical answers.
				// This verifies policy parity, including optimistic and unresolved answers,
				// without treating model judgments as expected source-level truth.
				rounds := 0
				for _, q := range questionsFor(u) {
					if n := len(questionChoices(q)); n > rounds {
						rounds = n
					}
				}
				for round := 0; round < rounds; round++ {
					answers := []map[string]string{}
					for _, q := range questionsFor(u) {
						values := questionChoices(q)
						answers = append(answers, map[string]string{"name": q.name, "type": "choice", "choice": values[round%len(values)]["value"]})
					}
					response, err := json.Marshal(map[string]any{"model": "fixture-model", "answers": answers})
					if err != nil {
						t.Fatal(err)
					}
					h, f := historical, fresh
					h.HTTPStatus, f.HTTPStatus = 200, 200
					h.Response, f.Response = response, response
					before, after := c.Replay(old, h), c.Replay(u, f)
					if before.Status != "completed" || after.Status != "completed" {
						t.Fatalf("fresh/historical replay not valid: %+v %+v", before, after)
					}
					before.RequestDigest, after.RequestDigest = "", ""
					if !reflect.DeepEqual(before, after) {
						t.Fatalf("classification changed for %s:\nbefore %+v\nafter %+v", u.ID, before, after)
					}
					if got := c.Replay(u, h); got.Status != "failed" || !strings.Contains(got.Reason, "exactly match") {
						t.Fatalf("historical request was reused: %+v", got)
					}
				}
				count++
			}
			if count == 0 {
				t.Fatal("no effective Python requests checked")
			}
			t.Logf("%d candidates: same questions/contracts/policy; changed requests reject historical replay", count)
		})
	}
}
