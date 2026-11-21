package judge

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCodedFactsCarryTheirNotes(t *testing.T) {
	u := selectedNoSQLUse(t)
	c, _ := New("openai", "fixture-model", "key")
	p, err := c.payload(u)
	if err != nil {
		t.Fatal(err)
	}
	var outer struct {
		Input string `json:"input"`
	}
	if err := json.Unmarshal(p, &outer); err != nil {
		t.Fatal(err)
	}
	var inner struct {
		Guidelines struct {
			Body string `json:"body"`
		} `json:"analysis_guidelines"`
		Use struct {
			Facts []string `json:"model_facts"`
		} `json:"use"`
	}
	if err := json.Unmarshal([]byte(outer.Input), &inner); err != nil {
		t.Fatal(err)
	}
	if len(inner.Use.Facts) == 0 {
		t.Fatal("fixture has no model facts")
	}
	for _, fact := range inner.Use.Facts {
		code, _, _ := strings.Cut(fact, ":")
		if !strings.Contains(inner.Guidelines.Body, "- `"+code+"`: ") {
			t.Fatalf("fact %q sent without its note", fact)
		}
		if strings.Contains(fact, "Scope is direct Express") {
			t.Fatalf("fixed interpretation duplicated in model_facts: %q", fact)
		}
	}
	if strings.Count(inner.Guidelines.Body, "## Fact codes") != 1 || strings.Contains(inner.Guidelines.Body, "`scope_grpc_unary`") {
		t.Fatalf("notes not limited to named codes:\n%s", inner.Guidelines.Body)
	}
	u.Completeness.ModelFacts = append(u.Completeness.ModelFacts, "undeclared_code: x")
	if _, err := c.payload(u); err == nil {
		t.Fatal("unknown fact code was sent without an owner")
	}
}
