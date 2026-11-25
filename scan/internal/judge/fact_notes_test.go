package judge

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/pipeline"
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

// TestEscapeFactSentences sends the sentences of an escaped operand only in the
// request of a record that has the fact, and leaves the record's contract alone.
func TestEscapeFactSentences(t *testing.T) {
	const particular, contract = "an escaped value that sits inside a quoted SQL string literal, and is not changed afterwards, cannot end that literal", "An escaped value inside a quoted SQL string literal, not changed afterwards, cannot end that literal for the connection charset"
	const general = "an escaped value interpolated into SQL text remains a construction finding"
	c, _ := New("openai", "fixture-model", "key")
	for _, form := range []struct {
		name, body string
		want       bool
	}{
		{"escaped", `$v = mysqli_real_escape_string($db, $_POST['v']); mysqli_query($db, "SELECT a FROM t WHERE b = '$v'");`, true},
		{"hash", `$v = md5($_POST['v']); mysqli_query($db, "SELECT a FROM t WHERE b = '$v'");`, false},
		{"not quoted", `$v = mysqli_real_escape_string($db, $_POST['v']); mysqli_query($db, "SELECT a FROM t WHERE b = $v");`, false},
		{"another engine", `$l = new SQLite3('a.db'); $v = mysqli_real_escape_string($db, $_POST['v']); $l->query("SELECT a FROM t WHERE b = '$v'");`, false},
		{"bound", `$s = $db->prepare('SELECT a FROM t WHERE b = ?' . $_GET['x']);`, false},
	} {
		t.Run(form.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, "index.php"), []byte("<?php\n$db = mysqli_connect('h', 'u', 'p', 'd');\n"+form.body+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			r, err := pipeline.Analyze(root, "")
			if err != nil {
				t.Fatal(err)
			}
			records := 0
			for _, u := range r.Uses {
				if u.Kind != "sql_query_candidate" {
					continue
				}
				records++
				before := u.APIModel.Semantics
				trace, err := c.Preview(u)
				if err != nil {
					t.Fatal(err)
				}
				text := string(trace.Request)
				if strings.Contains(text, particular) != form.want || strings.Contains(text, contract) != form.want || strings.Contains(text, general) == form.want {
					t.Fatalf("escape sentences sent: want %v\n%s", form.want, text)
				}
				if u.APIModel.Semantics != before || strings.Contains(before, contract) {
					t.Fatal("the record's own contract changed")
				}
			}
			if records == 0 {
				t.Fatal("no record")
			}
		})
	}
}
