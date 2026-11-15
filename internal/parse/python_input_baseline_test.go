package parse

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysispacks"
)

// Freeze the entire predecessor report, including invocation identities and all
// claim families. Only the optional acquisition extension is projected away.
func TestPythonInputPredecessorBaseline(t *testing.T) {
	const golden = "testdata/python/input-baseline.json"
	got := map[string]string{}
	for _, fixture := range []string{"routes", "dynamic-vulnpy", "command-injection", "path-traversal", "outbound"} {
		r, err := Analyze("testdata/python/"+fixture, "")
		if err != nil {
			t.Fatal(err)
		}
		r.Root = "python/" + fixture
		for i := range r.Uses {
			r.Uses[i].InputFacts = nil
			analysispacks.Attach(&r.Uses[i])
		}
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		got[fixture] = fmt.Sprintf("%x", sha256.Sum256(b))
	}
	if *update {
		b, err := json.MarshalIndent(got, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(golden, append(b, '\n'), 0644); err != nil {
			t.Fatal(err)
		}
	}
	b, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	var want map[string]string
	if err := json.Unmarshal(b, &want); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("predecessor evidence drift:\ngot  %v\nwant %v", got, want)
	}
}
