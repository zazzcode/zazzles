package parse

import "testing"

func TestPathGuardClassificationDeterminism(t *testing.T) {
	var first string
	for iter := 0; iter < 100; iter++ {
		defs := map[string]string{
			"checkA": "full.startsWith(ROOT)",
			"checkB": "full.startsWith(ROOT + path.sep)",
			"checkC": "full.startsWith(BASE)",
			"checkD": "full.startsWith('/srv/')",
		}
		got := classifyPathGuardText("!checkA || !checkB || !checkC || !checkD", []string{"full", "checkA", "checkB", "checkC", "checkD"}, defs, func(string) bool { return false })
		if iter == 0 {
			first = got
		} else if got != first {
			t.Fatalf("nondeterministic guard classification on iter %d: got %s, first %s", iter, got, first)
		}
	}
}
