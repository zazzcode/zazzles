package analysispacks

import (
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
)

// TestFamilyDigestIsolation proves D-9: bumping one family's protocol moves
// only that family's component selection. Shared components (input and flow
// capabilities) list every family's protocol; each family's reference covers
// only its own.
func TestFamilyDigestIsolation(t *testing.T) {
	items, err := descriptors()
	if err != nil {
		t.Fatal(err)
	}
	const bumped = "command-components-test-bump"
	protocols := map[string]bool{bumped: true}
	for _, f := range Families() {
		protocols[familyProtocol(f.Name)] = true
	}
	changed := 0
	for i := range items {
		for k, p := range items[i].Compatibility {
			if p == CommandProtocol {
				items[i].Compatibility[k] = bumped
				changed++
			}
		}
	}
	if changed < 3 {
		t.Fatalf("expected the command protocol on command and shared components, rewrote %d", changed)
	}
	next, err := newCatalogKnown(items, protocols)
	if err != nil {
		t.Fatal(err)
	}
	shared := 0
	for id, v := range embedded.components {
		if len(v.Compatibility) < 2 {
			continue
		}
		for _, f := range Families() {
			p := familyProtocol(f.Name)
			if f.Name == "command" || !contains(v.Compatibility, p) {
				continue
			}
			shared++
			if embedded.familyRef(id, p) != next.familyRef(id, p) {
				t.Errorf("%s: a command protocol bump moved the %s family's reference", id, f.Name)
			}
		}
	}
	if shared == 0 {
		t.Fatal("no shared component checked")
	}
	// The unscoped descriptor digest moves, which is what re-judged every family before.
	for id, v := range embedded.components {
		if strings.HasPrefix(id, "source.node-input") && contains(v.Compatibility, CommandProtocol) && embedded.refs[id] == next.refs[id] {
			t.Errorf("%s: unscoped digest should move with the command protocol", id)
		}
	}
	// A real selection: an SQL use's selection digest is unchanged.
	use := analysis.CandidateUse{Kind: "sql_query_candidate", EntryKind: "http", Sink: analysis.Evidence{Span: analysis.Span{File: "app.js"}},
		APIModel: SQLContract(sqlContractIDs[0]), Completeness: &analysis.Completeness{Evidence: map[string][]analysis.Evidence{"sink_binding": {{Kind: "sink_binding"}}}}}
	before, err := embedded.selectUse(use)
	if err != nil {
		t.Fatal(err)
	}
	after, err := next.selectUse(use)
	if err != nil {
		t.Fatal(err)
	}
	if before.Digest != after.Digest {
		t.Fatalf("SQL selection digest moved with a command bump: %s -> %s", before.Digest, after.Digest)
	}
}
