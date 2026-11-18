package langpy

import (
	"strings"
	"testing"

	"fmt"
	sitter "github.com/tree-sitter/go-tree-sitter"
	python "github.com/tree-sitter/tree-sitter-python/bindings/go"
	"github.com/zazzcode/zazzles/internal/parse"
)

func guardSiteLabel(l parse.GuardLang, g parse.GuardSite) string {
	polarity := "enforces"
	if g.Polarity != parse.GuardEnforcesWhenTrue {
		polarity = "rejects"
	}
	return fmt.Sprintf("%s/%s/%s", g.Kind, polarity, strings.Join(strings.Fields(g.Cond.Utf8Text(l.Src)), " "))
}

func TestGuardClimbSites(t *testing.T) {
	pyParser, err := parse.OpenParser(python.Language())
	if err != nil {
		t.Fatal(err)
	}
	defer pyParser.Close()
	for _, tt := range []struct {
		name, source string
		imports      map[string]pythonImport
		want         []string
	}{
		{"enclosing consequence", "def h():\n    if a:\n        sink(x)\n", nil, []string{"enclosing_guard/enforces/a"}},
		{"else branch is rejecting", "def h():\n    if a:\n        b()\n    else:\n        sink(x)\n", nil, []string{"enclosing_guard/rejects/a"}},
		{"verified abort terminates", "def h():\n    if a:\n        abort(403)\n    sink(x)\n", map[string]pythonImport{"abort": {module: "flask", name: "abort"}}, []string{"terminating_guard/rejects/a"}},
		{"verified sys.exit terminates", "def h():\n    if a:\n        sys.exit(1)\n    sink(x)\n", map[string]pythonImport{"sys": {module: "sys"}}, []string{"terminating_guard/rejects/a"}},
		{"unverified abort does not", "def h():\n    if a:\n        abort(403)\n    sink(x)\n", nil, nil},
		{"raise terminates", "def h():\n    if a:\n        raise ValueError(a)\n    sink(x)\n", nil, []string{"terminating_guard/rejects/a"}},
		{"return terminates", "def h():\n    if a:\n        return 1\n    sink(x)\n", nil, []string{"terminating_guard/rejects/a"}},
		{"elif conditions are not climbed", "def h():\n    if a:\n        b()\n    elif c:\n        sink(x)\n", nil, nil},
		{"function boundary stops the climb", "if a:\n    raise ValueError(a)\ndef h():\n    sink(x)\n", nil, nil},
	} {
		t.Run("python "+tt.name, func(t *testing.T) {
			src := []byte(tt.source)
			tree := pyParser.Parse(src, nil)
			defer tree.Close()
			m := &pythonModule{src: src, tree: tree, funcs: map[string]*sitter.Node{}, vars: map[string]*sitter.Node{}, imports: tt.imports}
			f := &pythonFlow{set: &pythonSet{modules: map[string]*pythonModule{}}, module: m, env: map[string]pythonValue{}, imports: tt.imports}
			l := f.guardLang()
			call := findCall(tree.RootNode(), src, "call", "sink(")
			if call == nil {
				t.Fatal("no sink call")
			}
			var got []string
			l.Climb(call, func(g parse.GuardSite) { got = append(got, guardSiteLabel(l, g)) })
			if strings.Join(got, ",") != strings.Join(tt.want, ",") {
				t.Fatalf("sites %v, want %v", got, tt.want)
			}
		})
	}
}

// findCall returns the first call whose text starts with prefix.
func findCall(root *sitter.Node, src []byte, kind, prefix string) *sitter.Node {
	var found *sitter.Node
	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		if found != nil {
			return
		}
		if n.Kind() == kind && strings.HasPrefix(n.Utf8Text(src), prefix) {
			found = n
			return
		}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			visit(n.NamedChild(i))
		}
	}
	visit(root)
	return found
}
