package parse

import (
	"fmt"
	"strings"
	"testing"

	sitter "github.com/tree-sitter/go-tree-sitter"
	js "github.com/tree-sitter/tree-sitter-javascript/bindings/go"
	python "github.com/tree-sitter/tree-sitter-python/bindings/go"
)

func guardSiteLabel(l guardLang, g guardSite) string {
	polarity := "enforces"
	if g.Polarity == guardRejectsWhenTrue {
		polarity = "rejects"
	}
	return fmt.Sprintf("%s/%s/%s", g.Kind, polarity, strings.Join(strings.Fields(l.text(g.Cond)), " "))
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

func TestGuardClimbSites(t *testing.T) {
	jsParser, err := openParser(js.Language())
	if err != nil {
		t.Fatal(err)
	}
	defer jsParser.Close()
	for _, tt := range []struct {
		name, source string
		want         []string
	}{
		{"enclosing consequence", `function h(){ if (a) { sink(x); } }`, []string{"enclosing_guard/enforces/(a)"}},
		{"else branch is rejecting", `function h(){ if (a) { b(); } else { sink(x); } }`, []string{"enclosing_guard/rejects/(a)"}},
		{"else if chain, innermost first", `function h(){ if (a) { b(); } else if (c) { sink(x); } }`, []string{"enclosing_guard/enforces/(c)", "enclosing_guard/rejects/(a)"}},
		{"terminating sibling", `function h(){ if (a) { return; } sink(x); }`, []string{"terminating_guard/rejects/(a)"}},
		{"throwing sibling", `function h(){ if (a) throw new Error('x'); sink(x); }`, []string{"terminating_guard/rejects/(a)"}},
		{"if/else that both exit", `function h(){ if (a) { return; } else { throw e; } sink(x); }`, []string{"terminating_guard/rejects/(a)"}},
		{"non-exiting sibling", `function h(){ if (a) { log(); } sink(x); }`, nil},
		{"process.exit terminates", `function h(){ if (a) { process.exit(1); } sink(x); }`, []string{"terminating_guard/rejects/(a)"}},
		{"shadowed process does not", `function h(process){ if (a) { process.exit(1); } sink(x); }`, nil},
		{"call inside the condition", `function h(){ if (sink(x)) { b(); } }`, nil},
		{"sibling after the call", `function h(){ sink(x); if (a) { return; } }`, nil},
		{"nested terminating and enclosing", `function h(){ if (a) { return; } if (b) { sink(x); } }`, []string{"enclosing_guard/enforces/(b)", "terminating_guard/rejects/(a)"}},
		{"function boundary stops the climb", `if (a) { return; } function h(){ sink(x); }`, nil},
	} {
		t.Run("js "+tt.name, func(t *testing.T) {
			src := []byte(tt.source)
			tree := jsParser.Parse(src, nil)
			defer tree.Close()
			m := &sourceModule{src: src, tree: tree, imports: map[string]importBinding{}}
			l := m.guardLang()
			call := findCall(tree.RootNode(), src, "call_expression", "sink(")
			if call == nil {
				t.Fatal("no sink call")
			}
			var got []string
			l.climb(call, func(g guardSite) { got = append(got, guardSiteLabel(l, g)) })
			if strings.Join(got, ",") != strings.Join(tt.want, ",") {
				t.Fatalf("sites %v, want %v", got, tt.want)
			}
		})
	}

	pyParser, err := openParser(python.Language())
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
			l.climb(call, func(g guardSite) { got = append(got, guardSiteLabel(l, g)) })
			if strings.Join(got, ",") != strings.Join(tt.want, ",") {
				t.Fatalf("sites %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGuardLangDerivedAndAssigned(t *testing.T) {
	jsParser, err := openParser(js.Language())
	if err != nil {
		t.Fatal(err)
	}
	defer jsParser.Close()
	src := []byte(`function h(){ const a = req.q; const b = a.trim(); const c = b + '1'; const d = other(); a2 = 1; if (c) { return; } a = a + 'x'; sink(a); }`)
	tree := jsParser.Parse(src, nil)
	defer tree.Close()
	m := &sourceModule{src: src, tree: tree, imports: map[string]importBinding{}}
	l := m.guardLang()
	call := findCall(tree.RootNode(), src, "call_expression", "sink(")
	scope := l.scope(call)
	names := map[string]bool{"a": true}
	l.derive(scope, names, map[string]string{}, map[string]*sitter.Node{})
	if got := strings.Join(sortedNameList(names), ","); got != "a,b,c" {
		t.Fatalf("derived closure %s, want a,b,c", got)
	}
	var ifEnd uint
	l.climb(call, func(g guardSite) { ifEnd = g.End })
	if !l.assignedBetween(scope, ifEnd, call.StartByte(), []string{"a"}) {
		t.Fatal("assignment between guard and call not detected")
	}
	if l.assignedBetween(scope, ifEnd, call.StartByte(), []string{"c"}) {
		t.Fatal("unrelated name reported as assigned")
	}
}
