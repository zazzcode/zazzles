package langjs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	sitter "github.com/tree-sitter/go-tree-sitter"
)

// oldBindingReassigned is the whole-module walk the write index replaced. It is
// kept here as the parity oracle.
func oldBindingReassigned(m *sourceModule, name string) bool {
	found := false
	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		if n.Kind() == "assignment_expression" || n.Kind() == "augmented_assignment_expression" {
			left := n.ChildByFieldName("left")
			found = found || (left != nil && left.Kind() == "identifier" && left.Utf8Text(m.src) == name)
		}
		for i := uint(0); i < n.NamedChildCount() && !found; i++ {
			visit(n.NamedChild(i))
		}
	}
	visit(m.tree.RootNode())
	return found
}

// oldContractBindingStable is the uncached whole-module walk that
// contractBindingStable used before the write index.
func oldContractBindingStable(m *sourceModule, name string, allowed ...*sitter.Node) bool {
	stable := !oldBindingReassigned(m, name)
	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		if !stable {
			return
		}
		var left *sitter.Node
		switch n.Kind() {
		case "assignment_expression", "augmented_assignment_expression":
			left = n.ChildByFieldName("left")
		case "update_expression":
			left = n.ChildByFieldName("argument")
		}
		if left != nil {
			text := left.Utf8Text(m.src)
			if text == name || strings.HasPrefix(text, name+".") || strings.HasPrefix(text, name+"[") {
				stable = false
				return
			}
		}
		if n.Kind() == "identifier" && n.Utf8Text(m.src) == name {
			if p := n.Parent(); p != nil {
				switch p.Kind() {
				case "arguments", "return_statement", "spread_element":
					permitted := false
					for _, item := range allowed {
						if item != nil && n.StartByte() == item.StartByte() && n.EndByte() == item.EndByte() {
							permitted = true
						}
					}
					if !permitted {
						stable = false
					}
				case "variable_declarator":
					if v := p.ChildByFieldName("value"); v != nil && v.StartByte() == n.StartByte() {
						stable = false
					}
				}
			}
		}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			visit(n.NamedChild(i))
		}
	}
	visit(m.tree.RootNode())
	return stable
}

func TestBindingIndexParity(t *testing.T) {
	roots := []string{"testdata"}
	if root := os.Getenv("ZAZZLES_JUICE_SHOP"); root != "" {
		roots = append(roots, root)
	}
	ps, err := newParsers()
	if err != nil {
		t.Fatal(err)
	}
	defer ps.close()
	files, names := 0, 0
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "node_modules" && root != "testdata" || d.Name() == ".git" {
					return filepath.SkipDir
				}
				return nil
			}
			switch strings.ToLower(filepath.Ext(path)) {
			case ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts":
			default:
				return nil
			}
			src, err := os.ReadFile(path)
			if err != nil || len(src) > 2<<20 {
				return err
			}
			tree, _ := parseRecovered(ps.forPath(path), src)
			if tree == nil {
				return nil
			}
			defer tree.Close()
			m := &sourceModule{file: path, src: src, tree: tree}
			files++
			for name, uses := range identifierNames(tree.RootNode(), src) {
				names++
				if got, want := bindingReassigned(m, name), oldBindingReassigned(m, name); got != want {
					t.Errorf("%s: bindingReassigned(%q) = %v, old walk = %v", path, name, got, want)
				}
				if got, want := contractBindingStable(m, name), oldContractBindingStable(m, name); got != want {
					t.Errorf("%s: contractBindingStable(%q) = %v, old walk = %v", path, name, got, want)
				}
				// Permitting single uses, and all uses together, exercises the escape rule.
				// The oracle walks the module per call, so single uses are capped.
				for _, use := range uses[:min(len(uses), 4)] {
					if got, want := contractBindingStable(m, name, use), oldContractBindingStable(m, name, use); got != want {
						t.Errorf("%s: contractBindingStable(%q, use@%d) = %v, old walk = %v", path, name, use.StartByte(), got, want)
					}
				}
				if got, want := contractBindingStable(m, name, uses...), oldContractBindingStable(m, name, uses...); got != want {
					t.Errorf("%s: contractBindingStable(%q, all uses) = %v, old walk = %v", path, name, got, want)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if files == 0 || names == 0 {
		t.Fatal("parity test covered no bindings")
	}
	t.Logf("checked %d identifier names in %d files", names, files)
}

// identifierNames maps every identifier text in a module to its use nodes,
// plus two names with no uses.
func identifierNames(root *sitter.Node, src []byte) map[string][]*sitter.Node {
	out := map[string][]*sitter.Node{"": nil, "undefinedNameNeverWritten": nil}
	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		if n.Kind() == "identifier" {
			out[n.Utf8Text(src)] = append(out[n.Utf8Text(src)], n)
		}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			visit(n.NamedChild(i))
		}
	}
	visit(root)
	return out
}
