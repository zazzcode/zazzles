package langpy

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	sitter "github.com/tree-sitter/go-tree-sitter"
)

// TestPythonMountIndexParity checks that the per-module mount-call index yields,
// for each caller's own filter, exactly the nodes the whole-module walk did.
func TestPythonMountIndexParity(t *testing.T) {
	roots, _ := filepath.Glob("testdata/*")
	roots = append(roots, "../parse/testdata/mixed/three-language")
	if root := os.Getenv("ZAZZLES_VULNPY"); root != "" {
		roots = append(roots, root)
	}
	filters := map[string]func(*pythonModule, *sitter.Node) bool{
		"mountPrefix": func(m *pythonModule, n *sitter.Node) bool {
			if n.Kind() != "call" {
				return false
			}
			fn := pyText(m, n.ChildByFieldName("function"))
			return strings.HasSuffix(fn, ".register_blueprint") || strings.HasSuffix(fn, ".include_router")
		},
		"dynamicMounts": func(m *pythonModule, n *sitter.Node) bool {
			if n.Kind() != "call" {
				return false
			}
			fn := n.ChildByFieldName("function")
			if fn == nil || fn.Kind() != "attribute" {
				return false
			}
			method := pyText(m, fn.ChildByFieldName("attribute"))
			return method == "register_blueprint" || method == "include_router"
		},
	}
	modules, mounts := 0, 0
	for _, root := range roots {
		if info, err := os.Stat(root); err != nil || !info.IsDir() {
			continue
		}
		py, err := newPythonSet(root)
		if err != nil {
			t.Fatal(err)
		}
		for _, file := range py.files {
			m := py.modules[file]
			if m == nil {
				continue
			}
			modules++
			mounts += len(m.mountCalls())
			for name, keep := range filters {
				var walked, indexed []*sitter.Node
				pyWalk(m.tree.RootNode(), func(n *sitter.Node) {
					if keep(m, n) {
						walked = append(walked, n)
					}
				})
				for _, n := range m.mountCalls() {
					if keep(m, n) {
						indexed = append(indexed, n)
					}
				}
				if !slices.EqualFunc(walked, indexed, func(a, b *sitter.Node) bool { return a.Id() == b.Id() }) {
					t.Errorf("%s %s (%s filter): index yields %d nodes, walk yields %d", root, file, name, len(indexed), len(walked))
				}
			}
		}
		py.close()
	}
	if modules == 0 {
		t.Fatal("parity test covered no Python modules")
	}
	t.Logf("checked %d Python modules, %d indexed mount calls", modules, mounts)
}
