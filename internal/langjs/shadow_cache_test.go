package langjs

import (
	"github.com/zazzcode/zazzles/internal/lang"
	"github.com/zazzcode/zazzles/internal/walk"
	"os"
	"strings"
	"testing"

	sitter "github.com/tree-sitter/go-tree-sitter"
)

func TestShadowCacheParity(t *testing.T) {
	roots := shadowFixtureRoots(t)
	if sample := os.Getenv("ZAZZLES_JUICE_SHOP"); sample != "" {
		roots = append(roots, sample)
	}
	count := 0
	for _, root := range roots {

		manifest, err := walk.Walk(root, walk.Options{})
		if err != nil {
			t.Fatal(err)
		}
		ps, err := newParsers()
		if err != nil {
			t.Fatal(err)
		}
		s := &moduleSet{root: root, parsers: ps, modules: map[string]*sourceModule{}, allowed: map[string]bool{}}
		var files []string
		for _, file := range manifest.Files {
			if file.Language == lang.JavaScript || file.Language == lang.TypeScript {
				files = append(files, file.Path)
				s.allowed[file.Path] = true
			}
		}

		for _, file := range files {
			m, err := s.load(file)
			if err != nil {
				t.Fatal(err)
			}
			if m == nil {
				continue
			}
			walkCalls(m.tree.RootNode(), func(n *sitter.Node) {
				fn := n.ChildByFieldName("function")
				if fn == nil {
					return
				}
				name := strings.Split(fn.Utf8Text(m.src), ".")[0]
				want := shadowed(n, name, m.src)
				for range 2 {
					if got := m.cachedShadowed(n, name); got != want {
						t.Fatalf("%s:%d %s got %v want %v", file, n.StartByte(), name, got, want)
					}
				}
				count++
			})
		}
		s.close()
	}
	if count == 0 {
		t.Fatal("no shadow queries")
	}
	t.Logf("%d fixture/sample call queries checked twice", count)
}
