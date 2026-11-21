package walk

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/lang"
)

// tree writes a repository fixture and returns its root. Paths use forward
// slashes regardless of platform.
func tree(t *testing.T, files ...string) string {
	t.Helper()
	root := t.TempDir()
	for _, name := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
		}
		if err := os.WriteFile(path, []byte("// fixture\n"), 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
	return root
}

func paths(files []File) []string {
	out := make([]string, 0, len(files))
	for _, f := range files {
		out = append(out, f.Path)
	}
	return out
}

func TestWalkSelectsSupportedFiles(t *testing.T) {
	root := tree(t,
		"src/server.ts",
		"src/handlers/user.js",
		"src/app.py",
		"README.md",
		"Makefile",
		"node_modules/left-pad/index.js",
		".git/config",
		"dist/bundle.js",
	)

	result, err := Walk(root, Options{})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}

	want := []string{"src/app.py", "src/handlers/user.js", "src/server.ts"}
	got := paths(result.Files)
	if len(got) != len(want) {
		t.Fatalf("Files = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("Files[%d] = %q, want %q", i, got[i], want[i])
		}
	}

	if result.ByLanguage[lang.TypeScript] != 1 ||
		result.ByLanguage[lang.JavaScript] != 1 ||
		result.ByLanguage[lang.Python] != 1 {
		t.Errorf("ByLanguage = %v, want one each of typescript, javascript, python", result.ByLanguage)
	}
	// Only files outside skipped directories are considered.
	if result.Examined != 5 {
		t.Errorf("Examined = %d, want 5", result.Examined)
	}
	if result.Unsupported != 2 {
		t.Errorf("Unsupported = %d, want 2 (README.md, Makefile)", result.Unsupported)
	}
}

func TestWalkReportsSkippedDirs(t *testing.T) {
	root := tree(t, "src/a.ts", "node_modules/x/i.js", "dist/b.js")

	result, err := Walk(root, Options{})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}

	want := []string{filepath.Join(root, "dist"), filepath.Join(root, "node_modules")}
	if len(result.SkippedDirs) != len(want) {
		t.Fatalf("SkippedDirs = %v, want %v", result.SkippedDirs, want)
	}
	for i := range want {
		if result.SkippedDirs[i] != want[i] {
			t.Errorf("SkippedDirs[%d] = %q, want %q", i, result.SkippedDirs[i], want[i])
		}
	}
}

func TestWalkIsDeterministic(t *testing.T) {
	root := tree(t, "z.ts", "a.ts", "m/n.ts", "b/c/d.ts")

	first, err := Walk(root, Options{})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}

	for run := 0; run < 5; run++ {
		again, err := Walk(root, Options{})
		if err != nil {
			t.Fatalf("Walk run %d: %v", run, err)
		}
		if len(again.Files) != len(first.Files) {
			t.Fatalf("run %d: %d files, want %d", run, len(again.Files), len(first.Files))
		}
		for i := range first.Files {
			if again.Files[i] != first.Files[i] {
				t.Fatalf("run %d: Files[%d] = %+v, want %+v", run, i, again.Files[i], first.Files[i])
			}
		}
	}
}

func TestWalkExtraSkipDirs(t *testing.T) {
	root := tree(t, "src/a.ts", "fixtures/b.ts")

	result, err := Walk(root, Options{SkipDirs: []string{"fixtures"}})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}

	if got := paths(result.Files); len(got) != 1 || got[0] != "src/a.ts" {
		t.Errorf("Files = %v, want just src/a.ts", got)
	}
}

func TestWalkMissingRoot(t *testing.T) {
	if _, err := Walk(filepath.Join(t.TempDir(), "nope"), Options{}); err == nil {
		t.Fatal("Walk on a missing root returned nil error")
	}
}
