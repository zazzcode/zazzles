package walk

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
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

func TestWalkConfigAndTemplates(t *testing.T) {
	root := tree(t,
		"project/composer.json", "project/config/routes.yaml", "project/config/routes/admin.yaml",
		"project/config/packages/twig.yaml", "project/config/services.yaml",
		"project/config/packages/irrelevant.yaml", "project/templates/blog/card.twig",
		"project/templates/index.html", "project/var/composer.json",
		"project/var/templates/cache.twig", "project/vendor/composer.json",
		"project/vendor/templates/plugin.twig", "unrelated/templates/other.twig",
		"project/public/index.php",
	)
	got, err := Walk(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	wantConfig := []string{"project/composer.json", "project/config/packages/twig.yaml",
		"project/config/routes.yaml", "project/config/routes/admin.yaml", "project/config/services.yaml"}
	wantTemplates := []string{"project/templates/blog/card.twig"}
	if !slices.Equal(got.Config, wantConfig) || !slices.Equal(got.Templates, wantTemplates) {
		t.Fatalf("Config=%v Templates=%v", got.Config, got.Templates)
	}
	if got.Examined != 12 || got.Unsupported != 11 || !slices.Equal(paths(got.Files), []string{"project/public/index.php"}) ||
		got.ByLanguage[lang.PHP] != 1 || len(got.ByLanguage) != 1 {
		t.Fatalf("changed source inventory: %+v", got)
	}
}

func TestWalkDeployList(t *testing.T) {
	root := tree(t,
		"Dockerfile", "Dockerfile.dev", "app.dockerfile", "public/.htaccess",
		"docker/apache.conf", "docker/php.ini", "cron.d/app", "crontab",
		"project/composer.json", "project/config/packages/framework.yaml",
		"project/.env", "project/public/index.php",
		"vendor/docker/php.ini", "project/vendor/hidden.conf",
		"php.ini", "notes/php.ini",
	)
	if err := os.Symlink("apache.conf", filepath.Join(root, "docker", "link.conf")); err != nil {
		t.Fatal(err)
	}
	big := filepath.Join(root, "docker", "big.conf")
	if err := os.WriteFile(big, make([]byte, (256<<10)+1), 0o644); err != nil {
		t.Fatal(err)
	}
	// The cap is 200. Extra .htaccess files past the files above must not be listed.
	for i := 0; i < 210; i++ {
		name := filepath.Join(root, "zzz", fmtHt(i), ".htaccess")
		if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(name, []byte("Options None\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := Walk(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Dockerfile", "Dockerfile.dev", "app.dockerfile", "public/.htaccess", "docker/apache.conf", "docker/php.ini", "cron.d/app", "crontab", "php.ini"} {
		if !slices.Contains(got.Deploy, want) {
			t.Errorf("deploy missing %s in %v", want, got.Deploy)
		}
	}
	for _, banned := range got.Deploy {
		if stringsHas(banned, "vendor/") || stringsHas(banned, "link.conf") || stringsHas(banned, "big.conf") || banned == "notes/php.ini" {
			t.Errorf("deploy read %s", banned)
		}
	}
	if len(got.Deploy) != 200 || !reflect.DeepEqual(got.Truncated, []string{"deploy"}) {
		t.Fatalf("deploy cap: %d truncated %v", len(got.Deploy), got.Truncated)
	}
	if !slices.Contains(got.Unread, "docker/link.conf") || !slices.Contains(got.Unread, "docker/big.conf") {
		t.Fatalf("unread %v", got.Unread)
	}
	if !slices.Contains(got.Config, "project/composer.json") || !slices.Contains(got.Config, "project/config/packages/framework.yaml") || !slices.Contains(got.Config, "project/.env") {
		t.Fatalf("config %v", got.Config)
	}
	if !slices.Equal(paths(got.Files), []string{"project/public/index.php"}) || got.ByLanguage[lang.PHP] != 1 {
		t.Fatalf("source inventory changed: files %v lang %v", paths(got.Files), got.ByLanguage)
	}

	// An existing fixture gains no deploy files and keeps its source inventory.
	existing := filepath.Join("..", "langphp", "testdata", "symfony", "authorization")
	prev, err := Walk(existing, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(prev.Deploy) != 0 || len(prev.Files) == 0 || prev.ByLanguage[lang.PHP] == 0 {
		t.Fatalf("existing fixture deploy=%v files=%d", prev.Deploy, len(prev.Files))
	}
}

func fmtHt(i int) string {
	return "h" + strconvI(i)
}

func strconvI(i int) string {
	if i == 0 {
		return "0"
	}
	var b [8]byte
	n := len(b)
	for i > 0 {
		n--
		b[n] = byte('0' + i%10)
		i /= 10
	}
	return string(b[n:])
}

func stringsHas(s, part string) bool {
	return len(s) >= len(part) && (s == part || len(s) > 0 && contains(s, part))
}

func contains(s, part string) bool {
	for i := 0; i+len(part) <= len(s); i++ {
		if s[i:i+len(part)] == part {
			return true
		}
	}
	return false
}
