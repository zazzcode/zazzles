package langjs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func resolverFor(t *testing.T, files map[string]string) *moduleSet {
	t.Helper()
	root := t.TempDir()
	for name, text := range files {
		writeSource(t, root, name, text)
	}
	return &moduleSet{root: root}
}

func requireResolution(t *testing.T, s *moduleSet, file, name, version, from string) {
	t.Helper()
	got := s.resolvePackage(file, name)
	if got.Version != version || (from != "" && got.File != from) {
		t.Fatalf("%s %s: got %+v, want version %q from %q", file, name, got, version, from)
	}
}

func TestPackageVersionNearestManifest(t *testing.T) {
	s := resolverFor(t, map[string]string{
		"package.json":              `{"dependencies":{"marked":"0.3.6","ranged":"^1.0.0"}}`,
		"packages/api/package.json": `{"dependencies":{"marked":"0.3.5"}}`,
		"packages/lib/package.json": `{"dependencies":{}}`,
		"packages/web/index.js":     `x`,
	})
	requireResolution(t, s, "packages/api/src/deep/x.js", "marked", "0.3.5", "packages/api/package.json")
	requireResolution(t, s, "packages/web/index.js", "marked", "0.3.6", "package.json")
	requireResolution(t, s, "packages/lib/x.js", "marked", "0.3.6", "package.json")
	requireResolution(t, s, "server.js", "marked", "0.3.6", "package.json")
	requireResolution(t, s, "server.js", "absent", "", "")
	got := s.resolvePackage("server.js", "ranged").Version
	if _, exact := exactVersion(got); got != "^1.0.0" || exact {
		t.Fatalf("a range must stay a non-exact declaration, got %q", got)
	}
}

func TestPackageVersionWorkspaceLocks(t *testing.T) {
	t.Run("npm v3 prefers the workspace entry, then hoisted", func(t *testing.T) {
		s := resolverFor(t, map[string]string{
			"package.json":              `{"private":true,"workspaces":["packages/*"]}`,
			"packages/api/package.json": `{"dependencies":{"marked":"^0.3.0"}}`,
			"packages/web/package.json": `{"dependencies":{"marked":"^0.3.0"}}`,
			"package-lock.json": `{"lockfileVersion":3,"packages":{"node_modules/marked":{"version":"0.3.6"},
				"packages/api/node_modules/marked":{"version":"0.3.5"}}}`,
		})
		requireResolution(t, s, "packages/api/src/x.js", "marked", "0.3.5", "package-lock.json")
		requireResolution(t, s, "packages/web/x.js", "marked", "0.3.6", "package-lock.json")
	})
	t.Run("npm v1 dependencies and lock over manifest pin", func(t *testing.T) {
		s := resolverFor(t, map[string]string{
			"package.json":      `{"dependencies":{"marked":"0.3.6"}}`,
			"package-lock.json": `{"lockfileVersion":1,"dependencies":{"marked":{"version":"0.3.5"}}}`,
		})
		requireResolution(t, s, "app.js", "marked", "0.3.5", "package-lock.json")
	})
	t.Run("nearest lock wins over an ancestor lock", func(t *testing.T) {
		s := resolverFor(t, map[string]string{
			"package.json":                   `{}`,
			"package-lock.json":              `{"packages":{"node_modules/marked":{"version":"0.3.6"}}}`,
			"services/api/package.json":      `{"dependencies":{"marked":"0.3.5"}}`,
			"services/api/package-lock.json": `{"packages":{"node_modules/marked":{"version":"0.3.5"}}}`,
		})
		requireResolution(t, s, "services/api/x.js", "marked", "0.3.5", "services/api/package-lock.json")
		requireResolution(t, s, "other.js", "marked", "0.3.6", "package-lock.json")
	})
	t.Run("yarn v1 matches the declared specifier", func(t *testing.T) {
		s := resolverFor(t, map[string]string{
			"package.json":              `{}`,
			"packages/api/package.json": `{"dependencies":{"marked":"^1.0.0"}}`,
			"packages/web/package.json": `{"dependencies":{"marked":"~0.3.0"}}`,
			"packages/old/package.json": `{"dependencies":{"marked":"^2.0.0"}}`,
			"yarn.lock":                 "# yarn lockfile v1\n\n\"marked@^1.0.0\", marked@^1.1.0:\n  version \"1.2.0\"\n  resolved \"https://x\"\n\nmarked@~0.3.0:\n  version \"0.3.5\"\n",
		})
		requireResolution(t, s, "packages/api/x.js", "marked", "1.2.0", "yarn.lock")
		requireResolution(t, s, "packages/web/x.js", "marked", "0.3.5", "yarn.lock")
		if got := s.resolvePackage("packages/old/x.js", "marked").Version; got != "^2.0.0" {
			t.Fatalf("an unmatched specifier must not borrow another entry, got %q", got)
		}
	})
	t.Run("yarn ambiguity without a declaration is unknown", func(t *testing.T) {
		s := resolverFor(t, map[string]string{
			"package.json": `{}`,
			"yarn.lock":    "marked@^1.0.0:\n  version \"1.2.0\"\n\nmarked@^0.3.0:\n  version \"0.3.5\"\n\nonly@^1.0.0:\n  version \"1.0.1\"\n",
		})
		requireResolution(t, s, "app.js", "marked", "", "")
		requireResolution(t, s, "app.js", "only", "1.0.1", "yarn.lock")
	})
	t.Run("yarn berry", func(t *testing.T) {
		s := resolverFor(t, map[string]string{
			"package.json": `{"dependencies":{"marked":"^1.0.0"}}`,
			"yarn.lock":    "__metadata:\n  version: 6\n\n\"marked@npm:^1.0.0\":\n  version: 1.2.0\n  resolution: \"marked@npm:1.2.0\"\n",
		})
		requireResolution(t, s, "app.js", "marked", "1.2.0", "yarn.lock")
	})
	t.Run("pnpm importers, formats 5, 6 and 9", func(t *testing.T) {
		v9 := "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n      marked:\n        specifier: ^0.3.0\n        version: 0.3.6\n\n  packages/api:\n    dependencies:\n      '@scope/pkg':\n        specifier: ^1.0.0\n        version: 1.4.0(react@18.0.0)\n      marked:\n        specifier: ^0.3.0\n        version: 0.3.5\n    devDependencies:\n      other:\n        specifier: ^1.0.0\n        version: 1.0.0\n\npackages:\n  marked@0.3.5:\n    resolution: {integrity: x}\n"
		s := resolverFor(t, map[string]string{"package.json": `{}`, "packages/api/package.json": `{}`, "packages/web/package.json": `{}`, "pnpm-lock.yaml": v9})
		requireResolution(t, s, "packages/api/x.js", "marked", "0.3.5", "pnpm-lock.yaml")
		requireResolution(t, s, "packages/api/x.js", "@scope/pkg", "1.4.0", "pnpm-lock.yaml")
		requireResolution(t, s, "x.js", "marked", "0.3.6", "pnpm-lock.yaml")
		requireResolution(t, s, "packages/api/x.js", "other", "", "")
		// A workspace the lock does not list is not guessed from the root importer.
		requireResolution(t, s, "packages/web/x.js", "marked", "", "")

		v5 := "lockfileVersion: 5.4\n\nspecifiers:\n  marked: ^0.3.0\n\ndependencies:\n  marked: 0.3.5_react@18.0.0\n\nimporters:\n  packages/api:\n    specifiers:\n      marked: ^0.3.0\n    dependencies:\n      marked: 0.3.4\n"
		s = resolverFor(t, map[string]string{"package.json": `{}`, "packages/api/package.json": `{}`, "pnpm-lock.yaml": v5})
		requireResolution(t, s, "app.js", "marked", "0.3.5", "pnpm-lock.yaml")
		requireResolution(t, s, "packages/api/x.js", "marked", "0.3.4", "pnpm-lock.yaml")
	})
}

func TestPackageVersionBoundsAndRootCompatibility(t *testing.T) {
	t.Run("malformed lock falls back to the manifest pin", func(t *testing.T) {
		s := resolverFor(t, map[string]string{"package.json": `{"dependencies":{"marked":"0.3.6"}}`, "package-lock.json": `{not json`})
		requireResolution(t, s, "app.js", "marked", "0.3.6", "package.json")
	})
	t.Run("an unreadable workspace manifest is a barrier, not a pass-through", func(t *testing.T) {
		for _, broken := range []string{`{"dependencies":{"marked":1}}`, `{"dependencies":{"marked":"0.3.5"`} {
			s := resolverFor(t, map[string]string{"package.json": `{"dependencies":{"marked":"0.3.6"}}`, "packages/api/package.json": broken})
			requireResolution(t, s, "packages/api/x.js", "marked", "", "")
			requireResolution(t, s, "server.js", "marked", "0.3.6", "package.json")
		}
	})
	t.Run("yarn dependency lines never replace an entry's version", func(t *testing.T) {
		s := resolverFor(t, map[string]string{
			"package.json": `{"dependencies":{"foo":"^1.0.0"}}`,
			"yarn.lock":    "foo@^1.0.0:\n  version \"1.2.3\"\n  dependencies:\n    version-compare \"^1.0.0\"\n  version-compare \"^1.0.0\"\n",
		})
		requireResolution(t, s, "app.js", "foo", "1.2.3", "yarn.lock")
	})
	t.Run("oversized lock is ignored", func(t *testing.T) {
		s := resolverFor(t, map[string]string{"package.json": `{"dependencies":{"marked":"0.3.6"}}`})
		lock := `{"packages":{"node_modules/marked":{"version":"0.3.5"}}}` + strings.Repeat(" ", maxPackageFileBytes)
		if err := os.WriteFile(filepath.Join(s.root, "package-lock.json"), []byte(lock), 0o644); err != nil {
			t.Fatal(err)
		}
		requireResolution(t, s, "app.js", "marked", "0.3.6", "package.json")
	})
	t.Run("skipped directories are never read", func(t *testing.T) {
		s := resolverFor(t, map[string]string{
			"package.json":                       `{"dependencies":{"marked":"0.3.6"}}`,
			"node_modules/vendored/package.json": `{"dependencies":{"marked":"0.0.1"}}`,
			"node_modules/vendored/lib/index.js": `x`,
			"node_modules/.package-lock.json":    `{"packages":{"node_modules/marked":{"version":"0.0.1"}}}`,
		})
		requireResolution(t, s, "node_modules/vendored/lib/index.js", "marked", "0.3.6", "package.json")
	})
	t.Run("a manifest symlinked outside the root is ignored", func(t *testing.T) {
		outside := t.TempDir()
		if err := os.WriteFile(filepath.Join(outside, "package.json"), []byte(`{"dependencies":{"marked":"0.0.1"}}`), 0o644); err != nil {
			t.Fatal(err)
		}
		s := resolverFor(t, map[string]string{"package.json": `{"dependencies":{"marked":"0.3.6"}}`, "packages/api/index.js": `x`})
		if err := os.Symlink(filepath.Join(outside, "package.json"), filepath.Join(s.root, "packages", "api", "package.json")); err != nil {
			t.Skip("symlinks unavailable")
		}
		requireResolution(t, s, "packages/api/index.js", "marked", "0.3.6", "package.json")
	})
	t.Run("root-only repositories resolve as before", func(t *testing.T) {
		for _, tt := range []struct {
			name  string
			files map[string]string
			want  string
		}{
			{"lock packages", map[string]string{"package.json": `{"dependencies":{"x":"1.0.0"}}`, "package-lock.json": `{"packages":{"node_modules/x":{"version":"1.0.1"}}}`}, "1.0.1"},
			{"lock dependencies", map[string]string{"package-lock.json": `{"dependencies":{"x":{"version":"1.0.2"}}}`}, "1.0.2"},
			{"manifest pin", map[string]string{"package.json": `{"dependencies":{"x":"1.0.3"}}`}, "1.0.3"},
			{"manifest range", map[string]string{"package.json": `{"dependencies":{"x":"^1.0.3"}}`}, "^1.0.3"},
			{"devDependencies are not read", map[string]string{"package.json": `{"devDependencies":{"x":"1.0.4"}}`}, ""},
			{"nothing", map[string]string{"server.js": `x`}, ""},
		} {
			s := resolverFor(t, tt.files)
			if got := s.packageVersion("src/deep/app.js", "x"); got != tt.want {
				t.Fatalf("%s: got %q, want %q", tt.name, got, tt.want)
			}
		}
	})
}
