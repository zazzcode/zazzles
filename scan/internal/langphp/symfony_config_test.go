package langphp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSymfonyConfig(t *testing.T) {
	fixture := filepath.Join("testdata", "symfony", "config")
	for _, tc := range []struct {
		id, name, literal string
		configuration     bool
	}{
		{"CF-05", "dir", "/public/up", false},
		{"CF-06", "prod_only", "", true},
	} {
		t.Run(tc.id, func(t *testing.T) {
			s, err := newPHPSet(fixture)
			if err != nil {
				t.Fatal(err)
			}
			defer s.close()
			p := s.symfonyProjectOf("src/Controller/A.php")
			got, ok := p.parameter(tc.name)
			if !ok || got.literal != tc.literal || got.configuration != tc.configuration {
				t.Fatalf("parameter %q: %+v, present=%v", tc.name, got, ok)
			}
			if tc.id == "CF-05" && !p.servedPath(got.literal) {
				t.Fatalf("parameter does not point to served content: %q", got.literal)
			}
		})
	}
	for _, tc := range []struct {
		id, file, contents string
		symlink            bool
	}{
		{"CF-01", "", "", false},
		{"CF-02", "config/services.yaml", "services:\n\tbroken: true\n", false},
		{"CF-03", "config/services.yaml", strings.Repeat("#", 2<<20), false},
		{"CF-04", "config/routes.yaml", "", true},
		{"CF-07", "composer.json", `{"require":{"symfony/framework-bundle":"^6.4"},"extra":{"public-dir":"web"}}`, false},
		{"CF-08", "", "", false},
	} {
		t.Run(tc.id, func(t *testing.T) {
			root := fixture
			if tc.file != "" {
				root = t.TempDir()
				if err := os.CopyFS(root, os.DirFS(fixture)); err != nil {
					t.Fatal(err)
				}
				target := filepath.Join(root, tc.file)
				if tc.symlink {
					if err := os.Rename(target, target+".original"); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(target+".original", target); err != nil {
						t.Fatal(err)
					}
				} else if err := os.WriteFile(target, []byte(tc.contents), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			report, err := Analyze(root, "")
			if err != nil {
				t.Fatal(err)
			}
			var gapFound bool
			for _, gap := range report.Gaps {
				if gap.Kind == "symfony_config_unread" {
					if gap.At.File != tc.file {
						t.Fatalf("unexpected unread file %q", gap.At.File)
					}
					gapFound = true
				}
			}
			if gapFound != (tc.file != "" && tc.id != "CF-07") {
				t.Fatalf("unexpected config gaps: %+v", report.Gaps)
			}
			if tc.id == "CF-02" {
				s, err := newPHPSet(root)
				if err != nil {
					t.Fatal(err)
				}
				defer s.close()
				resolved := s.resolveReference(s.modules["src/Controller/A.php"], `App\Demo::label`)
				if resolved.Kind != "psr4" || resolved.Target == nil || resolved.Target.module.file != "src/Demo.php" {
					t.Fatalf("malformed config blocked PSR-4: %+v", resolved)
				}
			}
			if tc.id == "CF-07" {
				files := map[string]bool{}
				for _, entry := range report.Entries {
					files[entry.Name] = true
				}
				if !files["FILE /web/index.php"] || files["FILE /public/index.php"] {
					t.Fatalf("document-root entries: %v", files)
				}
			}
			for _, entry := range report.Entries {
				if strings.HasPrefix(entry.Name, "FILE /var/") {
					t.Fatalf("cache exposed as entry: %s", entry.Name)
				}
				if entry.Name != "ANY /mixed" {
					continue
				}
				if tc.id == "CF-04" && !hasSymfonyGap(entry.Gaps, "symfony_config_unread") {
					t.Fatalf("route is missing its unread configuration gap: %+v", entry)
				}
				for _, binding := range report.DispatchBindings {
					if binding.EntryID == entry.ID && binding.Resolution == "resolved" {
						return
					}
				}
				t.Fatal("attribute route did not resolve")
			}
			t.Fatal("attribute route missing")
		})
	}
}
