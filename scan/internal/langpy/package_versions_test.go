package langpy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPythonPackageVersion(t *testing.T) {
	poetry := "[[package]]\nname = \"PYyaml\"\nversion = \"5.4.1\"\n"
	tests := []struct {
		name, version string
		files         map[string]string
	}{
		{"pin", "3.13", map[string]string{"requirements.txt": "PyYAML==3.13"}},
		{"extras and marker", "5.4.1", map[string]string{"requirements-dev.txt": "PY_YAML[libyaml] == 5.4.1 ; python_version > '3.8' # marker"}},
		{"poetry", "5.4.1", map[string]string{"poetry.lock": poetry}},
		{"uv", "5.4.1", map[string]string{"uv.lock": poetry}},
		{"ignores other package", "5.4.1", map[string]string{"uv.lock": "[[package]]\nname = \"other\"\nversion = \"2.1\"\n" + poetry}},
		{"nearest", "6.0.1", map[string]string{"requirements.txt": "pyyaml==3.13", "nested/requirements.txt": "pyyaml==6.0.1"}},
		{"nearest even if unknown", "", map[string]string{"requirements.txt": "pyyaml==3.13", "nested/requirements.txt": "pyyaml>=6"}},
		{"conflict", "", map[string]string{"requirements.txt": "pyyaml==3.13", "uv.lock": poetry}},
		{"duplicates", "5.4.1", map[string]string{"uv.lock": poetry + poetry}},
		{"ranges", "", map[string]string{"requirements.txt": "pyyaml<7\npyyaml>=2\npyyaml~=5.4\npyyaml==5.*\npyyaml===5.4"}},
		{"type package", "", map[string]string{"requirements.txt": "types-PyYAML==3.13"}},
		{"other manifest", "", map[string]string{"pyproject.toml": "dependencies = [\"PyYAML==5.4.1\"]", "setup.py": "requirements = ['PyYAML==5.4.1']"}},
		{"oversized", "", map[string]string{"requirements.txt": "PyYAML==3.13\n" + strings.Repeat("#", 1<<20)}},
		{"no file", "", nil},
	}
	for _, row := range tests {
		t.Run(row.name, func(t *testing.T) {
			root := t.TempDir()
			for name, source := range row.files {
				writeSource(t, root, name, source)
			}
			if err := os.MkdirAll(filepath.Join(root, "nested"), 0o755); err != nil {
				t.Fatal(err)
			}
			if got := (&pythonSet{root: root}).pyYAMLVersion("nested/call.py"); got != row.version {
				t.Errorf("version %q, want %q", got, row.version)
			}
		})
	}
	t.Run("symlink", func(t *testing.T) {
		root := t.TempDir()
		writeSource(t, root, "pin.txt", "PyYAML==3.13")
		if err := os.Symlink("pin.txt", filepath.Join(root, "requirements.txt")); err != nil {
			t.Fatal(err)
		}
		if version, found := pythonPackageVersion(root); version != "" || !found {
			t.Errorf("symlink produced %q, %v", version, found)
		}
	})
}
