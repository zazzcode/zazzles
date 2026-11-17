package lang

import "testing"

func TestDetect(t *testing.T) {
	tests := []struct {
		name string
		path string
		want Language
		ok   bool
	}{
		{"typescript", "src/handlers/user.ts", TypeScript, true},
		{"tsx", "src/components/App.tsx", TypeScript, true},
		{"esm javascript", "src/server.mjs", JavaScript, true},
		{"commonjs javascript", "lib/index.cjs", JavaScript, true},
		{"jsx", "src/App.jsx", JavaScript, true},
		{"python", "app/main.py", Python, true},
		{"php", "vulnerabilities/sqli/index.php", PHP, true},
		{"phtml", "legacy/page.phtml", PHP, true},
		{"go", "internal/walk/walk.go", Go, true},
		{"java", "src/main/java/App.java", Java, true},
		{"uppercase extension", "SRC/HANDLER.TS", TypeScript, true},
		{"markdown is unsupported", "README.md", "", false},
		{"no extension", "Makefile", "", false},
		{"dotfile", ".gitignore", "", false},
		{"empty path", "", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := Detect(tt.path)
			if ok != tt.ok || got != tt.want {
				t.Errorf("Detect(%q) = (%q, %v), want (%q, %v)", tt.path, got, ok, tt.want, tt.ok)
			}
		})
	}
}
