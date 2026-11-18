package pipeline

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
)

var update = flag.Bool("update", false, "rewrite golden files")

func mustJSON(t *testing.T, g *analysis.RouteInventory) []byte {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(g); err != nil {
		t.Fatalf("encode: %v", err)
	}
	return buf.Bytes()
}

func TestPHPRoutes(t *testing.T) {
	g, err := Routes("../langphp/testdata/routes")
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Routes) != 2 {
		t.Fatalf("routes: %#v", g.Routes)
	}
	byPath := map[string]analysis.Route{}
	for _, r := range g.Routes {
		if r.Framework != "php" || r.Method != "" {
			t.Fatalf("unexpected route record %#v", r)
		}
		byPath[r.PathPattern] = r
	}
	if _, ok := byPath["/index.php"]; !ok {
		t.Fatalf("missing server-mapped entry: %#v", byPath)
	}
	if _, ok := byPath["/admin/login.php"]; !ok {
		t.Fatalf("missing nested entry: %#v", byPath)
	}
	g.Root = "php/routes"
	encoded := mustJSON(t, g)
	const golden = "../langphp/testdata/routes/routes.json"
	if *update {
		if err := os.WriteFile(golden, encoded, 0644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, want) {
		t.Fatal("PHP route graph differs; run -update and review")
	}
}

func TestPythonRouteGolden(t *testing.T) {
	g, err := Routes("../langpy/testdata/routes")
	if err != nil {
		t.Fatal(err)
	}
	g.Root = "python/routes"
	encoded := mustJSON(t, g)
	const golden = "../langpy/testdata/routes/routes.json"
	if *update {
		if err := os.WriteFile(golden, encoded, 0644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, want) {
		t.Fatal("Python route graph differs; run -update and review")
	}
}

// The JS/TS route content checks of this fixture live in internal/langjs's
// TestExpressLoginGolden.
func TestExpressLoginGolden(t *testing.T) {
	g, err := Routes("../langjs/testdata/express-login")
	if err != nil {
		t.Fatal(err)
	}
	g.Root = "testdata/express-login"
	encoded := mustJSON(t, g)
	const golden = "../langjs/testdata/express-login/routes.json"
	if *update {
		if err := os.WriteFile(golden, encoded, 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	if !bytes.Equal(encoded, want) {
		t.Fatalf("route inventory differs from golden\n got:\n%s\nwant:\n%s", encoded, want)
	}
}
