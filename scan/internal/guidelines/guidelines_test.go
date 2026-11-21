package guidelines

import (
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/lang"
)

func TestAnalysisGuidelines(t *testing.T) {
	js, ok := Body(lang.TypeScript)
	if !ok || js.ID != "javascript" || js.Version != "5" || !strings.Contains(js.Body, "Free text") || !strings.Contains(js.Body, "## Logging") {
		t.Fatalf("javascript analysis guidelines=%+v", js)
	}
	if _, ok := Body(lang.JavaScript); !ok {
		t.Fatal("javascript files do not share the typescript analysis guidelines")
	}
	py, ok := Body(lang.Python)
	if !ok || py.ID != "python" || !strings.Contains(py.Body, "DB-API") {
		t.Fatalf("python analysis guidelines=%+v", py)
	}
	g, ok := Body(lang.Go)
	if !ok || g.ID != "go" || !strings.Contains(g.Body, "database/sql") {
		t.Fatalf("go analysis guidelines=%+v", g)
	}
	if _, ok := Body(lang.Java); ok {
		t.Fatal("java has no analysis guidelines pack")
	}
	got := ForPaths([]string{"src/server.ts", "handler.js", "app.py"})
	if len(got) != 2 || got[0].ID != "javascript" || got[1].ID != "python" || got[0].Body != "" {
		t.Fatalf("paths=%+v", got)
	}
}
