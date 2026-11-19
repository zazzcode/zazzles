package parse

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
)

// TestStoredWriteCensus (AC3, W3a) covers the keys the shared census owns
// beyond SQL tables: a Prisma model read through an application's own API
// and a PHP session key. It changes no dependency, blocker or status.
func TestStoredWriteCensus(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"prisma/seed.ts":         "await prisma.product.createMany({ data: [{ name: 'Lamp', imageUrl: '/lamp.png' }] });\n",
		"app/api/admin/route.ts": "export async function POST(req) {\n  const body = await req.json();\n  await prisma.product.update({\n    where: { id: body.id },\n    data: { imageUrl: body.url },\n  });\n}\n",
		"login.php":              "<?php\n$_SESSION['user'] = $_POST['name'];\n$_SESSION['role'] = 'guest';\n",
	}
	report := &analysis.AnalysisReport{Root: root}
	for name, text := range files {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
		report.Files = append(report.Files, analysis.Evidence{Kind: "file", Span: analysis.Span{File: name}, SHA256: fmt.Sprintf("%x", sha256.Sum256([]byte(text)))})
	}
	blocker := analysis.Gap{Kind: "storage_origin_unresolved", Detail: "x"}
	read := analysis.Dependency{Source: analysis.Evidence{Kind: "storage_read", Text: "prisma.product.findUnique({ where: { id } })"}}
	session := analysis.Dependency{StorageKey: "php-session:role", Source: analysis.Evidence{Kind: "storage_source", Text: "$_SESSION['role']"}}
	report.Uses = []analysis.CandidateUse{
		{Kind: "xss_candidate", Dependencies: []analysis.Dependency{read}, Completeness: &analysis.Completeness{Blockers: []analysis.Gap{blocker}}},
		{Kind: "sql_query_candidate", Dependencies: []analysis.Dependency{session}, Completeness: &analysis.Completeness{Blockers: []analysis.Gap{blocker}}},
		{Kind: "xss_candidate", Dependencies: []analysis.Dependency{read}, Completeness: &analysis.Completeness{}},
	}
	CensusStoredWrites(report)
	KeepStoredOriginFacts(report)
	prisma := report.Uses[0].StoredOrigin
	if prisma == nil || prisma.Stores[0].Key != "prisma:product" || len(prisma.Stores[0].Writes) != 2 || prisma.Stores[0].ClosedStore != "open" {
		t.Fatalf("prisma write set: %+v", prisma)
	}
	lit := map[string]bool{}
	for _, w := range prisma.Stores[0].Writes {
		lit[w.Evidence.Span.File] = w.Literal
	}
	if !lit["prisma/seed.ts"] || lit["app/api/admin/route.ts"] {
		t.Fatalf("prisma literal flags: %+v", prisma.Stores[0].Writes)
	}
	if report.Uses[0].Dependencies[0].StorageKey != "" {
		t.Fatal("the census must not change a dependency")
	}
	s := report.Uses[1].StoredOrigin
	if s == nil || len(s.Stores[0].Writes) != 1 || !s.Stores[0].Writes[0].Literal || s.Stores[0].ClosedStore != "unknown" {
		t.Fatalf("session write set: %+v", s)
	}
	if report.Uses[2].StoredOrigin != nil {
		t.Fatal("a record with a resolved origin carries no write set")
	}
	// A file that no longer matches the snapshot is not read.
	os.WriteFile(filepath.Join(root, "login.php"), []byte("<?php\n$_SESSION['role'] = $_GET['r'];\n"), 0o644)
	report.Uses[1].StoredOrigin = nil
	CensusStoredWrites(report)
	if s := report.Uses[1].StoredOrigin; s == nil || len(s.Stores[0].Writes) != 0 {
		t.Fatalf("a changed file must not be read: %+v", s)
	}
}
