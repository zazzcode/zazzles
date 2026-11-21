package langjs

import (
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

// TestNamedReadFileContentOrigin gives a named fs import's readFile result the
// same file_read origin as fs.readFile (phase 5). The request-derived path stays
// a path-traversal operand; the file content is not the request value.
func TestNamedReadFileContentOrigin(t *testing.T) {
	t.Run("express readFileSync", func(t *testing.T) {
		file, src := conditionalHandler("js", "const { readFileSync } = require('fs');const path=require('path');",
			"res.send(readFileSync(path.join('/srv', req.query.name)));")
		r := conditionalReport(t, file, src)
		assertFileOrigin(t, usesOfKind(r, "xss_candidate"))
		if len(usesOfKind(r, "path_traversal_candidate")) != 1 {
			t.Fatal("the request path must stay a path_traversal_candidate")
		}
	})
	t.Run("next readFile", func(t *testing.T) {
		f := "app/api/u/[...path]/route.ts"
		r := analyzeNext(t, nextRepo(t, map[string]string{f: `import { NextResponse } from 'next/server';
import { readFile } from 'fs/promises';
import { join } from 'path';
const TYPES: Record<string, string> = { '.svg': 'image/svg+xml' };
export async function GET(request: Request, { params }: { params: Promise<{ path: string[] }> }) {
  const { path } = await params;
  const name = path.join('/');
  const buf = await readFile(join(process.cwd(), 'uploads', name));
  return new NextResponse(buf, { headers: { 'Content-Type': TYPES[name.slice(name.lastIndexOf('.'))] } });
}`}))
		uses := usesOf(r, "xss_candidate", f)
		assertFileOrigin(t, uses)
		if b := blockers(uses[0]); len(b) == 0 {
			t.Fatal("file content with an unresolved type must stay Review")
		}
	})
}

func assertFileOrigin(t *testing.T, uses []analysis.CandidateUse) {
	t.Helper()
	if len(uses) != 1 {
		t.Fatalf("want one xss_candidate, got %d", len(uses))
	}
	for _, d := range uses[0].Dependencies {
		if d.Source.Kind != "file_read" {
			t.Fatalf("content origin = %s, want file_read", d.Source.Kind)
		}
	}
}
