package langjs

import (
	"strings"
	"testing"
)

func typeMapRoute(types, extra, check string) string {
	return `import { NextRequest, NextResponse } from "next/server";
import { readFile } from "fs/promises";
import { join } from "path";

const MIME_TYPES: Record<string, string> = {
` + types + `
};
` + extra + `
export async function GET(_request: NextRequest, { params }: { params: Promise<{ path: string[] }> }) {
  const { path } = await params;
  const filename = path.join("/");
  const filepath = join(process.cwd(), "uploads", filename);
  const ext = filename.substring(filename.lastIndexOf(".")).toLowerCase();
  const contentType = MIME_TYPES[ext];
` + check + `
  const fileBuffer = await readFile(filepath);
  return new NextResponse(fileBuffer, { headers: { "Content-Type": contentType } });
}
`
}

func TestClosedContentTypeMap(t *testing.T) {
	raster := `  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".gif": "image/gif",`
	reject := `  if (!contentType) {
    return NextResponse.json({ error: "Unsupported file type" }, { status: 400 });
  }`
	for _, tt := range []struct {
		name, types, extra, check string
		record                    bool
	}{
		{"raster-only closed map", raster, "", reject, false},
		{"map with SVG", raster + "\n  \".svg\": \"image/svg+xml\",", "", reject, true},
		{"mutated map", raster, `export function allow(ext: string, type: string) { MIME_TYPES[ext] = type; }`, reject, true},
		{"no missing-key return", raster, "", "", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := nextRepo(t, map[string]string{"app/api/uploads/[...path]/route.ts": typeMapRoute(tt.types, tt.extra, tt.check)})
			uses := usesOf(analyzeNext(t, root), "xss_candidate", "app/api/uploads/[...path]/route.ts")
			if (len(uses) > 0) != tt.record {
				t.Fatalf("xss records %d, want record=%v", len(uses), tt.record)
			}
			for _, u := range uses {
				if !hasNextGap(blockers(u), "render_protection_unresolved") {
					t.Fatalf("an unresolved type must stay Review: %v", blockers(u))
				}
				if tt.name == "map with SVG" && !hasNextGap(u.Gaps, "content_type_map_html_capable") {
					t.Fatalf("SVG map gap missing: %v", u.Gaps)
				}
				if tt.name != "map with SVG" && strings.Contains(u.Sink.Text, "x") && hasNextGap(u.Gaps, "content_type_map_html_capable") {
					t.Fatal("an open map was treated as closed")
				}
			}
		})
	}
}
