package langjs

import (
	"testing"
)

// ownAPIRepo is a Next.js page that fetches its own API route by a request
// slug and reads a file named by a field of the JSON response.
func ownAPIRepo(t *testing.T, handler string) string {
	return nextRepo(t, map[string]string{
		"lib/prisma.ts": `import { PrismaClient } from "@prisma/client";
export const prisma = new PrismaClient();
`,
		"lib/config.ts": `export function getBaseUrl() { return process.env.BASE_URL || "http://localhost:3000"; }
`,
		"app/api/flags/[slug]/route.ts": handler,
		"app/docs/[slug]/page.tsx": `import { readFile } from "fs/promises";
import { join } from "path";
import { getBaseUrl } from "@/lib/config";

async function getFlagBySlug(slug: string) {
  try {
    const baseUrl = getBaseUrl();
    const response = await fetch(` + "`${baseUrl}/api/flags/${slug}`" + `, { cache: "no-store" });
    if (!response.ok) {
      return null;
    }
    return await response.json();
  } catch (error) {
    return null;
  }
}

async function getMarkdownContent(filename: string): Promise<string> {
  const filePath = join(process.cwd(), "content", filename);
  return await readFile(filePath, "utf-8");
}

export default async function Page({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const flag = await getFlagBySlug(slug);
  if (!flag) {
    return null;
  }
  const markdown = await getMarkdownContent(flag.markdownFile);
  return <div>{markdown}</div>;
}
`,
	})
}

func TestOwnAPIResponseFieldOrigin(t *testing.T) {
	row := ownAPIRepo(t, `import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
export async function GET(request: Request, { params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const record = await prisma.flag.findUnique({ where: { slug }, select: { slug: true, markdownFile: true } });
  if (!record) {
    return NextResponse.json({ error: "Flag not found" }, { status: 404 });
  }
  return NextResponse.json(record);
}
`)
	echo := ownAPIRepo(t, `import { NextResponse } from "next/server";
export async function GET(request: Request, { params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  return NextResponse.json({ slug, markdownFile: slug });
}
`)
	for _, tt := range []struct {
		name    string
		root    string
		request bool
		storage bool
	}{
		{"row field takes the storage origin", row, false, true},
		{"echoed request value keeps the request origin", echo, true, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := analyzeNext(t, tt.root)
			uses := usesOf(r, "path_traversal_candidate", "app/docs/[slug]/page.tsx")
			if len(uses) != 1 {
				t.Fatalf("path uses: %d", len(uses))
			}
			u := uses[0]
			request, storage := false, false
			for _, d := range u.Dependencies {
				request = request || d.Source.Kind == "input_source"
				storage = storage || d.Source.Kind == "storage_read"
			}
			if request != tt.request || storage != tt.storage {
				t.Fatalf("origins %v: request=%v storage=%v gaps=%v", origins(u), request, storage, u.Gaps)
			}
			if tt.storage && !hasNextGap(blockers(u), "storage_origin_unresolved") {
				t.Fatalf("a stored row field must stay Review: %v", blockers(u))
			}
		})
	}
}
