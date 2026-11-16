package parse

import (
	"strings"
	"testing"
)

func TestNextPhase2FlowAndEntries(t *testing.T) {
	root := nextRepo(t, map[string]string{
		"lib/handler.ts":          `export function GET(request){return new Response(request.url)}`,
		"app/api/export/route.ts": `export * from '../../../lib/handler'`,
		"pages/initial.jsx":       `function Page({input}){return <div dangerouslySetInnerHTML={{__html:input}}/>} Page.getInitialProps=async ({query})=>({input:query.input});export default Page;`,
		"pages/static.jsx":        `export async function getStaticProps(){return {props:{input:'fixed'}}}export default function Page(){return null}`,
		"pages/props.jsx":         `import Child from '../components/Child';export async function getServerSideProps({query}){return {props:{input:query.input}}}export default function Page({input}){return <Child input={input}/>}`,
		"components/Child.jsx":    `"use client";import {useEffect} from 'react';export default function Child({input}){useEffect(()=>{eval(input)},[input]);return null}`,
		"pages/api/try.js":        `export default function handler(req,res){try{const code=req.body.code;eval(code);res.end()}catch(error){res.status(500).end()}}`,
		"app/area/page.tsx":       `export default function Page(){return <p>hello</p>}`,
		"app/area/layout.tsx":     `import {headers} from 'next/headers';export default async function Layout({children}){const h=await headers();return <div dangerouslySetInnerHTML={{__html:h.get('x-html')}}/>}`,
		"prisma/schema.prisma":    "model VisitorLog {\n id String @id\n ip String\n @@map(\"visitor_logs\")\n}\n",
		"lib/db.ts":               `import {PrismaClient} from '@prisma/client';export const db=new PrismaClient();`,
		"app/api/store/route.ts":  "import {db} from '../../../lib/db';export async function POST(request){const body=await request.json();const query=`INSERT INTO visitor_logs (ip) VALUES ('${body.ip}')`;await db.$executeRawUnsafe(query);return new Response('ok')}",
		"app/stored/page.tsx":     `import {db} from '../../lib/db';export default async function Page({searchParams}){let rows;if(searchParams.q){rows=await db.visitorLog.findMany({where:{id:'a'}})}else{rows=await db.visitorLog.findMany()}return rows.map(row=><div dangerouslySetInnerHTML={{__html:row.ip}}/>)}`,
	})
	r := analyzeNext(t, root)
	for _, name := range []string{"GET /api/export", "GET /initial"} {
		if entryNamed(r, name) == nil {
			t.Errorf("missing entry %s", name)
		}
	}
	if entryNamed(r, "GET /static") != nil {
		t.Error("build-time data became an HTTP input entry")
	}
	build := false
	for _, p := range r.Practice {
		build = build || p.Check == "NEXT-BUILD"
	}
	if !build {
		t.Error("missing static observation")
	}
	for _, file := range []string{"components/Child.jsx", "pages/api/try.js"} {
		uses := usesOf(r, "code_execution_candidate", file)
		if len(uses) != 1 {
			t.Errorf("%s code uses=%d", file, len(uses))
		}
		for _, u := range uses {
			if len(u.Completeness.Blockers) > 0 {
				t.Errorf("%s blockers=%+v", file, u.Completeness.Blockers)
			}
		}
	}
	layout := false
	for _, c := range r.InvocationContexts {
		for _, ctl := range c.Controls {
			layout = layout || ctl.Evidence.Kind == "next_layout_stage"
		}
	}
	if !layout {
		t.Error("missing layout stage")
	}
	stored := usesOf(r, "xss_candidate", "app/stored/page.tsx")
	linked := false
	for _, u := range stored {
		for _, d := range u.Dependencies {
			linked = linked || d.Source.Kind == "input_source" && strings.Contains(d.Source.Span.File, "api/store")
		}
		for _, g := range u.Gaps {
			if g.Kind == "async_response_unresolved" {
				t.Error("Prisma await unresolved")
			}
		}
	}
	if !linked {
		t.Errorf("raw SQL to Prisma link absent: %+v", stored)
	}
}

func TestNextPhase2PrismaPhysicalIdentity(t *testing.T) {
	for _, tt := range []struct {
		provider, table string
		linked          bool
	}{
		{"sqlite", "Visitor_Logs", true},
		{"postgresql", "Visitor_Logs", false},
		{"postgresql", "visitor_logs", true},
	} {
		t.Run(tt.provider+"/"+tt.table, func(t *testing.T) {
			root := nextRepo(t, map[string]string{
				"prisma/schema.prisma":   "datasource db {\n provider = \"" + tt.provider + "\"\n}\nmodel VisitorLog {\n id String @id\n ip String\n @@map(\"" + tt.table + "\")\n}\n",
				"lib/db.ts":              `import {PrismaClient} from '@prisma/client';export const db=new PrismaClient();`,
				"app/api/store/route.ts": "import {db} from '../../../lib/db';export async function POST(request){const body=await request.json();await db.$executeRawUnsafe(`INSERT INTO visitor_logs (ip) VALUES ('${body.ip}')`);return new Response('ok')}",
				"app/stored/page.tsx":    `import {db} from '../../lib/db';export default async function Page(){const rows=await db.visitorLog.findMany();return rows.map(row=><div dangerouslySetInnerHTML={{__html:row.ip}}/>)}`,
			})
			r := analyzeNext(t, root)
			linked := false
			for _, u := range usesOf(r, "xss_candidate", "app/stored/page.tsx") {
				for _, d := range u.Dependencies {
					linked = linked || d.Source.Kind == "input_source" && strings.Contains(d.Source.Span.File, "api/store")
				}
			}
			if linked != tt.linked {
				t.Errorf("physical table link=%v want %v", linked, tt.linked)
			}
		})
	}
}
