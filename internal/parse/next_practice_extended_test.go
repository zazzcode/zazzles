package parse

import "testing"

func TestNextPracticeExtended(t *testing.T) {
	for _, tt := range []struct{ name, check, file, bad, good string }{
		{"action", "NX-BP-09", "app/actions.ts", `"use server"; import {PrismaClient} from '@prisma/client';const db=new PrismaClient();export async function save(email){return db.user.create({data:{email}})}`, `"use server"; import {PrismaClient} from '@prisma/client';import {z} from 'zod';const db=new PrismaClient();const Schema=z.object({email:z.string().email()});export async function save(input){const data=Schema.parse(input);return db.user.create({data})}`},
		{"cookie", "NX-BP-11", "app/api/x/route.ts", `import {cookies} from 'next/headers';export async function GET(){const jar=await cookies();jar.set('session','x');return new Response('ok')}`, `import {cookies} from 'next/headers';export async function GET(){const jar=await cookies();jar.set('session','x',{httpOnly:true,secure:true,sameSite:'strict'});return new Response('ok')}`},
		{"image", "NX-BP-13", "next.config.js", `module.exports={images:{remotePatterns:[{hostname:'**'}],dangerouslyAllowSVG:true}}`, `module.exports={images:{remotePatterns:[{hostname:'images.example'}],dangerouslyAllowSVG:true,contentSecurityPolicy:"default-src 'none'"}}`},
		{"origin", "NX-BP-14", "next.config.js", `module.exports={experimental:{serverActions:{allowedOrigins:['*.example']}}}`, `module.exports={experimental:{serverActions:{allowedOrigins:['app.example']}}}`},
		{"cache", "NX-BP-15", "app/page.tsx", `import {cookies} from 'next/headers';export const dynamic='force-static';export default async function Page(){const c=await cookies();return <p>{c.get('user')}</p>}`, `import {cookies} from 'next/headers';export const dynamic='force-dynamic';export default async function Page(){const c=await cookies();return <p>{c.get('user')}</p>}`},
		{"response", "NX-BP-18", "app/api/x/route.ts", `import {NextResponse} from 'next/server';export function GET(){return NextResponse.json({email:'a@example',passwordHash:'x'})}`, `import {NextResponse} from 'next/server';export function GET(){return NextResponse.json({id:'1',title:'public'})}`},
		{"message", "NX-BP-21", "app/page.tsx", `"use client";export default function Page(){window.addEventListener('message',event=>{document.body.innerHTML=event.data});window.postMessage({token:'x'},'*');return null}`, `"use client";export default function Page(){window.addEventListener('message',event=>{if(event.origin!=='https://trusted.example')return;document.body.innerHTML=event.data});window.postMessage({token:'x'},'https://trusted.example');return null}`},
		{"admin", "NX-BP-22", "app/page.tsx", `"use client";export default function Page(){if(localStorage.getItem('role')==='admin'){fetch('/api/admin')}return null}`, `"use client";export default function Page(){fetch('/api/admin');return null}`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			for _, safe := range []bool{false, true} {
				source := tt.bad
				if safe {
					source = tt.good
				}
				files := map[string]string{tt.file: source}
				if tt.file == "next.config.js" {
					files["app/page.tsx"] = `export default function Page(){return <p>Hello</p>}`
				}
				r := analyzeNext(t, nextRepo(t, files))
				found := false
				for _, p := range r.Practice {
					found = found || p.Check == tt.check
				}
				if found == safe {
					t.Errorf("safe=%v found %s=%v; practice=%+v", safe, tt.check, found, r.Practice)
				}
			}
		})
	}
}

func TestNextCookieBindingAndSensitiveProjection(t *testing.T) {
	r := analyzeNext(t, nextRepo(t, map[string]string{
		"prisma/schema.prisma":  "model User {\n id String @id\n email String\n passwordHash String\n}\n",
		"app/api/good/route.ts": `import {NextResponse} from 'next/server';import {PrismaClient} from '@prisma/client';const db=new PrismaClient();export async function GET(){const rows=await db.user.findMany({select:{id:true}});const foo={cookies:{set(){}}};foo.cookies.set('x','y');return NextResponse.json(rows)}`,
		"app/api/bad/route.ts":  `import {NextResponse} from 'next/server';import {PrismaClient} from '@prisma/client';const db=new PrismaClient();export async function GET(){return NextResponse.json(await db.user.findMany())}`,
	}))
	found := false
	for _, p := range r.Practice {
		if p.Check == "NX-BP-11" {
			t.Errorf("unverified cookie receiver: %+v", p)
		}
		if p.Check == "NX-BP-18" {
			found = true
			for _, e := range p.Evidence {
				if e.Span.File == "app/api/good/route.ts" {
					t.Error("public projection marked sensitive")
				}
			}
		}
	}
	if !found {
		t.Error("missing whole sensitive row observation")
	}
}
