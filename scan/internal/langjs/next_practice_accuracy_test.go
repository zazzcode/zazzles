package langjs

import (
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

func practiceAccuracyObservations(r *analysis.AnalysisReport, check string) []analysis.PracticeObservation {
	var got []analysis.PracticeObservation
	for _, p := range r.Practice {
		if p.Check == check {
			got = append(got, p)
		}
	}
	return got
}

func assertPracticeAccuracy(t *testing.T, r *analysis.AnalysisReport, check string, want bool) {
	t.Helper()
	got := len(practiceAccuracyObservations(r, check)) > 0
	if got != want {
		t.Errorf("%s observation=%v want=%v; observations=%+v", check, got, want, practiceAccuracyObservations(r, check))
	}
}

// These seven exact source probes were promoted from the research runner. Keep
// their source and expected semantics unchanged as implementation regressions.
func TestPracticeAccuracyResearchProbes(t *testing.T) {
	for _, tt := range []struct {
		name, check string
		files       map[string]string
		want        bool
	}{
		{"cookie_composed_safe", "NX-BP-11", map[string]string{"app/api/x/route.ts": `import {cookies} from 'next/headers';export async function GET(){const defaults={httpOnly:true,secure:true,sameSite:'strict'};const jar=await cookies();jar.set('session','x',{...defaults});return new Response('ok')}`}, false},
		{"cookie_override_unsafe", "NX-BP-11", map[string]string{"app/api/x/route.ts": `import {cookies} from 'next/headers';export async function GET(){const insecure={secure:false};const jar=await cookies();jar.set('session','x',{httpOnly:true,secure:true,sameSite:'strict',...insecure});return new Response('ok')}`}, true},
		{"message_comparison_unused", "NX-BP-21", map[string]string{"app/page.tsx": `"use client";export default function Page(){window.addEventListener('message',event=>{const trusted=event.origin==='https://trusted.example';document.body.innerHTML=event.data});return null}`}, true},
		{"message_comparison_after_use", "NX-BP-21", map[string]string{"app/page.tsx": `"use client";export default function Page(){window.addEventListener('message',event=>{document.body.innerHTML=event.data;if(event.origin!=='https://trusted.example')return});return null}`}, true},
		{"cache_identity_name_only", "NX-BP-15", map[string]string{"app/page.tsx": `import {cookies} from 'next/headers';import {unstable_cache} from 'next/cache';export default async function Page(){const jar=await cookies();const user='global';const get=unstable_cache(async()=>jar.get('session')?.value,[user]);return <p>{await get()}</p>}`}, true},
		{"cache_public_unrelated", "NX-BP-15", map[string]string{"app/page.tsx": `import {cookies} from 'next/headers';export default async function Page(){const jar=await cookies();const catalog=await fetch('https://example.com/catalog',{cache:'force-cache'});return <p>{jar.get('session')?.value}</p>}`}, false},
		{"admin_ignored_auth", "NX-BP-22", map[string]string{"app/page.tsx": `"use client";export default function Page(){if(localStorage.getItem('role')==='admin'){fetch('/api/admin')}return null}`, "app/api/admin/route.ts": `import {auth} from './auth';export async function GET(){await auth();return Response.json({secret:'x'})}`}, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			assertPracticeAccuracy(t, analyzeNext(t, nextRepo(t, tt.files)), tt.check, tt.want)
		})
	}
}

func TestPracticeAccuracyCookieOptionResolution(t *testing.T) {
	for _, tt := range []struct {
		name, options string
		want          bool
	}{
		{"ordered_safe_spread", `const defaults={httpOnly:true,secure:true,sameSite:'strict'};jar.set('session','x',{...defaults})`, false},
		{"later_safe_override", `const defaults={httpOnly:true,secure:false,sameSite:'strict'};jar.set('session','x',{...defaults,secure:true})`, false},
		{"later_unsafe_override", `const defaults={httpOnly:true,secure:true,sameSite:'strict'};const override={secure:false};jar.set('session','x',{...defaults,...override})`, true},
		{"immutable_alias", `const safe={httpOnly:true,secure:true,sameSite:'strict'};const alias=safe;jar.set('session','x',alias)`, false},
		{"unknown_spread", `const options=getCookieOptions();jar.set('session','x',{httpOnly:true,...options})`, true},
		{"mutated_options", `const options={httpOnly:true,secure:true,sameSite:'strict'};options.secure=false;jar.set('session','x',options)`, true},
		{"aliased_mutated_options", `const options={httpOnly:true,secure:true,sameSite:'strict'};const alias=options;alias.secure=false;jar.set('session','x',options)`, true},
		{"deleted_option", `const options={httpOnly:true,secure:true,sameSite:'strict'};delete options.secure;jar.set('session','x',options)`, true},
		{"mutated_by_object_assign", `const options={httpOnly:true,secure:true,sameSite:'strict'};Object.assign(options,{secure:false});jar.set('session','x',options)`, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			source := `import {cookies} from 'next/headers';export async function GET(){const jar=await cookies();` + tt.options + `;return new Response('ok')}`
			assertPracticeAccuracy(t, analyzeNext(t, nextRepo(t, map[string]string{"app/api/x/route.ts": source})), "NX-BP-11", tt.want)
		})
	}
}

func TestPracticeAccuracyMessageOriginEnforcement(t *testing.T) {
	for _, tt := range []struct {
		name, body string
		want       bool
	}{
		{"early_reject", `if(event.origin!=='https://trusted.example')return;document.body.innerHTML=event.data`, false},
		{"use_only_on_accepting_branch", `if(event.origin==='https://trusted.example'){document.body.innerHTML=event.data}`, false},
		{"unused_boolean", `const trusted=event.origin==='https://trusted.example';document.body.innerHTML=event.data`, true},
		{"check_after_sink", `document.body.innerHTML=event.data;if(event.origin!=='https://trusted.example')return`, true},
		{"nested_guard_does_not_gate", `function check(){if(event.origin!=='https://trusted.example')return false;return true}document.body.innerHTML=event.data`, true},
		{"mutated_event", `event={origin:'https://trusted.example',data:event.data};if(event.origin!=='https://trusted.example')return;document.body.innerHTML=event.data`, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			source := `"use client";export default function Page(){window.addEventListener('message',event=>{` + tt.body + `});return null}`
			r := analyzeNext(t, nextRepo(t, map[string]string{"app/page.tsx": source}))
			assertPracticeAccuracy(t, r, "NX-BP-21", tt.want)
			if tt.want {
				for _, p := range practiceAccuracyObservations(r, "NX-BP-21") {
					if !strings.Contains(p.Detail, "origin") || len(p.Evidence) == 0 || p.Evidence[0].Span.File != "app/page.tsx" {
						t.Errorf("expected listener-scoped origin evidence, got %+v", p)
					}
				}
			}
		})
	}
}

func TestPracticeAccuracyCacheIdentityAndScope(t *testing.T) {
	for _, tt := range []struct {
		name, page string
		want       bool
	}{
		{"identity_argument_alias_in_effective_key", `import {cookies} from 'next/headers';import {unstable_cache} from 'next/cache';import {db} from '@/db';export default async function Page(){const jar=await cookies();const userId=jar.get('user')!.value;const identity=userId;const get=unstable_cache(async (id)=>db.user.findUnique({where:{id}}),['profile']);return <p>{(await get(identity))?.email}</p>}`, false},
		{"exact_cookie_value_used_and_keyed", `import {cookies} from 'next/headers';import {unstable_cache} from 'next/cache';export default async function Page(){const jar=await cookies();const session=jar.get('session')?.value;const get=unstable_cache(async()=>jar.get('session')?.value,[session]);return <p>{await get()}</p>}`, false},
		{"name_only_constant_key", `import {cookies} from 'next/headers';import {unstable_cache} from 'next/cache';export default async function Page(){const jar=await cookies();const user='global';const get=unstable_cache(async()=>jar.get('session')?.value,[user]);return <p>{await get()}</p>}`, true},
		{"different_cookie_key", `import {cookies} from 'next/headers';import {unstable_cache} from 'next/cache';export default async function Page(){const jar=await cookies();const locale=jar.get('locale')?.value;const get=unstable_cache(async()=>jar.get('session')?.value,[locale]);return <p>{await get()}</p>}`, true},
		{"whole_cookie_jar_key", `import {cookies} from 'next/headers';import {unstable_cache} from 'next/cache';export default async function Page(){const jar=await cookies();const get=unstable_cache(async()=>jar.get('session')?.value,[jar]);return <p>{await get()}</p>}`, true},
		{"unknown_cache_callback", `import {cookies} from 'next/headers';import {unstable_cache} from 'next/cache';import {loadProfile} from '@/profile';export default async function Page(){const jar=await cookies();const session=jar.get('session')?.value;const get=unstable_cache(loadProfile,['profile']);return <p>{(await get())?.email}</p>}`, true},
		{"public_fetch_next_to_cookie_read", `import {cookies} from 'next/headers';export default async function Page(){const jar=await cookies();const catalog=await fetch('https://example.com/catalog',{cache:'force-cache'});return <p>{jar.get('session')?.value}{catalog.status}</p>}`, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			assertPracticeAccuracy(t, analyzeNext(t, nextRepo(t, map[string]string{"app/page.tsx": tt.page})), "NX-BP-15", tt.want)
		})
	}
}

func TestPracticeAccuracyServerActionArgumentUse(t *testing.T) {
	for _, tt := range []struct {
		name, action string
		want         bool
	}{
		{"raw_action_argument", `"use server";import {PrismaClient} from '@prisma/client';const db=new PrismaClient();export async function update(email){return db.user.update({where:{id:'fixed-user'},data:{email}})}`, true},
		{"validator_result_ignored", `"use server";import {PrismaClient} from '@prisma/client';import {z} from 'zod';const db=new PrismaClient();const Email=z.string().email();export async function update(email){Email.parse(email);return db.user.update({where:{id:'fixed-user'},data:{email}})}`, true},
		{"validated_exact_argument", `"use server";import {PrismaClient} from '@prisma/client';import {z} from 'zod';const db=new PrismaClient();const Email=z.string().email();export async function update(email){const validated=Email.parse(email);return db.user.update({where:{id:'fixed-user'},data:{email:validated}})}`, false},
		{"unvalidated_sibling_argument", `"use server";import {PrismaClient} from '@prisma/client';import {z} from 'zod';const db=new PrismaClient();const Email=z.string().email();export async function update(email,id){const validated=Email.parse(email);return db.user.update({where:{id},data:{email:validated}})}`, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := analyzeNext(t, nextRepo(t, map[string]string{"app/actions.ts": tt.action}))
			assertPracticeAccuracy(t, r, "NX-BP-09", tt.want)
			if tt.want {
				for _, p := range practiceAccuracyObservations(r, "NX-BP-09") {
					if len(p.Evidence) == 0 || p.Evidence[0].Span.File != "app/actions.ts" {
						t.Errorf("expected action-use evidence, got %+v", p)
					}
				}
			}
		})
	}
}

func TestPracticeAccuracyConfigBoundaries(t *testing.T) {
	for _, tt := range []struct {
		name, config   string
		want13, want14 bool
	}{
		{"explicit_restrictive", `const imageHost='images.example';module.exports={images:{remotePatterns:[{hostname:imageHost}],dangerouslyAllowSVG:true,contentSecurityPolicy:"default-src 'none'"},experimental:{serverActions:{allowedOrigins:['app.example']}}}`, false, false},
		{"broad_values", `module.exports={images:{remotePatterns:[{hostname:'**.example.com'}],dangerouslyAllowSVG:true},experimental:{serverActions:{allowedOrigins:['*.example.com']}}}`, true, true},
		{"unresolved_composition", `const imagePolicy=getImagePolicy();const actionPolicy=getActionPolicy();module.exports={images:imagePolicy,experimental:{serverActions:actionPolicy}}`, true, true},
		{"unknown_spreads_can_override_restrictive_literals", `const imageExtras=getImagePolicy();const actionExtras=getActionPolicy();module.exports={images:{remotePatterns:[{hostname:'images.example'}],...imageExtras},experimental:{serverActions:{allowedOrigins:['app.example'],...actionExtras}}}`, true, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := analyzeNext(t, nextRepo(t, map[string]string{"next.config.js": tt.config, "app/page.tsx": `export default function Page(){return <p>ok</p>}`}))
			assertPracticeAccuracy(t, r, "NX-BP-13", tt.want13)
			assertPracticeAccuracy(t, r, "NX-BP-14", tt.want14)
		})
	}
}

func TestPracticeAccuracySensitiveResponseProjection(t *testing.T) {
	files := map[string]string{
		"prisma/schema.prisma":    "model User {\n id String @id\n email String\n passwordHash String\n profile Profile?\n}\nmodel Profile {\n id String @id\n phone String\n displayName String\n}\n",
		"app/api/whole/route.ts":  `import {NextResponse} from 'next/server';import {PrismaClient} from '@prisma/client';const db=new PrismaClient();export async function GET(){return NextResponse.json(await db.user.findMany())}`,
		"app/api/public/route.ts": `import {NextResponse} from 'next/server';import {PrismaClient} from '@prisma/client';const db=new PrismaClient();export async function GET(){return NextResponse.json(await db.user.findMany({select:{id:true}}))}`,
		"app/api/nested/route.ts": `import {NextResponse} from 'next/server';import {PrismaClient} from '@prisma/client';const db=new PrismaClient();export async function GET(){const rows=await db.user.findMany({include:{profile:true}});return NextResponse.json({data:rows})}`,
		"app/actions.ts":          `"use server";import {PrismaClient} from '@prisma/client';const db=new PrismaClient();export async function load(){return db.user.findMany()}`,
		"app/client.tsx":          `"use client";export function Client({user}:{user:any}){return <span>{user.email}</span>}`,
		"app/page.tsx":            `import {PrismaClient} from '@prisma/client';import {Client} from './client';const db=new PrismaClient();export default async function Page(){const user=await db.user.findFirst();return <Client user={user}/>} `,
	}
	r := analyzeNext(t, nextRepo(t, files))
	byFile := map[string]bool{}
	for _, p := range practiceAccuracyObservations(r, "NX-BP-18") {
		for _, e := range p.Evidence {
			byFile[e.Span.File] = true
		}
	}
	for _, file := range []string{"app/api/whole/route.ts", "app/api/nested/route.ts", "app/actions.ts", "app/page.tsx"} {
		if !byFile[file] {
			t.Errorf("NX-BP-18 missing sensitive whole/nested/action/client-prop evidence at %s; observations=%+v", file, practiceAccuracyObservations(r, "NX-BP-18"))
		}
	}
	if byFile["app/api/public/route.ts"] {
		t.Error("explicit public field projection was reported as sensitive")
	}
}

func TestPracticeAccuracyClientAuthorizationRequestPairing(t *testing.T) {
	for _, tt := range []struct {
		name, server string
		want         bool
	}{
		{"server_enforces_admin_role", `import {getServerSession as auth} from 'next-auth';export async function GET(){const session=await auth();if(session?.user?.role!=='admin')return Response.json({error:'forbidden'},{status:403});return Response.json({secret:'x'})}`, false},
		{"session_alias_mutation", `import {getServerSession as auth} from 'next-auth';export async function GET(){const session=await auth();if(session?.user?.role!=='admin')return Response.json({error:'forbidden'},{status:403});const alias=session;alias.user.role='guest';await deleteAllUsers();return Response.json({secret:'x'})}`, true},
		{"auth_call_only", `import {auth} from '@/auth';export async function GET(){await auth();return Response.json({secret:'x'})}`, true},
		{"auth_result_ignored", `import {auth} from '@/auth';export async function GET(){const session=await auth();return Response.json({secret:'x'})}`, true},
		{"admin_check_after_operation", `import {auth} from '@/auth';export async function GET(){const session=await auth();const result=await readSecret();if(session?.user?.role!=='admin')return Response.json({error:'forbidden'},{status:403});return Response.json(result)}`, true},
		{"operation_in_rejection_branch", `import {auth} from '@/auth';export async function GET(){const session=await auth();if(session?.user?.role!=='admin'){const secret=await readSecret();return Response.json({error:'forbidden',secret},{status:403})}return Response.json({ok:true})}`, true},
		{"operation_in_rejection_response_argument", `import {auth} from '@/auth';export async function GET(){const session=await auth();if(session?.user?.role!=='admin')return Response.json({error:await readSecret()},{status:403});return Response.json({ok:true})}`, true},
		{"cookie_role_is_not_server_identity", `import {cookies} from 'next/headers';export async function GET(){const jar=await cookies();const session={user:{role:jar.get('role')?.value}};if(session.user.role!=='admin')return Response.json({error:'forbidden'},{status:403});return Response.json({secret:'x'})}`, true},
		{"rejection_branch_returns_secret_status_200", `import {auth} from '@/auth';export async function GET(){const session=await auth();if(session?.user?.role!=='admin')return Response.json({secret:'x'},{status:200});return Response.json({ok:true})}`, true},
		{"unknown_local_auth_with_role_check", `import {auth} from '@/auth';export async function GET(){const session=await auth();if(session?.user?.role!=='admin')return Response.json({error:'forbidden'},{status:403});return Response.json({secret:'x'})}`, true},
		{"fake_local_response_does_not_reject", `import {getServerSession as auth} from 'next-auth';const Response={json(data,init){return {data,init}}};export async function GET(){const session=await auth();if(session?.user?.role!=='admin')return Response.json({error:'forbidden'},{status:403});return Response.json({secret:'x'})}`, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			files := map[string]string{
				"package.json":           `{"dependencies":{"next":"15.2.2","react":"19.2.0","next-auth":"5.0.0"}}`,
				"app/page.tsx":           `"use client";export default function Page(){if(localStorage.getItem('role')==='admin'){fetch('/api/admin')}return null}`,
				"app/api/admin/route.ts": tt.server,
			}
			r := analyzeNext(t, nextRepo(t, files))
			assertPracticeAccuracy(t, r, "NX-BP-22", tt.want)
			if tt.want {
				for _, p := range practiceAccuracyObservations(r, "NX-BP-22") {
					if !strings.Contains(p.Detail, "GET /api/admin") {
						t.Errorf("expected finding tied to matched GET request: %+v", p)
					}
				}
			}
		})
	}
}

func TestPracticeAccuracyClientRoleGateDoesNotAttachToPublicRequest(t *testing.T) {
	files := map[string]string{
		"package.json":             `{"dependencies":{"next":"15.2.2","react":"19.2.0","next-auth":"5.0.0"}}`,
		"app/page.tsx":             `"use client";export default function Page(){if(localStorage.getItem('role')==='admin'){fetch('/api/admin')}fetch('/api/catalog');return null}`,
		"app/api/admin/route.ts":   `import {getServerSession as auth} from 'next-auth';export async function GET(){const session=await auth();if(session?.user?.role!=='admin')return Response.json({error:'forbidden'},{status:403});return Response.json({secret:'x'})}`,
		"app/api/catalog/route.ts": `export async function GET(){return Response.json({items:[]})}`,
	}
	r := analyzeNext(t, nextRepo(t, files))
	assertPracticeAccuracy(t, r, "NX-BP-22", false)
}

func TestPracticeAccuracyTernaryClientAuthorization(t *testing.T) {
	r := analyzeNext(t, nextRepo(t, map[string]string{
		"app/page.tsx":           `"use client";export default function Page(){return localStorage.getItem('role')==='admin'?fetch('/api/admin'):null}`,
		"app/api/admin/route.ts": `export function GET(){return Response.json({secret:'x'})}`,
	}))
	assertPracticeAccuracy(t, r, "NX-BP-22", true)
}
