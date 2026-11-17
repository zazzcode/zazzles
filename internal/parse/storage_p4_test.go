package parse

import (
	"strings"
	"testing"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
)

func storedCodeFixture(setter, writer, column string) map[string]string {
	return map[string]string{
		"package.json": `{"dependencies":{"express":"4.19.2","sequelize":"6.37.0"}}`,
		"lib.ts":       "import sanitizeLib from 'sanitize-html'\nexport const clean = (h: string) => sanitizeLib(h)\nexport const sanitize = (i = '') => i.replace(/<(?:\\w+)\\W+?[\\w]/gi, '')\n",
		"user.ts":      "import { Model, DataTypes } from 'sequelize'\nimport * as lib from './lib'\nexport class User extends Model {}\nexport const init = (sequelize: any) => { User.init({ username: { type: DataTypes.STRING, set (username: string) { " + setter + "; this.setDataValue('username', username) } }, bio: DataTypes.STRING }, { tableName: 'Users', sequelize }) }\n",
		"app.ts": "import express from 'express'\nimport { User } from './user'\nconst app = express()\n" + writer + "\n" +
			"app.get('/profile', async (req, res) => { const user = await User.findByPk(1); const code = user." + column + "; res.send(String(eval(code))) })\n",
	}
}

const p4Writer = "app.post('/profile', async (req, res) => { const user = await User.findByPk(1); await user.update({ username: req.body.username }); res.send('ok') })"

const p4SeedWriter = "app.post('/profile', async (req, res) => { await User.create({ username: 'admin' }); res.send('ok') })"

func p4Eval(t *testing.T, files map[string]string) analysis.CandidateUse {
	t.Helper()
	r := analyzeFiles(t, files)
	uses := usesOfKind(r, "code_execution_candidate")
	if len(uses) != 1 {
		t.Fatalf("want one eval candidate, got %d", len(uses))
	}
	u := uses[0]
	if u.InputFacts != nil {
		if err := u.InputFacts.Validate(u.Dependencies); err != nil {
			t.Fatalf("invalid input facts: %v", err)
		}
	}
	return u
}

func p4Linked(u analysis.CandidateUse) bool {
	for _, d := range u.Dependencies {
		for _, e := range d.Transfers {
			if e.Kind == "storage_write" {
				return d.StorageKey == "" && strings.HasPrefix(d.Source.Text, "req.body.")
			}
		}
	}
	return false
}

func p4Unresolved(u analysis.CandidateUse) bool {
	for _, d := range u.Dependencies {
		if d.StorageKey == "" || strings.HasPrefix(d.Source.Text, "req.") {
			return false
		}
	}
	return len(u.Dependencies) > 0
}

func TestP4StoredCodeOperandLink(t *testing.T) {
	for _, tt := range []struct {
		name, setter, writer, column string
		mutate                       func(map[string]string)
		linked                       bool
	}{
		{"request writer without setter", "", p4Writer, "username", nil, true},
		{"HTML tag-stripping setter is not a code restriction", "username = lib.sanitize(username)", p4Writer, "username", nil, true},
		{"sanitize-html setter is not a code restriction", "username = lib.clean(username)", p4Writer, "username", nil, true},
		{"setter branch that does not test the value", "if (process.env.LEGACY) { username = lib.sanitize(username) } else { username = lib.clean(username) }", p4Writer, "username", nil, true},
		{"seed-only writer stays unresolved", "", p4SeedWriter, "username", nil, false},
		{"read of a different column stays unresolved", "", p4Writer, "bio", nil, false},
		{"allowlist test in setter is a write-side control", "if (!/^[a-z]+$/.test(username)) { throw new Error('bad') }", p4Writer, "username", nil, false},
		{"allowlist replace in setter is not an HTML sanitizer", "username = username.replace(/[^a-z]/g, '')", p4Writer, "username", nil, false},
		{"unknown helper in setter is not an HTML sanitizer", "username = lib.unknown(username)", p4Writer, "username", nil, false},
		{"validator on the attribute", "", p4Writer, "username", func(f map[string]string) {
			f["user.ts"] = strings.Replace(f["user.ts"], "username: { type", "username: { validate: { isAlpha: true }, type", 1)
		}, false},
		{"non-string column", "", p4Writer, "username", func(f map[string]string) {
			f["user.ts"] = strings.Replace(f["user.ts"], "type: DataTypes.STRING", "type: DataTypes.INTEGER", 1)
		}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			files := storedCodeFixture(tt.setter, tt.writer, tt.column)
			if tt.mutate != nil {
				tt.mutate(files)
			}
			u := p4Eval(t, files)
			if got := p4Linked(u); got != tt.linked {
				t.Fatalf("linked=%t want %t: %+v", got, tt.linked, u.Dependencies)
			}
			if !tt.linked && !p4Unresolved(u) {
				t.Fatalf("unlinked operand must stay a storage read: %+v", u.Dependencies)
			}
			// Every dependency keeps exactly one valid operand path (no
			// code_facts_invalid after the link replaces a stored read).
			if err := u.Code.Validate(len(u.Dependencies), len(u.Context)); err != nil || len(u.Code.Paths) != len(u.Dependencies) {
				t.Fatalf("code facts invalid after link: %v paths=%d deps=%d", err, len(u.Code.Paths), len(u.Dependencies))
			}
			if tt.linked {
				for _, p := range u.Code.Paths {
					if p.Protection != "raw" {
						t.Fatalf("a stored write is no code restriction: %+v", u.Code.Paths)
					}
				}
			}
		})
	}
}

func p4SQLRepo(provider, expr string) map[string]string {
	files := map[string]string{
		"lib/prisma.ts": `import { PrismaClient } from "@prisma/client";
const g = globalThis as any;
export const prisma = g.prisma ?? new PrismaClient();`,
		"app/api/tracking/route.ts": `import { NextRequest } from "next/server";
import { prisma } from "@/lib/prisma";
export async function POST(request: NextRequest) {
  const id = crypto.randomUUID();
  const ip = request.headers.get("x-forwarded-for") ?? "unknown";
  const ua = request.headers.get("user-agent") ?? "";
  const p = request.nextUrl.searchParams.get("p") ?? "";
  const sid = request.nextUrl.searchParams.get("s");
  const tail = request.nextUrl.searchParams.get("t") ?? "";
  const query = ` + "`" + expr + "`" + `;
  await prisma.$queryRawUnsafe(query);
  return Response.json({});
}`,
	}
	if provider != "" {
		files["prisma/schema.prisma"] = "datasource db {\n  provider = \"" + provider + "\"\n  url = env(\"DATABASE_URL\")\n}\n"
	}
	return files
}

// p4Facts runs the literal-escape fact producer on the repo's Prisma raw call.
func p4Facts(t *testing.T, files map[string]string) []string {
	t.Helper()
	root := nextRepo(t, files)
	ps, err := newParsers()
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{}
	for name := range files {
		if strings.HasSuffix(name, ".ts") {
			allowed[name] = true
		}
	}
	set := &moduleSet{root: root, parsers: ps, modules: map[string]*sourceModule{}, allowed: allowed}
	defer set.close()
	m, err := set.load("app/api/tracking/route.ts")
	if err != nil {
		t.Fatal(err)
	}
	var use *analysis.CandidateUse
	walkCalls(m.tree.RootNode(), func(call *sitter.Node) {
		if fn := call.ChildByFieldName("function"); fn != nil && strings.HasSuffix(fn.Utf8Text(m.src), "$queryRawUnsafe") {
			use = &analysis.CandidateUse{Kind: "sql_query_candidate", Sink: m.evidence("sink", call), Completeness: &analysis.Completeness{}}
		}
	})
	if use == nil {
		t.Fatal("no raw query call")
	}
	set.sqlLiteralEscapeFacts(use)
	return use.Completeness.ModelFacts
}

const p4Esc = `.replace(/'/g, "''")`

const p4Tracking = "INSERT INTO visitor_logs (id, ip, userAgent, path, sessionId) VALUES ('${id}', '${ip}', '${ua" + p4Esc + "}', '${p" + p4Esc + "}', ${sid ? `'${sid" + p4Esc + "}'` : \"NULL\"})"

func TestP4SQLLiteralEscapeFacts(t *testing.T) {
	operands := func(facts []string) string {
		var out []string
		for _, f := range facts {
			if !strings.HasPrefix(f, "sql_literal_quote_doubling: ") {
				t.Fatalf("unexpected fact %q", f)
			}
			out = append(out, strings.SplitN(strings.TrimPrefix(f, "sql_literal_quote_doubling: "), " at ", 2)[0])
		}
		return strings.Join(out, "|")
	}
	for _, tt := range []struct {
		name, provider, sql, want string
	}{
		{"sqlite marks only the escaped operands, ip stays raw", "sqlite", p4Tracking, "ua.replace(/'/g, \"''\")|p.replace(/'/g, \"''\")|sid.replace(/'/g, \"''\")"},
		{"postgres quote doubling is a literal escape", "postgresql", "SELECT 1 FROM t WHERE a = '${ua" + p4Esc + "}'", "ua.replace(/'/g, \"''\")"},
		{"mysql backslash escapes defeat quote doubling", "mysql", p4Tracking, ""},
		{"unknown dialect is not assumed", "", p4Tracking, ""},
		{"sql server is not assumed", "sqlserver", p4Tracking, ""},
		{"escape in numeric position is not a literal escape", "sqlite", "SELECT 1 FROM t WHERE id = ${p" + p4Esc + "}", ""},
		{"escape in identifier position", "sqlite", "SELECT 1 FROM t ORDER BY ${p" + p4Esc + "}", ""},
		{"escape inside a double-quoted identifier", "sqlite", `SELECT 1 FROM "${p` + p4Esc + `}"`, ""},
		{"escape inside a comment", "sqlite", "SELECT 1 /* ${p" + p4Esc + "} */", ""},
		{"escape inside a backslash E-string", "postgresql", "SELECT E'${p" + p4Esc + "}'", ""},
		{"later raw concatenation after the escape", "sqlite", "SELECT 1 FROM t WHERE a = '${ua" + p4Esc + " + tail}'", ""},
		{"raw operand sharing the literal gets no fact", "sqlite", "SELECT 1 FROM t WHERE a = '${ua" + p4Esc + "}${tail}'", "ua.replace(/'/g, \"''\")"},
		{"first occurrence only is not an escape", "sqlite", `SELECT 1 FROM t WHERE a = '${ua.replace("'", "''")}'`, ""},
		{"missing global flag is not an escape", "sqlite", `SELECT 1 FROM t WHERE a = '${ua.replace(/'/, "''")}'`, ""},
		{"backslash replacement is not quote doubling", "sqlite", `SELECT 1 FROM t WHERE a = '${ua.replace(/'/g, "\\'")}'`, ""},
		{"another character is not the literal delimiter", "sqlite", `SELECT 1 FROM t WHERE a = '${ua.replace(/"/g, '""')}'`, ""},
		{"escape bound to a variable is not followed", "sqlite", "SELECT 1 FROM t WHERE a = '${esc}'", ""},
		{"a conditional inside a literal is not searched", "sqlite", "SELECT 1 FROM t WHERE a = '${sid ? `'${sid" + p4Esc + "}'` : \"\"}'", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := operands(p4Facts(t, p4SQLRepo(tt.provider, tt.sql))); got != tt.want {
				t.Fatalf("facts %q want %q", got, tt.want)
			}
		})
	}
}

func TestP4SQLLiteralEscapeKeepsRawRecord(t *testing.T) {
	r := analyzeNext(t, nextRepo(t, p4SQLRepo("sqlite", p4Tracking)))
	uses := usesOf(r, "sql_query_candidate", "app/api/tracking/route.ts")
	if len(uses) != 1 {
		t.Fatalf("one SQL candidate expected, got %d", len(uses))
	}
	raw := false
	for _, d := range uses[0].Dependencies {
		raw = raw || strings.Contains(d.Source.Text, "x-forwarded-for") || d.Source.Text == "ip"
	}
	if !raw {
		t.Fatalf("the raw ip operand must remain a dependency: %+v", uses[0].Dependencies)
	}
}
