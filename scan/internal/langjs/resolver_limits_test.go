package langjs

import (
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

func blockerDetails(u analysis.CandidateUse, kind string) []string {
	var out []string
	for _, g := range u.Completeness.Blockers {
		if g.Kind == kind {
			out = append(out, g.Detail)
		}
	}
	return out
}

// TestMiddlewareResolverConstructs records, for hardening 3 D-6, which
// middleware constructs the chain resolver reads. The two constructs D-6 allows
// to be added already resolve; the two that block a claim are of another kind
// and stay blocked.
func TestMiddlewareResolverConstructs(t *testing.T) {
	const head = `import express from 'express';
import path from 'path';
import { expressjwt } from 'express-jwt';
import listing from 'serve-index';
const app = express();
`
	const route = `app.get('/docs/:name', (req, res) => { res.sendFile(path.resolve('docs/', req.params.name)) })`
	for _, tt := range []struct {
		name, source, detail string
	}{
		{"factory that declares constants and returns one function", head + `const stamp = () => {
  const label = 'docs'
  const limit = 3
  return (req, res, next) => { res.setHeader('x-area', label); next() }
};
app.use('/docs', stamp());
` + route, ""},
		{"binding shadowed by an inner scope at another call", head + `const stamp = (req, res, next) => { if (req.query.skip) { return res.end() } next() };
function unrelated () { const stamp = 1; return stamp }
app.use('/docs', stamp);
` + route, ""},
		{"factory whose body is a library middleware call", head + `const gate = () => expressjwt({ secret: 's', algorithms: ['HS256'] });
app.use('/docs', gate());
` + route, "no direct returned function"},
		{"middleware bound by a constant of the enclosing function", head + `function mount () {
  const stamp = (req, res, next) => { next() }
  app.use('/docs', stamp)
  ` + route + `
}
mount();`, "handler binding is shadowed"},
		{"library factory with arguments", head + `app.use('/docs', listing('docs', { icons: true }));
` + route, "factory arguments require parameter binding"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			u := claimOfKind(t, map[string]string{"server.ts": tt.source}, "path_traversal_candidate")
			got := blockerDetails(u, "applicable_middleware_unresolved")
			if tt.detail == "" && len(got) != 0 {
				t.Fatalf("construct must resolve, blockers: %v", got)
			}
			if tt.detail != "" && (len(got) != 1 || got[0] != tt.detail) {
				t.Fatalf("applicable_middleware_unresolved details = %v, want [%s]", got, tt.detail)
			}
		})
	}
}

// TestCodeSinkInsideTry records, for hardening 3 D-5, what a code sink inside
// a try records. The try statement is explored and leaves a coverage gap, never
// a blocker. What decides the operand path is an enclosing test that mentions
// the operand: with one the path is guarded, without one it is raw.
func TestCodeSinkInsideTry(t *testing.T) {
	const head = `import express from 'express';
const app = express();
`
	for _, tt := range []struct {
		name, body, protection string
	}{
		{"try alone", `  const text = req.body.note
  try {
    if (!text) { throw new Error('empty') }
    res.send(String(eval(text)))
  } catch (err) { res.send('failed') }`, "raw"},
		{"try inside a test of the operand's shape", `  const note = req.body.note
  if (note.match(/\[\[(.*)\]\]/) !== null) {
    const text = note.substring(2, note.length - 2)
    try {
      if (!text) { throw new Error('empty') }
      res.send(String(eval(text)))
    } catch (err) { res.send('failed') }
  }`, "guarded"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			u := claimOfKind(t, map[string]string{"server.ts": head + "app.post('/notes', (req, res) => {\n" + tt.body + "\n})"}, "code_execution_candidate")
			for _, g := range u.Completeness.Blockers {
				if g.Kind == "unsupported_control_flow" || g.Kind == "branch_exit" {
					t.Fatalf("the try statement must not block the claim: %+v", u.Completeness.Blockers)
				}
			}
			if !gapKind(u.Gaps, "unsupported_control_flow") {
				t.Fatalf("the explored try statement must stay a recorded gap: %+v", u.Gaps)
			}
			if u.Code == nil || len(u.Code.Paths) == 0 {
				t.Fatal("no code operand paths")
			}
			for _, p := range u.Code.Paths {
				if p.Protection != tt.protection {
					t.Fatalf("operand path protection = %s, want %s", p.Protection, tt.protection)
				}
			}
			if tt.protection == "guarded" {
				found := false
				for _, e := range u.Context {
					found = found || e.Kind == "enclosing_guard" && strings.Contains(e.Text, "match")
				}
				if !found {
					t.Fatal("the enclosing test is not recorded as the guard")
				}
			}
		})
	}
}
