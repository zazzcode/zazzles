package langjs

import (
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

// claimOfKind returns the single candidate of a kind in a project.
func claimOfKind(t *testing.T, files map[string]string, kind string) analysis.CandidateUse {
	t.Helper()
	root := t.TempDir()
	for name, text := range files {
		writeSource(t, root, name, text)
	}
	report, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	var found []analysis.CandidateUse
	for _, u := range report.Uses {
		if u.Kind == kind {
			found = append(found, u)
		}
	}
	if len(found) != 1 {
		t.Fatalf("%s candidates: got %d, want 1", kind, len(found))
	}
	if found[0].Completeness == nil {
		t.Fatalf("%s candidate has no completeness record", kind)
	}
	return found[0]
}

func blockerKinds(u analysis.CandidateUse) string {
	var kinds []string
	for _, g := range u.Completeness.Blockers {
		kinds = append(kinds, g.Kind)
	}
	return strings.Join(kinds, ",")
}

// TestVerifiedMiddlewareIsNotAFactory covers hardening 3 D-3: a verified multer
// binding call and a call on the closed authentication list are middleware with
// known behavior; any other call with arguments stays an unresolved factory.
func TestVerifiedMiddlewareIsNotAFactory(t *testing.T) {
	const primary = `import express from 'express';
import multer from 'multer';
import { expressjwt } from 'express-jwt';
const app = express();
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 1000 } });
const make = (label) => (req, res, next) => { next() };
`
	const transfer = `import express from 'express';
import multer from 'multer';
import passport from 'passport';
import path from 'path';
const api = express();
const intake = multer({ dest: 'incoming/' });
function build (flag) { return (request, reply, done) => { done() } }
`
	fetching := `async (req, res) => { const page = await fetch(req.body.link); res.send('ok') }`
	reading := `(request, reply) => { reply.sendFile(path.resolve('sheets/', request.query.sheet)) }`
	for _, tt := range []struct {
		name, source, kind string
		factory            bool
	}{
		{"multer and express-jwt before the handler", primary + "app.post('/preview', upload.single('picture'), expressjwt({ secret: 's', algorithms: ['HS256'] }), " + fetching + ")", "ssrf_candidate", false},
		{"multer alone", primary + "app.post('/preview', upload.single('picture'), " + fetching + ")", "ssrf_candidate", false},
		{"unknown call with an argument", primary + "app.post('/preview', make('preview'), " + fetching + ")", "ssrf_candidate", true},
		{"unknown call beside verified middleware", primary + "app.post('/preview', upload.single('picture'), make('preview'), " + fetching + ")", "ssrf_candidate", true},
		{"a name is not a binding", `import express from 'express';
const app = express();
const upload = { single: (field) => (req, res, next) => { next() } };
app.post('/preview', upload.single('picture'), ` + fetching + ")", "ssrf_candidate", true},
		{"multer with a custom file filter stays unresolved", primary + "const picky = multer({ storage: multer.memoryStorage(), fileFilter: (req, file, done) => { done(null, true) } });\napp.post('/preview', picky.single('picture'), " + fetching + ")", "ssrf_candidate", true},
		{"transfer: disk multer and passport", transfer + "api.get('/sheets', intake.array('scans', 3), passport.authenticate('jwt', { session: false }), " + reading + ")", "path_traversal_candidate", false},
		{"transfer: unknown call with an argument", transfer + "api.get('/sheets', build(true), " + reading + ")", "path_traversal_candidate", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			u := claimOfKind(t, map[string]string{"server.ts": tt.source}, tt.kind)
			if got := gapKind(u.Completeness.Blockers, "unresolved_factory"); got != tt.factory {
				t.Fatalf("unresolved_factory blocker = %v, want %v (blockers %s)", got, tt.factory, blockerKinds(u))
			}
		})
	}
}

// TestLiteralHeapWriteBesideTheOperand covers hardening 3 D-4 for the ssrf,
// path and code families: a literal assigned to a member that no dependency of
// the operand reads afterwards does not block the claim.
func TestLiteralHeapWriteBesideTheOperand(t *testing.T) {
	const head = `import express from 'express';
import path from 'path';
const app = express();
const marking = process.env.MARK === '1';
`
	const transferHead = `import express from 'express';
import path from 'path';
import vm from 'vm';
const api = express();
const marking = process.env.MARK === '1';
`
	for _, tt := range []struct {
		name, source, kind string
		blocked            bool
	}{
		{"ssrf: literal to an unrelated member", head + `app.post('/preview', async (req, res) => {
  const link = req.body.link
  if (marking) req.app.locals.previewed = true
  const page = await fetch(link)
  res.send('ok')
})`, "ssrf_candidate", false},
		{"ssrf: literal to the member the operand reads", head + `app.post('/preview', async (req, res) => {
  if (marking) req.body.link = 'https://docs.example/index'
  const page = await fetch(req.body.link)
  res.send('ok')
})`, "ssrf_candidate", true},
		{"ssrf: literal to a parent of the member the operand reads", head + `app.post('/preview', async (req, res) => {
  if (marking) req.body = null
  const page = await fetch(req.body.link)
  res.send('ok')
})`, "ssrf_candidate", true},
		{"ssrf: request value to an unrelated member", head + `app.post('/preview', async (req, res) => {
  const link = req.body.link
  if (marking) req.app.locals.last = req.body.note
  const page = await fetch(link)
  res.send('ok')
})`, "ssrf_candidate", true},
		{"ssrf: operand read through an alias of the written member", head + `app.post('/preview', async (req, res) => {
  const fields = req.body
  if (marking) req.body.link = 'https://docs.example/index'
  const page = await fetch(fields.link)
  res.send('ok')
})`, "ssrf_candidate", true},
		{"path: literal to an unrelated member", head + `app.get('/docs/:name', (req, res) => {
  if (marking) res.locals.served = 1
  res.sendFile(path.resolve('docs/', req.params.name))
})`, "path_traversal_candidate", false},
		{"path: literal to the member the operand reads", head + `app.get('/docs/:name', (req, res) => {
  if (marking) req.query.leaf = 'index.html'
  res.sendFile(path.resolve('docs/', req.query.leaf))
})`, "path_traversal_candidate", true},
		{"code: literal to an unrelated member", head + `app.post('/calc', (req, res) => {
  if (marking) req.app.locals.ran = 'yes'
  res.send(String(eval(req.body.expr)))
})`, "code_execution_candidate", false},
		{"code: literal to the member the operand reads", head + `app.post('/calc', (req, res) => {
  if (marking) req.body.expr = '1 + 1'
  res.send(String(eval(req.body.expr)))
})`, "code_execution_candidate", true},
		{"transfer ssrf: other names, literal null", transferHead + `api.put('/mirror', async function (request, reply) {
  const target = request.query.origin
  if (marking) reply.locals.mirrored = null
  const copy = await fetch(target)
  reply.end()
})`, "ssrf_candidate", false},
		{"transfer code: literal number, vm", transferHead + `api.post('/run', function (request, reply) {
  if (marking) request.app.locals.runs = 0
  reply.json(vm.runInNewContext(request.body.program))
})`, "code_execution_candidate", false},
		{"transfer path: the written member is read by the operand", transferHead + `api.get('/sheets', function (request, reply) {
  if (marking) request.query.sheet = 'summary.csv'
  reply.sendFile(path.resolve('sheets/', request.query.sheet))
})`, "path_traversal_candidate", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			u := claimOfKind(t, map[string]string{"server.ts": tt.source}, tt.kind)
			if got := gapKind(u.Completeness.Blockers, "unsupported_write"); got != tt.blocked {
				t.Fatalf("unsupported_write blocker = %v, want %v (blockers %s)", got, tt.blocked, blockerKinds(u))
			}
			if !gapKind(u.Gaps, "unsupported_write") {
				t.Fatalf("the write must stay recorded as a gap: %+v", u.Gaps)
			}
		})
	}
}

// TestLiteralHeapWritePollutionUnchanged holds the pollution family to its own
// rule: it reads heap write gaps as evidence, and D-4 does not apply to it.
func TestLiteralHeapWritePollutionUnchanged(t *testing.T) {
	report := analyzeFiles(t, map[string]string{"server.ts": `import express from 'express';
const app = express();
const settings = {};
app.post('/settings', (req, res) => {
  if (req.body.touch) req.app.locals.touched = true
  settings[req.body.section][req.body.key] = req.body.value
  res.send('ok')
})`})
	found := 0
	for _, u := range report.Uses {
		if u.Kind != analysis.PollutionKind {
			continue
		}
		found++
		if u.Completeness == nil || !gapKind(u.Completeness.Blockers, "unsupported_write") {
			t.Fatalf("pollution record must keep the literal write as a blocker: %+v", u.Completeness)
		}
	}
	if found == 0 {
		t.Fatal("no pollution candidate recorded")
	}
}
