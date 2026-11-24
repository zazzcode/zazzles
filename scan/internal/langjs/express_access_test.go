package langjs

import (
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

func entryAccessOf(t *testing.T, report *analysis.AnalysisReport, name string) *analysis.EntryAccess {
	t.Helper()
	for _, e := range report.Entries {
		if e.Name == name {
			access, ok := expressEntryAccess(e)
			if !ok {
				return nil
			}
			if access.Authentication == analysis.AccessNone && e.Access != nil {
				t.Fatalf("authentication none must be stored as no record, got %+v", e.Access)
			}
			return &access
		}
	}
	t.Fatalf("entry %q not found", name)
	return nil
}

// TestExpressEntryAccess covers D-2: authentication is decided by a closed list
// of library contracts on the entry's middleware chain, never by a name.
func TestExpressEntryAccess(t *testing.T) {
	const head = `import express from 'express';
import { expressjwt } from 'express-jwt';
import passport from 'passport';
import { requiresAuth } from 'express-openid-connect';
const app = express();
`
	for _, tt := range []struct {
		name  string
		files map[string]string
		entry string
		want  string
		src   string // a source kind or text the access Sources must mention ("" for none)
	}{
		{"express-jwt named export", map[string]string{"server.ts": head + `app.get('/x', expressjwt({ secret: 's', algorithms: ['HS256'] }), (req, res) => { res.send('ok') })`}, "GET /x", analysis.AccessRequired, "expressjwt"},
		{"express-jwt default export", map[string]string{"server.ts": `import express from 'express';
import jwt from 'express-jwt';
const app = express();
app.get('/x', jwt({ secret: 's' }), (req, res) => { res.send('ok') })`}, "GET /x", analysis.AccessRequired, "jwt("},
		{"passport authenticate", map[string]string{"server.ts": head + `app.get('/x', passport.authenticate('jwt', { session: false }), (req, res) => { res.send('ok') })`}, "GET /x", analysis.AccessRequired, "passport.authenticate"},
		{"openid requiresAuth", map[string]string{"server.ts": head + `app.get('/x', requiresAuth(), (req, res) => { res.send('ok') })`}, "GET /x", analysis.AccessRequired, "requiresAuth"},
		{"local wrapper returns listed middleware", map[string]string{"server.ts": head + `const gate = () => expressjwt({ secret: 's', algorithms: ['HS256'] });
app.get('/x', gate(), (req, res) => { res.send('ok') })`}, "GET /x", analysis.AccessRequired, "expressjwt"},
		{"wrapper in another module", map[string]string{"guards.ts": `import { expressjwt } from 'express-jwt';
export const gate = () => expressjwt({ secret: 's', algorithms: ['HS256'] });`, "server.ts": `import express from 'express';
import * as guards from './guards';
const app = express();
app.get('/x', guards.gate(), (req, res) => { res.send('ok') })`}, "GET /x", analysis.AccessRequired, "guards.gate"},
		{"mount level app.use with path", map[string]string{"server.ts": head + `app.use('/api', expressjwt({ secret: 's', algorithms: ['HS256'] }));
app.get('/api/x', (req, res) => { res.send('ok') });
app.get('/open', (req, res) => { res.send('ok') })`}, "GET /api/x", analysis.AccessRequired, "app.use"},
		{"mount path does not cover route", map[string]string{"server.ts": head + `app.use('/api', expressjwt({ secret: 's', algorithms: ['HS256'] }));
app.get('/open', (req, res) => { res.send('ok') })`}, "GET /open", analysis.AccessNone, ""},
		{"route registered before the mount", map[string]string{"server.ts": head + `app.get('/api/x', (req, res) => { res.send('ok') });
app.use('/api', expressjwt({ secret: 's', algorithms: ['HS256'] }))`}, "GET /api/x", analysis.AccessNone, ""},
		{"router mounted under a guarded prefix", map[string]string{"routes.ts": `import express from 'express';
const router = express.Router();
router.get('/x', (req, res) => { res.send('ok') });
export default router;`, "server.ts": head + `import router from './routes';
app.use('/api', passport.authenticate('jwt', { session: false }), router)`}, "GET /api/x", analysis.AccessRequired, "passport.authenticate"},
		{"local middleware ends on one branch and calls next on another", map[string]string{"server.ts": head + `const gate = (req, res, next) => { if (!req.headers.authorization) { return res.status(401).end() } next() };
app.get('/x', gate, (req, res) => { res.send('ok') })`}, "GET /x", analysis.AccessUnresolved, "gate"},
		{"no listed middleware and no local guard", map[string]string{"server.ts": head + `app.get('/x', (req, res) => { res.send('ok') })`}, "GET /x", analysis.AccessNone, ""},
		{"a name is not a contract", map[string]string{"server.ts": head + `const requireAuth = (req, res, next) => { next() };
app.get('/x', requireAuth, (req, res) => { res.send('ok') })`}, "GET /x", analysis.AccessNone, ""},
		{"same names from an unlisted module", map[string]string{"server.ts": `import express from 'express';
import { expressjwt } from './local-jwt';
const app = express();
app.get('/x', expressjwt({ secret: 's' }), (req, res) => { res.send('ok') })`, "local-jwt.ts": `export const expressjwt = (o) => (req, res, next) => { next() };`}, "GET /x", analysis.AccessNone, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			for name, text := range tt.files {
				writeSource(t, root, name, text)
			}
			report, err := Analyze(root, "")
			if err != nil {
				t.Fatal(err)
			}
			access := entryAccessOf(t, report, tt.entry)
			if access == nil {
				t.Fatal("entry has no access record")
			}
			if access.Authentication != tt.want {
				t.Fatalf("authentication = %q, want %q (sources %+v gaps %+v)", access.Authentication, tt.want, access.Sources, access.Gaps)
			}
			if tt.src != "" {
				found := false
				for _, s := range access.Sources {
					if containsText(s.Text, tt.src) {
						found = true
					}
				}
				if !found {
					t.Fatalf("sources do not name %q: %+v", tt.src, access.Sources)
				}
			}
		})
	}
}

func containsText(text, part string) bool {
	for i := 0; i+len(part) <= len(text); i++ {
		if text[i:i+len(part)] == part {
			return true
		}
	}
	return false
}
