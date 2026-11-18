package langjs

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDynamicHTTPRegistrations(t *testing.T) {
	root := t.TempDir()
	source := `import express from 'express';
const app = express();
const routes = [['/one', 'first'], ['/two', 'second']];
for (const [path, label] of routes) {
 app.get(path, (req, res) => res.send('<p>' + label + req.query.q + '</p>'));
}
`
	if err := os.WriteFile(filepath.Join(root, "routes.js"), []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	report, err := Analyze(root, "routes.js")
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, entry := range report.Entries {
		if entry.HTTP != nil {
			found[entry.HTTP.Path] = true
		}
	}
	if !found["/one"] || !found["/two"] {
		t.Fatalf("finite registrations missing: %v", found)
	}
}

func TestDynamicHTTPContextIsolation(t *testing.T) {
	root := t.TempDir()
	source := `import express from 'express';
const app=express();
function factory(prefix) { return (req,res) => res.send(prefix + req.query.q); }
app.get('/one', factory('<p>one:'));
app.get('/two', factory('<p>two:'));
`
	if err := os.WriteFile(filepath.Join(root, "routes.js"), []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	report, err := Analyze(root, "routes.js")
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Entries) != 2 {
		t.Fatalf("entries=%d", len(report.Entries))
	}
	callable := ""
	for _, b := range report.DispatchBindings {
		if b.Mechanism != "factory_expansion" || b.CallableID == "" {
			t.Fatalf("factory binding: %+v", b)
		}
		if callable != "" && callable != b.CallableID {
			t.Fatal("shared body lost identity")
		}
		callable = b.CallableID
	}
	contexts := map[string]bool{}
	for _, ctx := range report.InvocationContexts {
		contexts[ctx.ID] = true
		if len(ctx.Closures) != 1 || ctx.Closures[0].Parameter != "prefix" {
			t.Fatalf("closure: %+v", ctx)
		}
	}
	if len(contexts) != 2 {
		t.Fatal("contexts collapsed")
	}
	uses := map[string]bool{}
	for _, u := range report.Uses {
		if u.Kind == "xss_candidate" {
			uses[u.InvocationContextID] = true
		}
	}
	if len(uses) != 2 {
		t.Fatalf("contextual XSS uses=%v", uses)
	}
}

func TestDynamicHTTPContextIsolationControls(t *testing.T) {
	for _, language := range []string{"javascript", "typescript"} {
		t.Run(language, func(t *testing.T) {
			report, err := Analyze("testdata/"+language+"/dynamic-dispatch", "")
			if err != nil {
				t.Fatal(err)
			}
			paths := map[string]string{}
			for _, e := range report.Entries {
				if e.HTTP != nil {
					paths[e.ID] = e.HTTP.Path
				}
			}
			outcomes := map[string]string{}
			for _, u := range report.Uses {
				if u.XSS != nil {
					outcomes[paths[u.EntryID]] = u.XSS.Protection
				}
			}
			if outcomes["/raw"] != "raw" || outcomes["/encoded"] != "sanitized" {
				t.Fatalf("outcomes=%v", outcomes)
			}
			unknown := false
			for _, b := range report.DispatchBindings {
				if paths[b.EntryID] == "/unknown" {
					unknown = b.Resolution == "unresolved" && len(b.Gaps) > 0
				}
			}
			if !unknown {
				t.Fatal("unknown factory binding lost")
			}
		})
	}
}

func TestDynamicHTTPBounds(t *testing.T) {
	cases := []struct {
		name, source string
		max          int
		gap          string
	}{
		{"runtime", `const rows=load(); for (const [path,label] of rows) {app.get(path,(req,res)=>res.send(req.query.q));}`, 0, "dynamic_registration_unresolved"},
		{"mutation", `const rows=[['/one','a']]; rows.push(['/two','b']); for (const [path,label] of rows) {app.get(path,(req,res)=>res.send(req.query.q));}`, 0, "dynamic_registration_unresolved"},
		{"recursive", `function make(mode){return make(mode)} app.get('/recursive',make(true));`, 1, "unresolved_factory"},
		{"wrapper", `app.get('/wrapper',unknown((req,res)=>res.send(req.query.q)));`, 1, "unresolved_factory"},
		{"shadowed", `const rows=[['/one','a']];function register(app){for (const [path,label] of rows){app.get(path,(req,res)=>res.send(req.query.q))}}`, 1, "ambiguous_receiver"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			source := "import express from 'express';const app=express();\n" + tc.source
			if err := os.WriteFile(filepath.Join(root, "routes.js"), []byte(source), 0600); err != nil {
				t.Fatal(err)
			}
			r, err := Analyze(root, "routes.js")
			if err != nil {
				t.Fatal(err)
			}
			if len(r.Entries) > tc.max {
				t.Fatalf("fabricated expansion: %d", len(r.Entries))
			}
			found := false
			for _, g := range r.Gaps {
				found = found || g.Kind == tc.gap
			}
			for _, e := range r.Entries {
				for _, g := range e.Gaps {
					found = found || g.Kind == tc.gap
				}
			}
			if !found {
				t.Fatalf("missing %s gap: %+v", tc.gap, r.Gaps)
			}
			for _, u := range r.Uses {
				if u.XSS != nil && u.XSS.Protection != "unknown" {
					t.Fatal("unsupported binding acquired rendering claim")
				}
			}
		})
	}
}

func TestDynamicHTTPBoundsLimitAndDeterminism(t *testing.T) {
	root := t.TempDir()
	var source strings.Builder
	source.WriteString("import express from 'express';const app=express();const rows=[")
	for i := 0; i < 130; i++ {
		fmt.Fprintf(&source, "['/r%d','constant'],", i)
	}
	source.WriteString("];for(const [path,label] of rows){app.get(path,(req,res)=>res.json(label))}")
	if err := os.WriteFile(filepath.Join(root, "routes.js"), []byte(source.String()), 0600); err != nil {
		t.Fatal(err)
	}
	var previous []byte
	for i := 0; i < 2; i++ {
		r, err := Analyze(root, "routes.js")
		if err != nil {
			t.Fatal(err)
		}
		if len(r.Entries) != 128 {
			t.Fatalf("bounded entries=%d", len(r.Entries))
		}
		found := false
		for _, g := range r.Gaps {
			found = found || strings.Contains(g.Detail, "remainder unexpanded")
		}
		if !found {
			t.Fatal("limit remainder hidden")
		}
		data, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		if previous != nil && !bytes.Equal(previous, data) {
			t.Fatal("repeated expansion changed")
		}
		previous = data
	}
}

func TestDynamicHTTPRegistrationsMounted(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"server.js": `import express from 'express';import router from './router';const app=express();app.use('/api',router);`,
		"router.js": `import express from 'express';const router=express.Router();const rows=[['/one','first'],['/two','second']];for(const [path,label] of rows){router.get(path,(req,res)=>res.send('<p>'+label+req.query.q))}export default router;`,
	}
	for name, source := range files {
		if err := os.WriteFile(filepath.Join(root, name), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
	}
	r, err := Analyze(root, "server.js")
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, e := range r.Entries {
		if e.HTTP != nil {
			found[e.HTTP.Path] = true
		}
	}
	if !found["/api/one"] || !found["/api/two"] || found["/one"] {
		t.Fatalf("mounted generation=%v", found)
	}
}
