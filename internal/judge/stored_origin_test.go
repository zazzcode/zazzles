package judge

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/pipeline"
)

const storedOriginApp = `const express = require("express");
const initSqlJs = require("sql.js");
const app = express();
let db;
async function initDb() {
  const SQL = await initSqlJs();
  db = new SQL.Database();
  db.run("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)");
  db.run("INSERT INTO users (name) VALUES ('Alice')");
}
app.use(express.json());
app.post("/rename", (req, res) => {
  db.run("UPDATE users SET name = '" + req.body.name + "' WHERE id = 1");
  res.send("ok");
});
function queryAll(sql) {
  const stmt = db.prepare(sql);
  const rows = [];
  while (stmt.step()) {
    rows.push(stmt.getAsObject());
  }
  stmt.free();
  return rows;
}
app.get("/users", (_req, res) => {
  const users = queryAll("SELECT id, name FROM users");
  res.send(users.map(u => ` + "`<li>${u.name}</li>`" + `).join(""));
});
initDb();
`

func storedOriginUse(t *testing.T) analysis.CandidateUse {
	t.Helper()
	dir := t.TempDir()
	for name, text := range map[string]string{"package.json": `{"dependencies":{"express":"4.18.2","sql.js":"1.10.0"}}`, "server.js": storedOriginApp} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	r, err := pipeline.Analyze(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range r.Uses {
		if u.Kind == "xss_candidate" && strings.Contains(u.Sink.Text, "<li>") && storedOriginAskable(u) {
			return u
		}
	}
	t.Fatalf("no stored-origin XSS record with a write set")
	return analysis.CandidateUse{}
}

// TestStoredOriginJudgment (AC3, W3b, D-4): the request carries the write set
// and read query; a verified cited request write yields a stored-flow
// finding; no request write yields Protected only when every key is closed.
func TestStoredOriginJudgment(t *testing.T) {
	use := storedOriginUse(t)
	c, _ := New("openai", "fixture-model", "k")
	payload, err := c.payload(use)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := requestUse(payload)
	if err != nil || wire["stored_origin"] == nil || !strings.Contains(string(payload), `\"read_queries\"`) {
		t.Fatalf("request lacks stored_origin and the read query: %v", err)
	}
	if _, fixed := resolutionGate(use); fixed {
		t.Fatal("a record with a write set is resolvable")
	}
	stored := func(answer string) map[string]string {
		v := map[string]string{"output_context": use.XSS.OutputContext, "xss_exposure": "vulnerable", "xss_all_paths_protected": "no", "encoding_adequacy": "not_present", "sanitizer_effectiveness": "absent"}
		for _, q := range payloadResolutionQuestions(payload) {
			if strings.HasPrefix(q.name, resolvePrefix+"stored_") && !strings.HasSuffix(q.name, citeSuffix) {
				v[q.name] = answer
			}
		}
		return v
	}
	closed := use.StoredOrigin.Stores[0].ClosedStore
	if closed != "closed" {
		t.Fatalf("fixture store must be closed, got %s", closed)
	}
	for _, tt := range []struct {
		name, answer, status string
		open                 bool
		tamper               func(string) string
	}{
		{"cited request write is a finding", "request_write_cited", "confirmed_vulnerability", false, nil},
		{"uncited request write stays Review", "request_write_cited", "needs_evidence", false, func(string) string { return citeNone }},
		{"no request write in a closed store is Protected", "no_request_write_in_evidence", "protected_for_claim", false, nil},
		{"no request write in an open store stays Review", "no_request_write_in_evidence", "needs_evidence", true, nil},
		{"cannot_tell stays Review", "cannot_tell", "needs_evidence", false, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			u := use
			if tt.open {
				so := *use.StoredOrigin
				so.Stores = append([]analysis.StoredWriteSet{}, use.StoredOrigin.Stores...)
				so.Stores[0].ClosedStore = "open"
				u.StoredOrigin = &so
			}
			a := resolutionStub(t, stored(tt.answer), "", tt.tamper).Assess(context.Background(), u)
			if a.Status != "completed" || a.FindingStatus != tt.status {
				t.Fatalf("status %s/%s blockers %+v resolutions %+v reason %q", a.Status, a.FindingStatus, a.BlockingGaps, a.Resolutions, a.Reason)
			}
			if tt.status != "needs_evidence" && !a.ModelResolved() {
				t.Fatal("outcome must carry the model-resolved mark")
			}
		})
	}
}

// TestStoredOriginLiteralOnlyIsGated: a census of literal writes in a store
// that is not closed leaves no answer that could change the record, so it is
// not asked and the send gate keeps it back. Every question sent has at least
// two choices (the provider rejects fewer).
func TestStoredOriginLiteralOnlyIsGated(t *testing.T) {
	use := storedOriginUse(t)
	so := *use.StoredOrigin
	so.Stores = append([]analysis.StoredWriteSet{}, use.StoredOrigin.Stores...)
	so.Stores[0].Writes = []analysis.StoredWrite{{Evidence: use.StoredOrigin.Stores[0].Writes[0].Evidence, Literal: true}}
	so.Stores[0].ClosedStore = "unknown"
	use.StoredOrigin = &so
	if storedOriginAskable(use) {
		t.Fatal("literal-only writes in an open store are not askable")
	}
	if _, fixed := resolutionGate(use); !fixed {
		t.Fatal("the record must be gated")
	}
	so.Stores[0].ClosedStore = "closed"
	if !storedOriginAskable(use) {
		t.Fatal("a closed store stays askable: no request write would support protection")
	}
	c, _ := New("openai", "fixture-model", "k")
	payload, err := c.payload(use)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range payloadResolutionQuestions(payload) {
		if len(q.choices) < 2 {
			t.Fatalf("question %s has %d choices", q.name, len(q.choices))
		}
	}
}
