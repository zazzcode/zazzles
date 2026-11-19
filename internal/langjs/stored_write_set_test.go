package langjs

import (
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
)

const storedWriteSetApp = `const express = require("express");
const initSqlJs = require("sql.js");
const app = express();
let db;
async function initDb() {
  const SQL = await initSqlJs();
  db = new SQL.Database();
  db.run(` + "`" + `
    CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT);
    CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT);
    INSERT INTO users (name, email) VALUES ('Alice', 'alice@example.com');
  ` + "`" + `);
}
function queryAll(sql) {
  const stmt = db.prepare(sql);
  const rows = [];
  while (stmt.step()) {
    rows.push(stmt.getAsObject());
  }
  stmt.free();
  return rows;
}
function queryOne(sql) {
  const rows = queryAll(sql);
  return rows.length > 0 ? rows[0] : null;
}
app.use(express.json());
app.get("/users", (_req, res) => {
  const users = queryAll("SELECT id, name FROM users");
  res.send(users.map(u => ` + "`<li>${u.name}</li>`" + `).join(""));
});
app.post("/login", (req, res) => {
  const query = ` + "`SELECT * FROM users WHERE email = '${req.body.email}'`" + `;
  const user = queryOne(query);
  res.send(` + "`<h1>${user.name}</h1>`" + `);
});
app.post("/notes", (req, res) => {
  db.run("INSERT INTO notes (body) VALUES (?)", [req.body.body]);
  res.send("ok");
});
app.get("/notes", (_req, res) => {
  const notes = queryAll("SELECT body FROM notes");
  res.send(notes.map(n => ` + "`<p>${n.body}</p>`" + `).join(""));
});
app.get("/note-ids", (_req, res) => {
  const ids = queryAll("SELECT id FROM notes");
  res.send(ids.map(n => ` + "`<p>${n.id}</p>`" + `).join(""));
});
initDb();
`

func TestStoredOriginWriteSet(t *testing.T) {
	r := analyzeFiles(t, map[string]string{"package.json": `{"dependencies":{"express":"4.18.2","sql.js":"1.10.0"}}`, "server.js": storedWriteSetApp})
	record := func(marker string) *analysis.CandidateUse {
		for i, u := range r.Uses {
			if u.Kind == "xss_candidate" && strings.Contains(u.Sink.Text, marker) {
				return &r.Uses[i]
			}
		}
		t.Fatalf("no xss record for %s", marker)
		return nil
	}
	store := func(marker string) *analysis.StoredWriteSet {
		if u := record(marker); u.StoredOrigin != nil {
			return &u.StoredOrigin.Stores[0]
		}
		return nil
	}
	users := store("<li>")
	if users == nil || !users.StaticRead || users.ClosedStore != "closed" || users.Schema == nil || len(users.Writes) != 1 || !users.Writes[0].Literal {
		t.Fatalf("literal-only table read by a static query: %+v", users)
	}
	if login := store("<h1>"); login == nil || login.StaticRead {
		t.Fatalf("a read through a request-built query must not be static: %+v", login)
	}
	if linked := record("n.body"); linked.StoredOrigin != nil {
		t.Fatalf("a record linked to its request writer carries no write set: %+v", linked.StoredOrigin)
	}
	ids := store("n.id")
	if ids == nil || len(ids.Writes) != 1 || ids.Writes[0].Literal {
		t.Fatalf("the table's one request write must be listed as non-literal: %+v", ids)
	}
	for _, marker := range []string{"<li>", "<h1>", "n.id"} {
		if !hasNextGap(blockers(*record(marker)), "storage_origin_unresolved") {
			t.Fatalf("%s: the write set is evidence only; the record stays blocked", marker)
		}
	}
}
