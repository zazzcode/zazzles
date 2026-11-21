package langpy

import (
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/parse"
)

// TestStoredWriteCensus (AC3, W3a): an unresolved stored read of a Python SQL
// table carries every write of that table, literal and request-built, and
// keeps its Review blocker.
func TestStoredWriteCensus(t *testing.T) {
	root := pythonFixture(t, map[string]string{"app.py": `from flask import Flask, request, render_template
import sqlite3
app=Flask(__name__)
def seed(cur):
    cur.execute("CREATE TABLE users (id INTEGER, email TEXT, country TEXT)")
    cur.execute("INSERT INTO users (email) VALUES ('admin@example.com')")
@app.post('/write')
def write():
    c=sqlite3.connect('app.db')
    cur=c.cursor()
    cur.execute('INSERT INTO users (country) VALUES (?)', (request.form['country'],))
    return 'ok'
@app.get('/read')
def read():
    c=sqlite3.connect('app.db')
    cur=c.cursor()
    cur.execute('SELECT * FROM users WHERE id = ?', (request.args['id'],))
    user=cur.fetchone()
    return render_template('view.html', user=user)
`, "templates/view.html": `<p>{{ user.email | safe }}</p>`})
	r, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	parse.CensusStoredWrites(r)
	parse.KeepStoredOriginFacts(r)
	var record *analysis.CandidateUse
	for i, u := range r.Uses {
		if u.Kind == "xss_candidate" && u.StoredOrigin != nil {
			record = &r.Uses[i]
		}
	}
	if record == nil {
		t.Fatalf("no unresolved stored read with a write set: %+v", pythonXSSOnly(r.Uses))
	}
	set := record.StoredOrigin.Stores[0]
	if set.Key != "python-sql:users.email" || set.Schema == nil || set.ClosedStore != "unknown" || len(set.Writes) != 2 {
		t.Fatalf("write set: %+v", set)
	}
	if !set.Writes[0].Literal || set.Writes[1].Literal {
		t.Fatalf("literal flags: %+v", set.Writes)
	}
	blocked := false
	for _, g := range record.Completeness.Blockers {
		blocked = blocked || g.Kind == "storage_origin_unresolved"
	}
	if !blocked || record.XSS.OriginResolved {
		t.Fatal("the census must not change the record's status")
	}
}
