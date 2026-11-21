package judge

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/report"
)

func TestSQLPythonComponentPipeline(t *testing.T) {
	for _, driver := range []string{"sqlite3", "psycopg", "psycopg2", "pymysql", "mysql.connector"} {
		t.Run(driver, func(t *testing.T) {
			placeholder := "%s"
			if driver == "sqlite3" {
				placeholder = "?"
			}
			for _, tc := range []struct{ name, statement, injection, want string }{
				{"raw", "cur.execute('select '+request.args.get('name'))", "vulnerable", "confirmed_vulnerability"},
				{"bound", fmt.Sprintf("cur.execute('select * from users where name = %s',(request.args.get('name'),))", placeholder), "protected", "protected_for_claim"},
				{"identifier", "cur.execute('select * from '+request.args.get('table'),('ignored',))", "vulnerable", "confirmed_vulnerability"},
				{"unknown", "cur.execute('select '+external_transform(request.args.get('name')))", "protected", "needs_evidence"},
			} {
				t.Run(tc.name, func(t *testing.T) {
					r := sqlFixture(t, "app.py", "from flask import Flask,request\nimport "+driver+"\napp=Flask(__name__)\n@app.get('/')\ndef entry():\n    c="+driver+".connect('demo')\n    cur=c.cursor()\n    "+tc.statement+"\n    return 'ok'\n")
					count := 0
					for i := range r.Uses {
						u := &r.Uses[i]
						if u.Kind != "sql_query_candidate" {
							continue
						}
						count++
						if u.Components == nil || u.Components.Failure != "" {
							t.Fatalf("driver selection failed: %+v", u.Components)
						}
						server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
							var body struct{ Input string }
							json.NewDecoder(req.Body).Decode(&body)
							if !strings.Contains(body.Input, `"library":"`+driver+`"`) {
								t.Error("wrong selected driver")
							}
							w.Write(sqlResponse(*u, "fixture-model", "insufficient", tc.injection))
						}))
						defer server.Close()
						c, _ := New("openai", "fixture-model", "key")
						c.endpoint = server.URL
						c.http = server.Client()
						a, tr := c.AssessTrace(context.Background(), *u)
						if a.Status != "completed" || a.FindingStatus != tc.want {
							t.Fatalf("unexpected policy result: %+v", a)
						}
						if c.Replay(*u, tr).Status != "completed" {
							t.Fatal("Python exact replay failed")
						}
						u.Assessment = a
					}
					if count != 1 {
						t.Fatalf("SQL candidates %d", count)
					}
					report.Enrich(r)
					assertComponentReportParity(t, r)
				})
			}
		})
	}
}
