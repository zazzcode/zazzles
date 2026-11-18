package judge

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/internal/pipeline"
	reportpkg "github.com/zazzcode/zazzles/internal/report"
)

func TestPythonEvidenceDecisionReportPipeline(t *testing.T) {
	root := t.TempDir()
	source := `from flask import Flask,request
import sqlite3,logging
app=Flask(__name__)
@app.get('/')
def index():
    name=request.args.get('name')
    c=sqlite3.connect(':memory:')
    c.execute('select ' + name)
    logging.info(request.form.get('email'))
    return name
`
	if err := os.WriteFile(filepath.Join(root, "app.py"), []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := pipeline.Analyze(root, "app.py")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var body struct {
			Input     string `json:"input"`
			Questions []struct {
				Name string `json:"name"`
			} `json:"questions"`
		}
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		if !strings.Contains(body.Input, `"id":"python"`) || !strings.Contains(body.Input, `"version":"3"`) {
			t.Error("Python analysis guidelines not transmitted")
		}
		answers := []map[string]string{}
		choices := map[string]string{"validation": "uncertain", "protection": "insufficient", "injection_protection": "vulnerable", "output_context": "html_text", "encoding_adequacy": "not_present", "sanitizer_effectiveness": "absent", "xss_all_paths_protected": "no", "xss_exposure": "vulnerable", "data_class": "personal_data", "content_exposure": "yes", "redaction": "no", "log_exposure": "vulnerable"}
		for _, q := range body.Questions {
			answers = append(answers, map[string]string{"type": "choice", "name": q.Name, "choice": choices[q.Name]})
		}
		json.NewEncoder(w).Encode(map[string]any{"model": "gpt-6-luna", "answers": answers})
	}))
	defer server.Close()
	c, err := New("openai", "gpt-6-luna", "test-key")
	if err != nil {
		t.Fatal(err)
	}
	c.endpoint = server.URL
	c.http = server.Client()
	assessed := 0
	for i := range r.Uses {
		u := &r.Uses[i]
		if u.Kind != "sql_query_candidate" && u.Kind != "xss_candidate" && u.Kind != "log_sink_candidate" {
			continue
		}
		a, trace := c.AssessTrace(context.Background(), *u)
		u.Assessment = a
		assessed++
		if a.FindingStatus != "confirmed_vulnerability" {
			t.Errorf("%s: %+v", u.Kind, a)
		}
		if strings.Contains(string(trace.Request), "test-key") {
			t.Error("credential leaked into source trace")
		}
	}
	if assessed != 3 {
		t.Fatalf("assessed %d uses, want SQL/XSS/logging", assessed)
	}
	reportpkg.Enrich(r)
	count := 0
	for _, f := range r.Findings {
		if f.Status == "confirmed_vulnerability" {
			count++
		}
	}
	if count != 3 {
		t.Fatalf("confirmed report records %d", count)
	}
}
