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

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
	"github.com/zazzcode/zazzles/scan/internal/pipeline"
	"github.com/zazzcode/zazzles/scan/internal/report"
)

func packageCallReport(t *testing.T, imports, setup, body string) (*analysis.AnalysisReport, analysis.CandidateUse) {
	t.Helper()
	root := t.TempDir()
	src := "import express from 'express'\n" + imports + "\nconst app = express()\n" + setup + "\napp.get('/r', async (req, res) => {\n  const id = req.query.id\n  " + body + "\n  res.json({})\n})\napp.listen(3000)\n"
	if err := os.WriteFile(filepath.Join(root, "app.js"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := pipeline.AnalyzeWithChecks(root, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range r.Uses {
		if packageSQL(u) {
			return r, u
		}
	}
	t.Fatal("no package SQL record")
	return nil, analysis.CandidateUse{}
}

// assessPackageCall answers every question of the record's real request; cite
// picks the citation choice from the offered values.
func assessPackageCall(t *testing.T, u analysis.CandidateUse, call, injection string, cite func(choices []string) string) (analysis.Assessment, DecisionTrace, *Client) {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Questions []struct {
				Name    string              `json:"name"`
				Choices []map[string]string `json:"choices"`
			} `json:"questions"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
		}
		var answers []map[string]any
		for _, q := range req.Questions {
			values := []string{}
			for _, c := range q.Choices {
				values = append(values, c["value"])
			}
			v := "none"
			switch {
			case strings.HasPrefix(q.Name, sqlCallPrefix) && strings.HasSuffix(q.Name, citeSuffix):
				v = cite(values)
			case strings.HasPrefix(q.Name, sqlCallPrefix):
				v = call
			case q.Name == "injection_protection":
				v = injection
			case q.Name == "validation", q.Name == "protection":
				v = "insufficient"
			}
			answers = append(answers, map[string]any{"name": q.Name, "type": "choice", "choice": v, "confidence": 0.9, "probabilities": []map[string]any{{"value": v, "probability": 0.9}}})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"model": "fixture-model", "answers": answers, "usage": map[string]int{"input_tokens": 1}})
	}))
	t.Cleanup(s.Close)
	c, err := New("openai", "fixture-model", "synthetic-test-key")
	if err != nil {
		t.Fatal(err)
	}
	c.UseEndpoint(s.URL, nil)
	a, trace := c.AssessTrace(context.Background(), u)
	if a.Status != "completed" {
		t.Fatalf("assessment %s: %s", a.Status, a.Reason)
	}
	return a, trace, c
}

// citing picks the offered citation whose import is, or is not, the callee's.
func citing(own map[string]bool, want bool) func([]string) string {
	return func(choices []string) string {
		for _, c := range choices {
			if c != citeNone && own[c] == want {
				return c
			}
		}
		return citeNone
	}
}

func TestSQLCallResolution(t *testing.T) {
	_, u := packageCallReport(t, "import oracledb from 'oracledb'", "const conn = await oracledb.getConnection({})", "await conn.execute(`SELECT * FROM users WHERE id = ${id}`)")
	if _, gated := resolutionGate(u); gated {
		t.Fatal("an askable package record must be sent")
	}
	preview, err := New("openai", "fixture-model", "synthetic-test-key")
	if err != nil {
		t.Fatal(err)
	}
	trace, err := preview.Preview(u)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := requestUse(trace.Request)
	if err != nil {
		t.Fatal(err)
	}
	x, err := indexWire(wire)
	if err != nil {
		t.Fatal(err)
	}
	ownChoice := map[string]bool{}
	for _, q := range payloadResolutionQuestions(trace.Request) {
		if strings.HasPrefix(q.name, sqlCallPrefix) && strings.HasSuffix(q.name, citeSuffix) {
			for _, c := range q.choices {
				if id, _, ok := strings.Cut(c["value"], ">"); ok {
					ownChoice[c["value"]] = strings.Contains(x.evidence[id].text, "oracledb")
				}
			}
		}
	}
	if len(ownChoice) < 2 {
		t.Fatalf("the citation must offer the callee's import and another: %v", ownChoice)
	}
	if trace.QuestionVersion != analysispacks.SQLProtocol {
		t.Fatalf("the family protocol must not change: %s", trace.QuestionVersion)
	}
	own, other := citing(ownChoice, true), citing(ownChoice, false)
	none := func([]string) string { return citeNone }
	for _, tt := range []struct {
		name, call, injection string
		cite                  func([]string) string
		status                string
		resolved              bool
	}{
		{"verified executes", "executes", "vulnerable", own, "confirmed_vulnerability", true},
		{"verified prepares", "prepares_then_executes", "vulnerable", own, "confirmed_vulnerability", true},
		{"uncited", "executes", "vulnerable", none, "needs_evidence", false},
		{"another import", "executes", "vulnerable", other, "needs_evidence", false},
		{"not sql", "not_sql", "vulnerable", own, "needs_evidence", false},
		{"bound only contradicts the call", "bound_only", "vulnerable", own, "needs_evidence", false},
		{"cannot tell", "cannot_tell", "vulnerable", own, "needs_evidence", false},
		{"never protected", "executes", "protected", own, "needs_evidence", true},
		{"never dismissed", "executes", "not_applicable", own, "needs_evidence", true},
		{"unknown injection", "executes", "unknown", own, "needs_evidence", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			a, tr, c := assessPackageCall(t, u, tt.call, tt.injection, tt.cite)
			if a.FindingStatus != tt.status || a.ModelResolved() != tt.resolved {
				t.Fatalf("status %s model-resolved %v reason %q blockers %+v resolutions %+v", a.FindingStatus, a.ModelResolved(), a.Reason, a.BlockingGaps, a.Resolutions)
			}
			if a.Protection == "sufficient" {
				t.Fatal("a model-resolved callee never gives Protected")
			}
			again := c.Replay(u, tr)
			if again.FindingStatus != a.FindingStatus || again.RequestDigest != a.RequestDigest {
				t.Fatalf("replay differs: %s %s", again.FindingStatus, again.Reason)
			}
		})
	}
}

// Text that reads as SQL but goes to a package that is no database is sent, and
// is never a finding without a verified answer that it runs as SQL.
func TestSQLCallLookalikeIsNotReported(t *testing.T) {
	for _, tt := range []struct{ name, imports, setup, body string }{
		{"mail", "import mailer from 'nodemailer'", "const transport = mailer.createTransport({})", "await transport.sendMail({ text: `SELECT name FROM users WHERE id = ${id}` })"},
		{"log", "import pino from 'pino'", "const logger = pino()", "logger.child({}).trace(`SELECT name FROM users WHERE id = ${id}`)"},
		{"search", "import { Client } from '@elastic/elasticsearch'", "const es = new Client({})", "await es.index({ document: `DELETE FROM users WHERE id = ${id}` })"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r, u := packageCallReport(t, tt.imports, tt.setup, tt.body)
			report.Enrich(r)
			for _, f := range r.Findings {
				if f.UseID == u.ID && f.RecordType == "finding" {
					t.Fatalf("unjudged lookalike reported: %s %s", f.Status, f.Title)
				}
			}
			a, _, _ := assessPackageCall(t, u, "not_sql", "not_applicable", func(c []string) string { return c[0] })
			if a.FindingStatus != "needs_evidence" || a.ModelResolved() {
				t.Fatalf("status %s", a.FindingStatus)
			}
		})
	}
}
