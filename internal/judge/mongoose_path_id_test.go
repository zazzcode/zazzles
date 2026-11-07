package judge

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/parse"
	"github.com/zazzcode/zazzles/internal/report"
)

func TestMongoosePathIDJudgment(t *testing.T) {
	for _, tc := range []struct {
		name, input, middleware, answer, want string
		removeEvidence                        bool
	}{
		{name: "path ID protected", input: "req.params.id", answer: "protected", want: "protected_for_claim"},
		{name: "uncertainty is retained", input: "req.params.id", answer: "unknown", want: "needs_evidence"},
		{name: "contradictory vulnerability is blocked", input: "req.params.id", answer: "vulnerable", want: "needs_evidence"},
		{name: "missing source evidence is blocked", input: "req.params.id", answer: "protected", want: "needs_evidence", removeEvidence: true},
		{name: "body operator remains unsafe", input: "req.body.id", answer: "vulnerable", want: "confirmed_vulnerability"},
		{name: "unknown middleware blocks protection", input: "req.params.id", middleware: "app.use(unknown);", answer: "protected", want: "needs_evidence"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			operation := "Todo.findById(" + tc.input + ",(err,todo)=>res.json(todo))"
			if tc.name == "body operator remains unsafe" {
				operation = "Todo.find({content:req.body.id},(err,todo)=>res.json(todo))"
			}
			for name, text := range map[string]string{
				"package.json": `{"dependencies":{"mongoose":"4.2.4"}}`,
				"server.js":    `const express=require('express');const mongoose=require('mongoose');const Todo=mongoose.model('Todo',new mongoose.Schema({content:String}));const app=express();app.use(express.json());` + tc.middleware + `app.post('/update/:id',(req,res)=>{` + operation + `;});`,
			} {
				if err := os.WriteFile(filepath.Join(root, name), []byte(text), 0600); err != nil {
					t.Fatal(err)
				}
			}
			r, err := parse.Analyze(root, "")
			if err != nil {
				t.Fatal(err)
			}
			var u analysis.CandidateUse
			for _, candidate := range r.Uses {
				if candidate.Kind == "nosql_query_candidate" {
					u = candidate
				}
			}
			if u.ID == "" {
				t.Fatal("missing query candidate")
			}
			if tc.removeEvidence {
				u.InputFacts = nil
				u.Completeness.Required = nil
			}
			answers := map[string]string{"validation": "uncertain", "protection": "uncertain", "injection_protection": tc.answer, "all_paths_protected": "yes", "source_coverage": "yes", "library_coverage": "yes", "guard_coverage": "yes", "path_coverage": "yes"}
			if tc.answer == "vulnerable" {
				answers["all_paths_protected"] = "no"
			}
			stub := fixedAnswerStub(t, answers)
			defer stub.Close()
			c, _ := New("openai", "fixture-model", "synthetic-test-key")
			c.endpoint = stub.URL
			c.http = stub.Client()
			a, tr := c.AssessTrace(context.Background(), u)
			if a.FindingStatus != tc.want {
				t.Fatalf("want %s got %+v", tc.want, a)
			}
			if a.Status == "completed" && c.Replay(u, tr).FindingStatus != tc.want {
				t.Fatal("exact replay changed result")
			}
			if tc.name != "path ID protected" {
				return
			}
			p, err := c.payload(u)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(p, []byte("input_facts")) || !bytes.Contains(p, []byte("ObjectId")) {
				t.Fatal("request omitted source/operation semantics")
			}
			changed := u
			changed.APIModel = &analysis.APIModel{ID: "mongoose-model-query-v2", Library: "mongoose"}
			if replay := c.Replay(changed, tr); replay.Status == "completed" {
				t.Fatal("changed contract reused old answer")
			}
			u.Assessment = a
			r.Uses = []analysis.CandidateUse{u}
			report.Enrich(r)
			var saved analysis.AnalysisReport
			raw, _ := json.Marshal(r)
			if err := json.Unmarshal(raw, &saved); err != nil {
				t.Fatal(err)
			}
			if saved.Findings[0].Status != "protected_for_claim" {
				t.Fatal("JSON lost protection")
			}
			if strings.Contains(strings.ToLower(saved.Findings[0].Title), "review") || !strings.Contains(saved.Findings[0].Summary, "ObjectId") {
				t.Fatal("protected record still describes unresolved type semantics")
			}
			var page bytes.Buffer
			if err := report.HTML(&page, &saved); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(page.String(), "NoSQL Injection <span class=\"pill-status\">· protected") {
				t.Fatal("HTML pill lost protection")
			}
			sarif := report.SARIF(&saved)
			runs := sarif["runs"].([]any)
			results := runs[0].(map[string]any)["results"].([]any)
			if len(results) != 1 || results[0].(map[string]any)["kind"] != "pass" {
				t.Fatal("SARIF disagrees with protected JSON")
			}
		})
	}
}
