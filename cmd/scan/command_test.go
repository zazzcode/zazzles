package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/judge"
)

const commandCLIApp = `const express=require('express');const {exec}=require('child_process');const app=express();
app.get('/ping',(req,res)=>{exec('ping -c 1 '+req.query.host,()=>{});res.end()});
app.post('/signup',(req,res)=>{const e=req.body.email;res.end()});`

func commandStubClient(t *testing.T, requests *int) func(string, string, string) (*judge.Client, error) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*requests++
		var body struct {
			Questions []struct {
				Name string `json:"name"`
			} `json:"questions"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		answers := []map[string]string{}
		for _, q := range body.Questions {
			choice := map[string]string{"shell_syntax_protection": "vulnerable", "executable_control": "not_applicable", "argument_control": "not_applicable", "protection_coverage": "incomplete", "field_requirement": "unknown", "validation": "uncertain", "enforcement_coverage": "incomplete"}[q.Name]
			answers = append(answers, map[string]string{"name": q.Name, "type": "choice", "choice": choice})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"model": "fixture-model", "answers": answers})
	}))
	t.Cleanup(server.Close)
	return func(provider, model, key string) (*judge.Client, error) {
		c, err := judge.New(provider, model, "synthetic-key")
		if err == nil {
			c.UseEndpoint(server.URL, server.Client())
		}
		return c, err
	}
}

func TestCommandCLI(t *testing.T) {
	t.Setenv("SCAN_FINDINGS_DIR", "")
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "server.js"), []byte(commandCLIApp), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Run("structural mode makes no judgment and shows Review", func(t *testing.T) {
		var out, errOut bytes.Buffer
		if code := run([]string{"--analyze", "--json", root}, &out, &errOut); code != exitOK {
			t.Fatalf("exit %d: %s", code, errOut.String())
		}
		var r analysis.AnalysisReport
		if err := json.Unmarshal(out.Bytes(), &r); err != nil {
			t.Fatal(err)
		}
		found := 0
		for _, u := range r.Uses {
			if u.Kind == "command_execution_candidate" {
				found++
				if u.Assessment.Status != "not_run" || u.Assessment.FindingStatus != "" {
					t.Fatalf("structural mode produced a verdict: %+v", u.Assessment)
				}
			}
		}
		if found != 1 {
			t.Fatalf("command candidates = %d", found)
		}
	})
	t.Run("full judged scan with the input-validation analyzer skipped", func(t *testing.T) {
		requests := 0
		old := newJudgeClient
		newJudgeClient = commandStubClient(t, &requests)
		t.Cleanup(func() { newJudgeClient = old })
		t.Setenv("OPENAI_API_KEY", "synthetic-key")
		outDir := t.TempDir()
		var out, errOut bytes.Buffer
		code := run([]string{"--analyze", "--judge", "openai", "--judge-model", "gpt-6-luna", "--judge-limit", "20", "--skip-family", "input-validation", "--output-dir", outDir, root}, &out, &errOut)
		if code != exitOK {
			t.Fatalf("exit %d: %s", code, errOut.String())
		}
		var runs []string
		_ = filepath.WalkDir(outDir, func(path string, d os.DirEntry, err error) error {
			if err == nil && d.Name() == "findings.json" {
				runs = append(runs, path)
			}
			return nil
		})
		if len(runs) != 1 {
			t.Fatalf("bundle files: %v", runs)
		}
		raw, _ := os.ReadFile(runs[0])
		var r analysis.AnalysisReport
		if err := json.Unmarshal(raw, &r); err != nil {
			t.Fatal(err)
		}
		if len(r.SkippedFamilies) != 1 || r.SkippedFamilies[0] != "input-validation" {
			t.Fatalf("skipped families not recorded: %v", r.SkippedFamilies)
		}
		confirmed, skipped := 0, 0
		for _, u := range r.Uses {
			switch u.Kind {
			case "command_execution_candidate":
				if u.Assessment.FindingStatus == "confirmed_vulnerability" {
					confirmed++
				}
			case "input_validation_candidate":
				if u.Assessment.Status != "not_run" || !strings.Contains(u.Assessment.Reason, "analyzer not used") {
					t.Fatalf("validation record was judged or lacks the reason: %+v", u.Assessment)
				}
				skipped++
			}
		}
		if confirmed != 1 || skipped == 0 {
			t.Fatalf("confirmed %d skipped %d", confirmed, skipped)
		}
		if requests != len(r.Uses)-skipped {
			t.Fatalf("requests %d for %d judged uses", requests, len(r.Uses)-skipped)
		}
		limited := false
		for _, l := range r.Limitations {
			limited = limited || strings.Contains(l, "input-validation analyzer was not used")
		}
		html, _ := os.ReadFile(filepath.Join(filepath.Dir(runs[0]), "findings.html"))
		sarif, _ := os.ReadFile(filepath.Join(filepath.Dir(runs[0]), "findings.sarif"))
		if !limited || !strings.Contains(string(html), "Analyzer not used in this run") || !strings.Contains(string(sarif), "skippedFamilies") {
			t.Fatal("JSON, HTML and SARIF must all state the skipped analyzer")
		}
	})
	t.Run("option validation", func(t *testing.T) {
		for _, args := range [][]string{{"--analyze", "--skip-family", "input-validation", root}, {"--analyze", "--judge", "openai", "--skip-family", "xss", root}} {
			var out, errOut bytes.Buffer
			if code := run(args, &out, &errOut); code != exitUsage {
				t.Fatalf("%v exit %d", args, code)
			}
		}
	})
}
