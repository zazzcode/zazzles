package main

import (
	"bytes"
	"encoding/json"
	htmlpkg "html"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
	"github.com/zazzcode/zazzles/internal/judge"
	reportpkg "github.com/zazzcode/zazzles/internal/report"
)

func TestCLIFamilySelection(t *testing.T) {
	for _, args := range [][]string{
		{"--only-family", "unknown"},
		{"--only-family", "path", "--skip-family", "sql"},
	} {
		var out, stderr bytes.Buffer
		base := []string{"--analyze", "--judge", "openai"}
		base = append(base, args...)
		base = append(base, t.TempDir())
		if code := run(base, &out, &stderr); code != exitUsage {
			t.Fatalf("code=%d: %s", code, stderr.String())
		}
	}
	for _, family := range []string{"sql", "nosql", "xss", "command", "path", "logging", "input-validation", "outbound"} {
		if _, err := parseSkipFamilies(family); err != nil {
			t.Error(err)
		}
	}
}

func TestFamilySelectionReports(t *testing.T) {
	root := t.TempDir()
	source := `const express=require('express'); const fs=require('fs'); const cp=require('child_process');const app=express();
app.get('/scan',(req,res)=>{fs.readFileSync(req.query.file);cp.exec(req.query.cmd);console.log(req.query.password);fetch(req.query.url);res.send(req.query.html)});`
	if err := os.WriteFile(filepath.Join(root, "server.js"), []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, flag, value, env string
		allowed                map[string]bool
	}{
		{"only", "--only-family", "path,command", "", map[string]bool{"path": true, "command": true}},
		{"skip", "--skip-family", "outbound,input-validation,xss,logging", "", map[string]bool{"path": true, "command": true}},
		{"environment", "", "path,command", "JUDGE_ONLY_FAMILY", map[string]bool{"path": true, "command": true}},
		{"flag overrides environment", "--only-family", "path", "JUDGE_ONLY_FAMILY", map[string]bool{"path": true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("JUDGE_ONLY_FAMILY", "")
			t.Setenv("JUDGE_SKIP_FAMILY", "")
			t.Setenv("JUDGE_DECISION_MODEL", "")
			t.Setenv("SCAN_FINDINGS_DIR", "")
			t.Setenv("OPENAI_API_KEY", "offline")
			if tc.env != "" {
				t.Setenv(tc.env, "path,command")
			}
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				var body struct {
					Questions []struct {
						Name    string
						Choices []struct{ Value string }
					}
				}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
				}
				answers := []map[string]string{}
				for _, q := range body.Questions {
					answers = append(answers, map[string]string{"type": "choice", "name": q.Name, "choice": q.Choices[0].Value})
				}
				json.NewEncoder(w).Encode(map[string]any{"model": "fixture-model", "answers": answers, "usage": map[string]int{"input_tokens": 10}})
			}))
			defer server.Close()
			old := newJudgeClient
			defer func() { newJudgeClient = old }()
			newJudgeClient = func(provider, model, key string) (*judge.Client, error) {
				c, err := judge.New(provider, model, key)
				if err == nil {
					c.UseEndpoint(server.URL, server.Client())
				}
				return c, err
			}
			args := []string{"--analyze", "--json", "--judge", "openai", "--judge-limit", "100"}
			if tc.flag != "" {
				args = append(args, tc.flag, tc.value)
			}
			args = append(args, root)
			var out, stderr bytes.Buffer
			if code := run(args, &out, &stderr); code != exitOK {
				t.Fatalf("code=%d %s", code, stderr.String())
			}
			var report analysis.AnalysisReport
			if err := json.Unmarshal(out.Bytes(), &report); err != nil {
				t.Fatal(err)
			}
			completed := 0
			for _, u := range report.Uses {
				family := analysispacks.FamilySlugForKind(u.Kind)
				if tc.allowed[family] {
					if u.Assessment.Status != "completed" {
						t.Fatal(u.Assessment)
					}
					completed++
				} else if u.Assessment.Status != "not_run" || !strings.Contains(u.Assessment.Reason, "analyzer not used for this run") {
					t.Fatal(u.Assessment)
				}
			}
			if completed == 0 || calls != completed {
				t.Fatalf("calls=%d completed=%d", calls, completed)
			}
			b, _ := json.Marshal(reportpkg.SARIF(&report))
			var html bytes.Buffer
			reportpkg.HTML(&html, &report)
			for _, l := range report.Limitations {
				if !strings.Contains(string(b), l) || !strings.Contains(html.String(), htmlpkg.EscapeString(l)) {
					t.Fatalf("missing cross-format limitation %q", l)
				}
			}
		})
	}
}

func TestFamilyEnvironmentDoesNotAffectOfflineModes(t *testing.T) {
	t.Setenv("SCAN_FINDINGS_DIR", "")
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "server.js"), []byte(`const express=require('express');const app=express();app.get('/one',(req,res)=>res.send(req.query.value));`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"JUDGE_ONLY_FAMILY", "JUDGE_SKIP_FAMILY"} {
		t.Setenv(key, "unknown-family")
	}
	for _, mode := range []string{"--analyze", "--list", "--routes"} {
		var out, stderr bytes.Buffer
		if code := run([]string{mode, "--json", root}, &out, &stderr); code != exitOK {
			t.Fatalf("%s code=%d %s", mode, code, stderr.String())
		}
	}
	for _, name := range []string{"--only-family", "--skip-family"} {
		var out, stderr bytes.Buffer
		if code := run([]string{"--analyze", name, "command", root}, &out, &stderr); code != exitUsage {
			t.Fatalf("explicit %s code=%d", name, code)
		}
	}
}
