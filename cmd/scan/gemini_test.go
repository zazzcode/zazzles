package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/judge"
)

func TestGeminiScanBundleAndLimit(t *testing.T) {
	for _, name := range []string{"SCAN_OPENAI_MODEL", "SCAN_GEMINI_MODEL", "SCAN_JEV_MODEL"} {
		t.Setenv(name, "")
	}
	t.Setenv("JUDGE_DECISION_MODEL", "gemini-decision-1")
	t.Setenv("GEMINI_API_KEY", "synthetic-google-key")
	calls := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("x-goog-api-key") != "synthetic-google-key" {
			t.Error("wrong selected credential")
		}
		var body struct {
			Questions map[string]struct{ Criteria map[string]string }
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
			return
		}
		answers := map[string]any{}
		for name, q := range body.Questions {
			choice := "unknown"
			if _, ok := q.Criteria[choice]; !ok {
				choice = "uncertain"
			}
			if _, ok := q.Criteria[choice]; !ok {
				keys := []string{}
				for key := range q.Criteria {
					keys = append(keys, key)
				}
				sort.Strings(keys)
				choice = keys[0]
			}
			answers[name] = map[string]string{"type": "choice", "choice": choice}
		}
		json.NewEncoder(w).Encode(map[string]any{"answers": answers})
	}))
	defer s.Close()
	old := newJudgeClient
	t.Cleanup(func() { newJudgeClient = old })
	newJudgeClient = func(provider, model, key string) (*judge.Client, error) {
		c, err := judge.New(provider, model, key)
		if err == nil {
			c.UseEndpoint(s.URL, s.Client())
		}
		return c, err
	}
	for _, limit := range []string{"20", "1"} {
		t.Run(limit, func(t *testing.T) {
			root := t.TempDir()
			source := `import express from 'express';import {exec} from 'node:child_process';const app=express();app.get('/ping',(req,res)=>{exec('ping '+req.query.host);res.send('done')});`
			if err := os.WriteFile(filepath.Join(root, "server.ts"), []byte(source), 0600); err != nil {
				t.Fatal(err)
			}
			outDir := t.TempDir()
			var out, stderr bytes.Buffer
			code := run([]string{"--analyze", "--json", "--judge", "gemini", "--judge-limit", limit, "--output-dir", outDir, root}, &out, &stderr)
			if limit == "20" && code != exitOK {
				t.Fatalf("code=%d error=%s", code, stderr.String())
			}
			if limit == "1" && code != exitError {
				t.Fatalf("limit did not leave scan incomplete: code=%d", code)
			}
			var report analysis.AnalysisReport
			if err := json.Unmarshal(out.Bytes(), &report); err != nil {
				t.Fatal(err)
			}
			completed := 0
			for _, u := range report.Uses {
				if u.Assessment.Status == "completed" {
					completed++
					if u.Assessment.Provider != "gemini" || u.Assessment.Model != "gemini-decision-1" {
						t.Fatal("wrong provider attribution")
					}
				}
			}
			if completed == 0 {
				t.Fatal("no judgments")
			}
			for _, ext := range []string{"json", "html", "sarif"} {
				files, _ := filepath.Glob(filepath.Join(outDir, "*", "*", "findings."+ext))
				if len(files) != 1 {
					t.Fatalf("missing %s bundle: %v", ext, files)
				}
			}
		})
	}
	if calls == 0 {
		t.Fatal("no stub requests")
	}
}
