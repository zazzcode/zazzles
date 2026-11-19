package main

import (
	"bytes"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestJudgeLimitConfiguration(t *testing.T) {
	for _, tt := range []struct {
		name    string
		args    []string
		env     map[string]string
		wantErr bool
		rpm     int
		tpm     int64
		limit   int
		conc    int
	}{
		{"environment", nil, map[string]string{"JUDGE_RPM": "60", "JUDGE_TPM": "600000", "JUDGE_LIMIT": "30", "JUDGE_CONCURRENCY": "2"}, false, 60, 600000, 30, 2},
		{"flags override", []string{"--judge-rpm=2", "--judge-tpm=50000", "--judge-limit=5", "--judge-concurrency=8"}, map[string]string{"JUDGE_RPM": "invalid", "JUDGE_TPM": "invalid", "JUDGE_LIMIT": "invalid", "JUDGE_CONCURRENCY": "invalid"}, false, 2, 50000, 5, 8},
		{"malformed", nil, map[string]string{"JUDGE_RPM": "NaN"}, true, 0, 0, 0, 0},
		{"negative", nil, map[string]string{"JUDGE_TPM": "-1"}, true, 0, 0, 0, 0},
		{"overflow", nil, map[string]string{"JUDGE_RPM": "9999999999999999999999"}, true, 0, 0, 0, 0},
		{"bad limit", nil, map[string]string{"JUDGE_LIMIT": "no"}, true, 0, 0, 0, 0},
		{"removed cost environment ignored", nil, map[string]string{"JUDGE_BUDGET_USD": "invalid", "JUDGE_INPUT_USD_PER_MILLION": "invalid"}, false, 0, 0, noJudgeLimit, 4},
		{"concurrency default", nil, nil, false, 0, 0, noJudgeLimit, 4},
		{"concurrency serial", []string{"--judge-concurrency=1"}, nil, false, 0, 0, noJudgeLimit, 1},
		{"concurrency zero", []string{"--judge-concurrency=0"}, nil, true, 0, 0, 0, 0},
		{"concurrency negative", []string{"--judge-concurrency=-2"}, nil, true, 0, 0, 0, 0},
		{"concurrency non-integer", []string{"--judge-concurrency=2.5"}, nil, true, 0, 0, 0, 0},
		{"concurrency empty flag", []string{"--judge-concurrency="}, map[string]string{"JUDGE_CONCURRENCY": "3"}, true, 0, 0, 0, 0},
		{"concurrency environment zero", nil, map[string]string{"JUDGE_CONCURRENCY": "0"}, true, 0, 0, 0, 0},
		{"concurrency environment non-integer", nil, map[string]string{"JUDGE_CONCURRENCY": "four"}, true, 0, 0, 0, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fs := flag.NewFlagSet("test", flag.ContinueOnError)
			fs.SetOutput(io.Discard)
			fs.Int("judge-limit", 0, "")
			f := addJudgeLimitFlags(fs)
			if err := fs.Parse(tt.args); err != nil {
				t.Fatal(err)
			}
			runtime, limit, err := f.resolve(fs, func(k string) string { return tt.env[k] })
			if (err != nil) != tt.wantErr {
				t.Fatalf("error=%v", err)
			}
			cfg := runtime.limits
			if err == nil && (cfg.RPM != tt.rpm || cfg.TPM != tt.tpm || limit != tt.limit || runtime.concurrency != tt.conc) {
				t.Fatalf("runtime=%+v limit=%d", runtime, limit)
			}
		})
	}
}

func TestJudgeTPMProducesIncompleteThreeFormatBundle(t *testing.T) {
	for _, key := range []string{"SCAN_OPENAI_MODEL", "SCAN_GEMINI_MODEL", "SCAN_JEV_MODEL", "JUDGE_RPM", "JUDGE_TPM", "JUDGE_LIMIT"} {
		t.Setenv(key, "")
	}
	t.Setenv("JUDGE_DECISION_MODEL", "gpt-6-luna")
	t.Setenv("OPENAI_API_KEY", "synthetic-noncredential")
	root, outDir := t.TempDir(), t.TempDir()
	source := `import express from 'express';import fs from 'node:fs';const app=express();app.get('/file',(req,res)=>{fs.readFileSync(req.query.name);});`
	if err := os.WriteFile(filepath.Join(root, "app.js"), []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	var out, stderr bytes.Buffer
	code := run([]string{"--analyze", "--json", "--judge", "openai", "--judge-tpm=1", "--output-dir", outDir, root}, &out, &stderr)
	if code != exitOK || !strings.Contains(stderr.String(), "scan: warning: some assessments are incomplete") || !strings.Contains(out.String(), "judge limit: request token reservation") {
		t.Fatalf("code=%d out=%s stderr=%s", code, out.String(), stderr.String())
	}
	for _, ext := range []string{"json", "html", "sarif"} {
		paths, _ := filepath.Glob(filepath.Join(outDir, "*", "*", "findings."+ext))
		if len(paths) != 1 {
			t.Fatalf("missing %s", ext)
		}
		data, err := os.ReadFile(paths[0])
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(data), "Decision-model limits") {
			t.Fatalf("%s lacks accounting", ext)
		}
	}
	t.Setenv("JUDGE_TPM", "NaN")
	out.Reset()
	stderr.Reset()
	if code := run([]string{"--analyze", "--json", root}, &out, &stderr); code != exitOK {
		t.Fatalf("offline code=%d: %s", code, stderr.String())
	}
}

func TestRemovedCostFlagsRejected(t *testing.T) {
	for _, name := range []string{"--judge-budget-usd=1", "--judge-input-usd-per-million=.1"} {
		var out, stderr bytes.Buffer
		if code := run([]string{"--analyze", "--judge", "openai", name, t.TempDir()}, &out, &stderr); code != exitUsage {
			t.Fatalf("%s exit=%d", name, code)
		}
	}
}

func TestJudgeConcurrencyUsageErrors(t *testing.T) {
	t.Setenv("JUDGE_CONCURRENCY", "")
	t.Setenv("OPENAI_API_KEY", "synthetic-noncredential")
	for _, value := range []string{"0", "-1", "two", "1.5"} {
		var out, stderr bytes.Buffer
		if code := run([]string{"--analyze", "--judge", "openai", "--judge-concurrency=" + value, t.TempDir()}, &out, &stderr); code != exitUsage || !strings.Contains(stderr.String(), "--judge-concurrency requires a positive integer") {
			t.Fatalf("%s: exit=%d stderr=%s", value, code, stderr.String())
		}
	}
	t.Setenv("JUDGE_CONCURRENCY", "0")
	var out, stderr bytes.Buffer
	if code := run([]string{"--analyze", "--judge", "openai", t.TempDir()}, &out, &stderr); code != exitUsage {
		t.Fatalf("environment zero: exit=%d", code)
	}
}
