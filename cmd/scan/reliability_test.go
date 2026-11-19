package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/zazzcode/zazzles/internal/judge"
)

// TestJudgeStopExitsWithReason: only a stopped judge fails a CI run. A
// rejected key stops the scan after one request, exits 1 and logs why;
// a candidate-level 400 is warned about and exits 0.
func TestJudgeStopExitsWithReason(t *testing.T) {
	root := t.TempDir()
	source := `const express=require('express');const cp=require('child_process');const fs=require('fs');const app=express();
app.get('/a',(req,res)=>{cp.exec(req.query.cmd);fs.readFileSync(req.query.file);res.send('ok')});`
	if err := os.WriteFile(filepath.Join(root, "server.js"), []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		status      int
		code        int
		stderr      string
		maxRequests int64
	}{
		{http.StatusUnauthorized, exitError, "scan: judge stopped: decision model account or credentials rejected (judge HTTP 401)", 1},
		{http.StatusBadRequest, exitOK, "scan: warning: some assessments are incomplete", 100},
	} {
		t.Setenv("OPENAI_API_KEY", "offline")
		t.Setenv("JUDGE_DECISION_MODEL", "")
		t.Setenv("SCAN_FINDINGS_DIR", "")
		var calls atomic.Int64
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			w.WriteHeader(tc.status)
		}))
		old := newJudgeClient
		newJudgeClient = func(provider, model, key string) (*judge.Client, error) {
			c, err := judge.New(provider, model, key)
			if err == nil {
				c.UseEndpoint(server.URL, server.Client())
			}
			return c, err
		}
		var out, stderr bytes.Buffer
		code := run([]string{"--analyze", "--json", "--judge", "openai", "--judge-concurrency", "1", root}, &out, &stderr)
		newJudgeClient = old
		server.Close()
		if code != tc.code || !strings.Contains(stderr.String(), tc.stderr) || calls.Load() == 0 || calls.Load() > tc.maxRequests {
			t.Fatalf("status %d: code=%d calls=%d stderr=%s", tc.status, code, calls.Load(), stderr.String())
		}
	}
}
