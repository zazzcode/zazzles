package cli

import (
	"bytes"
	"encoding/json"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"os"
	"path/filepath"
	"testing"
)

func TestPythonCLI(t *testing.T) {
	root := t.TempDir()
	out := t.TempDir()
	for name, src := range map[string]string{
		"app.py":    "from flask import Flask,request\napp=Flask(__name__)\n@app.get('/python')\ndef handler():\n    return request.args.get('name')\n",
		"server.js": "import express from 'express';const app=express();app.get('/js',(req,res)=>res.send(req.query.name))",
	} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(src), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, entry := range []string{"app.py", ""} {
		var stdout, stderr bytes.Buffer
		args := []string{"--analyze", "--json", "--output-dir", out}
		if entry != "" {
			args = append(args, "--entry", entry)
		}
		args = append(args, root)
		if code := run(args, &stdout, &stderr); code != exitOK {
			t.Fatalf("entry %q: %s", entry, stderr.String())
		}
		var r analysis.AnalysisReport
		if err := json.Unmarshal(stdout.Bytes(), &r); err != nil {
			t.Fatal(err)
		}
		want := 1
		if entry == "" {
			want = 2
		}
		if len(r.Entries) != want {
			t.Fatalf("entry %s routes=%d want %d", entry, len(r.Entries), want)
		}
		found := false
		for _, u := range r.Uses {
			found = found || (u.XSS != nil && u.XSS.Protection == "raw" && u.Sink.Span.File == "app.py")
		}
		if !found {
			t.Error("Python rendering missing from CLI")
		}
	}
	dirs, err := filepath.Glob(filepath.Join(out, filepath.Base(root), "run-*"))
	if err != nil || len(dirs) != 2 {
		t.Fatalf("bundles %v %v", dirs, err)
	}
	for _, dir := range dirs {
		for _, name := range []string{"findings.json", "findings.html", "findings.sarif"} {
			if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
				t.Fatal(err)
			}
		}
	}
}
