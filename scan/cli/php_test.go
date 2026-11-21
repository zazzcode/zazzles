package cli

import (
	"bytes"
	"encoding/json"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"os"
	"path/filepath"
	"testing"
)

func TestPHPCLI(t *testing.T) {
	root := t.TempDir()
	out := t.TempDir()
	for name, src := range map[string]string{
		"page.php":  "<?php\n$id = $_GET['id'];\n$html = '';\n$html .= \"<pre>{$id}</pre>\";\necho $html;\n",
		"server.js": "import express from 'express';const app=express();app.get('/js',(req,res)=>res.send(req.query.name))",
	} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(src), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, entry := range []string{"page.php", ""} {
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
		wantPHP := 1
		if entry == "" {
			wantPHP = 2 // PHP file entry plus the JS route entry
		}
		if len(r.Entries) != wantPHP {
			t.Fatalf("entry %q entries=%d want %d", entry, len(r.Entries), wantPHP)
		}
		found := false
		for _, u := range r.Uses {
			found = found || (u.XSS != nil && u.XSS.Protection == "raw" && u.Sink.Span.File == "page.php")
		}
		if !found {
			t.Error("PHP rendering missing from CLI")
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
