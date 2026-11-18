package pipeline

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFixture(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, text := range files {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(text), 0644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// TestPHPMixedRepository needs every runner, so it lives with the pipeline
// rather than in internal/langphp.
func TestPHPMixedRepository(t *testing.T) {
	root := writeFixture(t, map[string]string{
		"page.php":  "<?php echo $_GET['x'];",
		"app.py":    "from flask import Flask,request\napp=Flask(__name__)\n@app.get('/py')\ndef h():\n    return request.args.get('name')\n",
		"server.js": "import express from 'express';const app=express();app.get('/js',(req,res)=>res.send(req.query.name))",
	})
	r, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	phpEntries, pyEntries, jsEntries := 0, 0, 0
	for _, e := range r.Entries {
		if e.HTTP == nil {
			continue
		}
		switch e.HTTP.Framework {
		case "php":
			phpEntries++
		case "flask":
			pyEntries++
		case "express":
			jsEntries++
		}
	}
	if phpEntries != 1 || pyEntries != 1 || jsEntries != 1 {
		t.Fatalf("mixed entries php=%d py=%d js=%d", phpEntries, pyEntries, jsEntries)
	}
}
