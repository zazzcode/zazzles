package pipeline_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/judge"
	"github.com/zazzcode/zazzles/internal/pipeline"
)

// Finalized reports, rather than internal flow values alone, must carry a
// complete native witness into the offline request builder.
func TestSummaryWitnessFinalizedCommandRequests(t *testing.T) {
	for _, language := range []string{"javascript", "typescript", "python", "php"} {
		t.Run(language, func(t *testing.T) {
			filename, source, left, right := summaryCommandSource(language)
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, filename), []byte(source), 0600); err != nil {
				t.Fatal(err)
			}
			report, err := pipeline.Analyze(root, "")
			if err != nil {
				t.Fatal(err)
			}
			client, err := judge.New("openai", "fixture-model", "never-persist-test-key")
			if err != nil {
				t.Fatal(err)
			}
			var uses []analysis.CandidateUse
			for _, u := range report.Uses {
				if u.Kind == "command_execution_candidate" {
					uses = append(uses, u)
				}
			}
			if len(uses) != 2 {
				t.Fatalf("deep helper sinks = %d; want both caller witnesses", len(uses))
			}
			sources := map[string]bool{}
			ids := map[string]bool{}
			var requests [][]byte
			for _, u := range uses {
				if ids[u.ID] {
					t.Fatal("different callers share candidate identity")
				}
				ids[u.ID] = true
				if u.Command == nil || len(u.Dependencies) == 0 {
					t.Fatalf("missing command witness: %+v", u)
				}
				if err := u.Command.Validate(len(u.Dependencies), len(u.Context)); err != nil {
					t.Fatal(err)
				}
				sourceForUse := ""
				for _, d := range u.Dependencies {
					name := ""
					sourceLine := d.Source.Text
					if line := d.Source.Span.StartLine; line > 0 && line <= len(strings.Split(source, "\n")) {
						sourceLine = strings.Split(source, "\n")[line-1]
					}
					if strings.Contains(sourceLine, left) {
						name = left
					}
					if strings.Contains(sourceLine, right) {
						if name != "" {
							t.Fatal("source mixes callers")
						}
						name = right
					}
					if name == "" {
						t.Fatalf("lost caller source: %+v", d.Source)
					}
					if sourceForUse != "" && sourceForUse != name {
						t.Fatal("one candidate borrowed sibling caller provenance")
					}
					sourceForUse = name
					sources[name] = true
					bindings := 0
					for _, e := range d.Transfers {
						if e.Kind == "parameter_binding" || e.Kind == "argument_to_parameter" {
							bindings++
						}
						if e.Span.File == filename && e.Text != "" && e.SHA256 == "" {
							t.Fatalf("unhashed transfer: %+v", e)
						}
					}
					if bindings < 3 {
						t.Fatalf("only %d parameter bindings in concrete helper witness: %+v", bindings, d.Transfers)
					}
				}
				for _, g := range u.Gaps {
					switch g.Kind {
					case "helper_call_limit", "path_unrelated_helper_limit", "work_limit":
						t.Fatalf("supported witness keeps inline limit: %+v", g)
					}
				}
				trace, err := client.Preview(u)
				if err != nil {
					t.Fatalf("native witness cannot build exact request: %v", err)
				}
				if len(trace.Request) == 0 || !json.Valid(trace.Request) {
					t.Fatal("invalid offline request")
				}
				if bytes.Contains(trace.Request, []byte("never-persist-test-key")) || bytes.Contains(trace.Request, []byte("summary_parameter")) {
					t.Fatal("synthetic input leaked into witness")
				}
				if _, err := client.EquivalenceSignature(u); err != nil {
					t.Fatal(err)
				}
				requests = append(requests, trace.Request)
			}
			if !sources[left] || !sources[right] {
				t.Fatalf("caller source set=%v", sources)
			}
			if bytes.Equal(requests[0], requests[1]) {
				t.Fatal("different callers share exact request bytes")
			}
			again, err := pipeline.Analyze(root, "")
			if err != nil {
				t.Fatal(err)
			}
			a, _ := json.Marshal(report)
			b, _ := json.Marshal(again)
			if !bytes.Equal(a, b) {
				t.Fatal("witness instantiation is nondeterministic")
			}
		})
	}
}

func summaryCommandSource(language string) (filename, source, left, right string) {
	left, right = "left_command", "right_command"
	switch language {
	case "javascript", "typescript":
		filename = "app.js"
		source = "const express = require('express');\nconst { exec } = require('child_process');\nconst app = express();\nfunction leaf(x) { exec(x); return x; }\n"
		for i := 4; i >= 0; i-- {
			next := "leaf"
			if i < 4 {
				next = fmt.Sprintf("h%d", i+1)
			}
			source += fmt.Sprintf("function h%d(x) { return %s(x); }\n", i, next)
		}
		source += "app.get('/left', (req,res) => { h0(req.query.left_command); res.send('done'); });\napp.get('/right', (req,res) => { h0(req.query.right_command); res.send('done'); });\n"
		if language == "typescript" {
			filename = "app.ts"
			source = strings.ReplaceAll(source, "function leaf(x)", "function leaf(x: string)")
			for i := 0; i <= 4; i++ {
				source = strings.ReplaceAll(source, fmt.Sprintf("function h%d(x)", i), fmt.Sprintf("function h%d(x: string)", i))
			}
		}
	case "python":
		filename = "app.py"
		source = "from flask import Flask, request\nimport os\napp=Flask(__name__)\ndef leaf(x):\n os.system(x)\n return x\n"
		for i := 4; i >= 0; i-- {
			next := "leaf"
			if i < 4 {
				next = fmt.Sprintf("h%d", i+1)
			}
			source += fmt.Sprintf("def h%d(x):\n return %s(x)\n", i, next)
		}
		source += "@app.get('/left')\ndef left():\n h0(request.args['left_command'])\n return 'done'\n@app.get('/right')\ndef right():\n h0(request.args['right_command'])\n return 'done'\n"
	case "php":
		filename = "index.php"
		source = "<?php\nfunction leaf($x) { system($x); return $x; }\n"
		for i := 4; i >= 0; i-- {
			next := "leaf"
			if i < 4 {
				next = fmt.Sprintf("h%d", i+1)
			}
			source += fmt.Sprintf("function h%d($x) { return %s($x); }\n", i, next)
		}
		source += "h0($_GET['left_command']);\nh0($_GET['right_command']);\n"
	}
	return
}
