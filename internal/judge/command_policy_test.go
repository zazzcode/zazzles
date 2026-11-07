package judge

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
	"github.com/zazzcode/zazzles/internal/parse"
)

// commandAnswers is a deliberately stubbed model answer set.
type commandAnswers map[string]string

var (
	// rawShell is an honest answer for request text in a shell command.
	rawShell = commandAnswers{"shell_syntax_protection": "vulnerable", "executable_control": "not_applicable", "argument_control": "not_applicable", "protection_coverage": "incomplete"}
	// optimistic claims everything is constrained, whatever the source shows.
	optimistic = commandAnswers{"shell_syntax_protection": "not_applicable", "executable_control": "constrained", "argument_control": "constrained", "protection_coverage": "complete"}
)

func commandStub(t *testing.T, provider string, answers commandAnswers) (*Client, *int) {
	t.Helper()
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		calls++
		var body struct {
			Questions json.RawMessage `json:"questions"`
		}
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		var names []string
		if provider == "openai" {
			var list []struct {
				Name string `json:"name"`
			}
			_ = json.Unmarshal(body.Questions, &list)
			for _, q := range list {
				names = append(names, q.Name)
			}
		} else {
			var m map[string]json.RawMessage
			_ = json.Unmarshal(body.Questions, &m)
			for name := range m {
				names = append(names, name)
			}
		}
		if provider == "openai" {
			list := []map[string]string{}
			for _, name := range names {
				list = append(list, map[string]string{"name": name, "type": "choice", "choice": answers[name]})
			}
			json.NewEncoder(w).Encode(map[string]any{"model": "fixture-model", "answers": list, "usage": map[string]int{"input_tokens": 11, "output_tokens": 3}})
			return
		}
		out := map[string]map[string]string{}
		for _, name := range names {
			out[name] = map[string]string{"type": "choice", "choice": answers[name]}
		}
		json.NewEncoder(w).Encode(map[string]any{"model": "fixture-model", "answers": out, "usage": map[string]int{"input_tokens": 11, "output_tokens": 3}})
	}))
	t.Cleanup(server.Close)
	c, err := New(provider, "fixture-model", "synthetic-test-key")
	if err != nil {
		t.Fatal(err)
	}
	c.endpoint = server.URL
	c.http = server.Client()
	return c, &calls
}

type commandSource struct {
	file, text string
}

// commandScenario is one source shape realized in every language.
type commandScenario struct {
	name    string
	sources map[string]commandSource // javascript, typescript, python
	answers commandAnswers
	want    []string // expected final statuses in source order
}

const jsHead = `const express=require('express');const {exec,execFile}=require('child_process');const app=express();const ALLOWED=['alpha','beta'];`
const tsHead = `import express, {Request, Response} from 'express';import {exec,execFile} from 'child_process';const app=express();const ALLOWED: string[]=['alpha','beta'];`
const pyHead = "import os\nimport subprocess\nfrom flask import Flask, request\napp = Flask(__name__)\nALLOWED = ('alpha', 'beta')\n"

func scenario(name string, answers commandAnswers, want []string, js, ts, py string) commandScenario {
	return commandScenario{name: name, answers: answers, want: want, sources: map[string]commandSource{
		"javascript": {"server.js", jsHead + js},
		"typescript": {"server.ts", tsHead + ts},
		"python":     {"app.py", pyHead + py},
	}}
}

func commandScenarios() []commandScenario {
	finite := commandAnswers{"shell_syntax_protection": "not_applicable", "executable_control": "constrained", "argument_control": "constrained", "protection_coverage": "complete"}
	return []commandScenario{
		scenario("raw shell text", rawShell, []string{"confirmed_vulnerability"},
			`app.get('/r',(req,res)=>{exec('echo '+req.query.x,()=>{});res.end()});`,
			`app.get('/r',(req: Request,res: Response)=>{const x: string=req.query.x as string;exec('echo '+x,()=>{});res.end()});`,
			"@app.route('/r')\ndef r():\n    return str(os.system('echo ' + request.args.get('x', '')))\n"),
		scenario("protected finite allow-list", finite, []string{"protected_for_claim"},
			`app.get('/p',(req,res)=>{const v=req.query.name;if(!ALLOWED.includes(v)){return res.status(400).end()}execFile('/usr/bin/lookup',[v],()=>{});res.end()});`,
			`app.get('/p',(req: Request,res: Response)=>{const v: string=req.query.name as string;if(!ALLOWED.includes(v)){return res.status(400).end()}execFile('/usr/bin/lookup',[v],()=>{});res.end()});`,
			"@app.route('/p')\ndef p():\n    v = request.args.get('name', '')\n    if v not in ALLOWED:\n        return 'bad', 400\n    return str(subprocess.run(['/usr/bin/lookup', v]))\n"),
		scenario("untrusted executable", commandAnswers{"shell_syntax_protection": "not_applicable", "executable_control": "unsafe", "argument_control": "unknown", "protection_coverage": "incomplete"}, []string{"confirmed_vulnerability"},
			`app.get('/e',(req,res)=>{execFile(req.query.prog,['-v'],()=>{});res.end()});`,
			`app.get('/e',(req: Request,res: Response)=>{execFile(req.query.prog as string,['-v'],()=>{});res.end()});`,
			"@app.route('/e')\ndef e():\n    return str(subprocess.run([request.args.get('prog', ''), '-v']))\n"),
		scenario("unknown utility options overclaimed", commandAnswers{"shell_syntax_protection": "not_applicable", "executable_control": "constrained", "argument_control": "unsafe", "protection_coverage": "incomplete"}, []string{"needs_evidence"},
			`app.get('/u',(req,res)=>{execFile('/usr/bin/lookup',[req.query.name],()=>{});res.end()});`,
			`app.get('/u',(req: Request,res: Response)=>{execFile('/usr/bin/lookup',[req.query.name as string],()=>{});res.end()});`,
			"@app.route('/u')\ndef u():\n    return str(subprocess.run(['/usr/bin/lookup', request.args.get('name', '')]))\n"),
		scenario("unknown utility options honest", commandAnswers{"shell_syntax_protection": "not_applicable", "executable_control": "constrained", "argument_control": "unknown", "protection_coverage": "unknown"}, []string{"needs_evidence"},
			`app.get('/u',(req,res)=>{execFile('/usr/bin/lookup',[req.query.name],()=>{});res.end()});`,
			`app.get('/u',(req: Request,res: Response)=>{execFile('/usr/bin/lookup',[req.query.name as string],()=>{});res.end()});`,
			"@app.route('/u')\ndef u():\n    return str(subprocess.run(['/usr/bin/lookup', request.args.get('name', '')]))\n"),
		scenario("explicit interpreter", rawShell, []string{"confirmed_vulnerability"},
			`app.get('/i',(req,res)=>{execFile('/bin/sh',['-c',req.query.c],()=>{});res.end()});`,
			`app.get('/i',(req: Request,res: Response)=>{execFile('/bin/sh',['-c',req.query.c as string],()=>{});res.end()});`,
			"@app.route('/i')\ndef i():\n    return str(subprocess.run(['/bin/sh', '-c', request.args.get('c', '')]))\n"),
		scenario("reject without return", optimistic, []string{"needs_evidence"},
			`app.get('/w',(req,res)=>{const v=req.query.name;if(!ALLOWED.includes(v)){res.status(400)}execFile('/usr/bin/lookup',[v],()=>{});res.end()});`,
			`app.get('/w',(req: Request,res: Response)=>{const v: string=req.query.name as string;if(!ALLOWED.includes(v)){res.status(400)}execFile('/usr/bin/lookup',[v],()=>{});res.end()});`,
			"@app.route('/w')\ndef w():\n    v = request.args.get('name', '')\n    if v not in ALLOWED:\n        pass\n    return str(subprocess.run(['/usr/bin/lookup', v]))\n"),
		scenario("mixed guarded and raw operands", optimistic, []string{"needs_evidence"},
			`app.get('/m',(req,res)=>{const v=req.query.name;if(!ALLOWED.includes(v)){return res.status(400).end()}execFile('/usr/bin/lookup',[v,req.query.raw],()=>{});res.end()});`,
			`app.get('/m',(req: Request,res: Response)=>{const v: string=req.query.name as string;if(!ALLOWED.includes(v)){return res.status(400).end()}execFile('/usr/bin/lookup',[v,req.query.raw as string],()=>{});res.end()});`,
			"@app.route('/m')\ndef m():\n    v = request.args.get('name', '')\n    if v not in ALLOWED:\n        return 'bad', 400\n    return str(subprocess.run(['/usr/bin/lookup', v, request.args.get('raw', '')]))\n"),
		scenario("conditional raw path", rawShell, []string{"confirmed_vulnerability"},
			`app.get('/c',(req,res)=>{if(req.query.debug){exec('echo '+req.query.x,()=>{})}res.end()});`,
			`app.get('/c',(req: Request,res: Response)=>{if(req.query.debug){exec('echo '+(req.query.x as string),()=>{})}res.end()});`,
			"@app.route('/c')\ndef c():\n    if request.args.get('debug'):\n        os.system('echo ' + request.args.get('x', ''))\n    return 'ok'\n"),
		scenario("shell vulnerability claimed for verified shell-disabled data", rawShell, []string{"needs_evidence"},
			`app.get('/d',(req,res)=>{execFile('/usr/bin/lookup',[req.query.name],()=>{});res.end()});`,
			`app.get('/d',(req: Request,res: Response)=>{execFile('/usr/bin/lookup',[req.query.name as string],()=>{});res.end()});`,
			"@app.route('/d')\ndef d():\n    return str(subprocess.run(['/usr/bin/lookup', request.args.get('name', '')]))\n"),
		scenario("all not applicable is not protection", commandAnswers{"shell_syntax_protection": "not_applicable", "executable_control": "not_applicable", "argument_control": "not_applicable", "protection_coverage": "complete"}, []string{"needs_evidence"},
			`app.get('/n',(req,res)=>{execFile('/usr/bin/lookup',[req.query.name],()=>{});res.end()});`,
			`app.get('/n',(req: Request,res: Response)=>{execFile('/usr/bin/lookup',[req.query.name as string],()=>{});res.end()});`,
			"@app.route('/n')\ndef n():\n    return str(subprocess.run(['/usr/bin/lookup', request.args.get('name', '')]))\n"),
	}
}

func commandUsesOf(r *analysis.AnalysisReport) []analysis.CandidateUse {
	var out []analysis.CandidateUse
	for _, u := range r.Uses {
		if u.Kind == "command_execution_candidate" {
			out = append(out, u)
		}
	}
	return out
}

func TestCommandPolicyMatrix(t *testing.T) {
	for _, sc := range commandScenarios() {
		for _, language := range []string{"javascript", "typescript", "python"} {
			for _, provider := range []string{"openai", "jev"} {
				t.Run(sc.name+"/"+language+"/"+provider, func(t *testing.T) {
					src := sc.sources[language]
					r, err := parse.Analyze(writeFixture(t, map[string]string{src.file: src.text}), "")
					if err != nil {
						t.Fatal(err)
					}
					uses := commandUsesOf(r)
					if len(uses) != len(sc.want) {
						t.Fatalf("command candidates = %d, want %d", len(uses), len(sc.want))
					}
					c, calls := commandStub(t, provider, sc.answers)
					for i, u := range uses {
						a, trace := c.AssessTrace(context.Background(), u)
						if a.Status != "completed" || a.QuestionVersion != analysispacks.CommandProtocol {
							t.Fatalf("assessment: %+v", a)
						}
						if a.FindingStatus != sc.want[i] {
							t.Fatalf("status %s, want %s; reason %q blockers %+v answers %v facts %+v paths %+v", a.FindingStatus, sc.want[i], a.Reason, a.BlockingGaps, a.Answers, u.Command, u.Command.Paths)
						}
						switch a.FindingStatus {
						case "confirmed_vulnerability":
							if a.Protection != "insufficient" {
								t.Fatalf("protection %s", a.Protection)
							}
						case "protected_for_claim":
							if a.Protection != "sufficient" {
								t.Fatalf("protection %s", a.Protection)
							}
						default:
							if a.Protection != "uncertain" {
								t.Fatalf("protection %s", a.Protection)
							}
						}
						if len(a.Answers) != 4 || a.RequestDigest == "" {
							t.Fatalf("raw answers or digest missing: %+v", a)
						}
						if replay := c.Replay(u, trace); replay.Status != "completed" || replay.FindingStatus != a.FindingStatus {
							t.Fatalf("replay: %+v", replay)
						}
					}
					if *calls != len(uses) {
						t.Fatalf("calls %d for %d candidates", *calls, len(uses))
					}
				})
			}
		}
	}
}

func TestCommandMixedInvocations(t *testing.T) {
	// One handler, two process calls: the guarded call is protected while the
	// raw sibling is confirmed; neither inherits the other's constraint.
	files := map[string]string{
		"server.js": jsHead + `app.get('/two',(req,res)=>{const v=req.query.name;if(!ALLOWED.includes(v)){return res.status(400).end()}execFile('/usr/bin/lookup',[v],()=>{});exec('echo '+req.query.x,()=>{});res.end()});`,
	}
	r, err := parse.Analyze(writeFixture(t, files), "")
	if err != nil {
		t.Fatal(err)
	}
	uses := commandUsesOf(r)
	if len(uses) != 2 {
		t.Fatalf("candidates = %d", len(uses))
	}
	if uses[0].ID == uses[1].ID {
		t.Fatal("invocation identity collapsed")
	}
	for _, u := range uses {
		raw := strings.Contains(u.Sink.Text, "exec(")
		answers := optimistic
		want := "protected_for_claim"
		if raw {
			answers, want = rawShell, "confirmed_vulnerability"
		}
		c, _ := commandStub(t, "openai", answers)
		if a := c.Assess(context.Background(), u); a.FindingStatus != want {
			t.Fatalf("%s: %s want %s (%s)", u.Sink.Text, a.FindingStatus, want, a.Reason)
		}
	}
}
