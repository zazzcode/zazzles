package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/pipeline"
)

// Redirect only provider transport to localhost. Target fixture URLs never enter
// a transport; any such request fails the test.
type outboundStubTransport struct {
	target    *url.URL
	transport http.RoundTripper
	t         *testing.T
}

func (s outboundStubTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Host != "api.openai.com" && r.URL.Host != "api.typesafe.ai" {
		s.t.Errorf("unexpected target request: %s", r.URL.Host)
		return nil, fmt.Errorf("unexpected host")
	}
	clone := r.Clone(r.Context())
	u := *r.URL
	u.Scheme = s.target.Scheme
	u.Host = s.target.Host
	clone.URL = &u
	return s.transport.RoundTrip(clone)
}

func TestMixedAssessmentWithOutboundObservations(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"server.js": `const express=require('express'); import {Sequelize} from 'sequelize';const sql=new Sequelize('sqlite::memory:'); const marsdb=require('marsdb'); const db=new marsdb.Collection('items'); const app=express();
app.get('/mixed',(req,res)=>{fetch('https://target.invalid/hook',{method:'POST',body:req.query.url});sql.query('SELECT '+req.query.sql);db.find({name:req.query.name});res.send(req.query.html)});`,
		"app.py": `from flask import Flask, request
app = Flask(__name__)
@app.get('/validation')
def validation():
    email = request.args.get('email')
    return 'ok'
`,
	}
	for name, s := range files {
		if err := os.WriteFile(filepath.Join(root, name), []byte(s), 0600); err != nil {
			t.Fatal(err)
		}
	}
	r, err := pipeline.Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]bool{}
	for _, u := range r.Uses {
		kinds[u.Kind] = true
	}
	for _, kind := range []string{"sql_query_candidate", "nosql_query_candidate", "input_validation_candidate", "xss_candidate", "outbound_http_candidate"} {
		if !kinds[kind] {
			t.Fatalf("missing mixed claim %s", kind)
		}
	}
	order := append([]analysis.CandidateUse(nil), r.Uses...)
	sort.SliceStable(order, func(a, b int) bool { return queryUse(order[a]) && !queryUse(order[b]) })
	for _, provider := range []string{"openai", "jev"} {
		for _, limit := range []int{1, 3, 100} {
			t.Run(fmt.Sprintf("%s/cap%d", provider, limit), func(t *testing.T) {
				var calls atomic.Int64 // the scheduler sends requests concurrently
				stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
					calls.Add(1)
					raw, _ := io.ReadAll(req.Body)
					var p map[string]json.RawMessage
					if err := json.Unmarshal(raw, &p); err != nil {
						t.Error(err)
					}
					// Both encoders carry their evidence as a JSON string.
					field := "input"
					if provider == "jev" {
						field = "state"
					}
					var input string
					json.Unmarshal(p[field], &input)
					var evidence struct {
						Use struct {
							Kind string `json:"kind"`
						} `json:"use"`
					}
					json.Unmarshal([]byte(input), &evidence)
					if evidence.Use.Kind == "outbound_http_candidate" {
						t.Error("outbound reached provider")
					}
					answers := []map[string]string{}
					obj := map[string]any{}
					if provider == "openai" {
						var qs []struct {
							Name    string
							Choices []struct{ Value string }
						}
						json.Unmarshal(p["questions"], &qs)
						for _, q := range qs {
							answers = append(answers, map[string]string{"type": "choice", "name": q.Name, "choice": q.Choices[0].Value})
						}
					} else {
						var qs map[string]struct{ Criteria map[string]string }
						json.Unmarshal(p["questions"], &qs)
						for name, q := range qs {
							keys := []string{}
							for key := range q.Criteria {
								keys = append(keys, key)
							}
							sort.Strings(keys)
							obj[name] = map[string]string{"type": "choice", "choice": keys[0]}
						}
					}
					var result any = answers
					if provider == "jev" {
						result = obj
					}
					json.NewEncoder(w).Encode(map[string]any{"model": "fixture-model", "answers": result})
				}))
				defer stub.Close()
				target, _ := url.Parse(stub.URL)
				previous := http.DefaultTransport
				http.DefaultTransport = outboundStubTransport{target, previous, t}
				defer func() { http.DefaultTransport = previous }()
				t.Setenv("OPENAI_API_KEY", "offline-key")
				t.Setenv("TYPESAFE_API_KEY", "offline-key")
				t.Setenv("SCAN_FINDINGS_DIR", "")
				var out, stderr bytes.Buffer
				code := run([]string{"--analyze", "--json", "--judge", provider, "--judge-model", "fixture-model", "--judge-limit", fmt.Sprint(limit), root}, &out, &stderr)
				if code != exitOK || !strings.Contains(stderr.String(), "scan: warning: some assessments are incomplete") {
					t.Fatalf("incomplete requested scan exit=%d stderr=%s", code, stderr.String())
				}
				var got analysis.AnalysisReport
				if err := json.Unmarshal(out.Bytes(), &got); err != nil {
					t.Fatal(err)
				}
				expected := 0
				requestIndex := 0
				for _, u := range order {
					var actual analysis.CandidateUse
					for _, v := range got.Uses {
						if v.ID == u.ID {
							actual = v
						}
					}
					if u.Kind != "outbound_http_candidate" && u.Kind != "xss_data_candidate" {
						requestIndex++
					}
					if u.Kind != "outbound_http_candidate" && u.Kind != "xss_data_candidate" && requestIndex > limit {
						if actual.Assessment.Status != "not_run" || actual.Assessment.Reason != "judge request limit reached" {
							t.Fatal("cap scheduling changed")
						}
						continue
					}
					if u.Kind == "outbound_http_candidate" {
						if actual.Assessment.Status != "not_run" || !strings.Contains(actual.Assessment.Reason, "not implemented") || actual.Assessment.RequestDigest != "" {
							t.Fatalf("observation: %+v", actual.Assessment)
						}
					} else {
						expected++
						if actual.Assessment.Status != "completed" {
							t.Fatalf("supported %s: %+v", u.Kind, actual.Assessment)
						}
					}
				}
				if got := int(calls.Load()); got != expected || got > limit {
					t.Fatalf("calls=%d expected=%d cap=%d", got, expected, limit)
				}
			})
		}
	}
}

func TestOutboundObservationCLI(t *testing.T) {
	for _, provider := range []string{"openai", "jev"} {
		t.Setenv("OPENAI_API_KEY", "offline-key")
		t.Setenv("TYPESAFE_API_KEY", "offline-key")
		t.Setenv("SCAN_FINDINGS_DIR", "")
		previous := http.DefaultTransport
		var calls atomic.Int64
		stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(400) })) // non-retried
		target, _ := url.Parse(stub.URL)
		http.DefaultTransport = outboundStubTransport{target, previous, t}
		var out, stderr bytes.Buffer
		bundle := t.TempDir()
		code := run([]string{"--analyze", "--json", "--judge", provider, "--judge-model", "fixture-model", "--judge-limit", "100", "--output-dir", bundle, "../../internal/langjs/testdata/javascript/outbound"}, &out, &stderr)
		http.DefaultTransport = previous
		stub.Close()
		// Observations make no call; the one verified fetch whose destination is a
		// request value is an SSRF claim and is the only provider request.
		if code != exitOK || calls.Load() != 1 {
			t.Fatalf("%s code=%d calls=%d stderr=%s", provider, code, calls.Load(), stderr.String())
		}
		files, err := filepath.Glob(filepath.Join(bundle, "outbound", "run-*", "findings.json"))
		if err != nil || len(files) != 1 {
			t.Fatalf("saved bundle %v %v", files, err)
		}
		original, err := os.ReadFile(files[0])
		if err != nil {
			t.Fatal(err)
		}
		var disk, stdoutReport any
		json.Unmarshal(original, &disk)
		json.Unmarshal(out.Bytes(), &stdoutReport)
		if !reflect.DeepEqual(disk, stdoutReport) {
			t.Fatal("saved JSON/stdout drift")
		}
		for _, mode := range []string{"--export-html", "--export-sarif"} {
			var exported, errors bytes.Buffer
			if code := run([]string{mode, files[0]}, &exported, &errors); code != exitOK {
				t.Fatalf("%s: %d %s", mode, code, errors.String())
			}
			name := "findings.html"
			if mode == "--export-sarif" {
				name = "findings.sarif"
			}
			saved, err := os.ReadFile(filepath.Join(filepath.Dir(files[0]), name))
			if err != nil {
				t.Fatal(err)
			}
			if mode == "--export-html" && !bytes.Equal(saved, exported.Bytes()) {
				t.Fatal("saved/exported HTML drift")
			}
			if mode == "--export-sarif" {
				var a, b any
				json.Unmarshal(saved, &a)
				json.Unmarshal(exported.Bytes(), &b)
				if !reflect.DeepEqual(a, b) {
					t.Fatal("saved/exported SARIF drift")
				}
			}
		}
		after, _ := os.ReadFile(files[0])
		if !bytes.Equal(original, after) {
			t.Fatal("export mutated saved answers")
		}

	}
}
