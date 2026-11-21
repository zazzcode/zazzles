package judge

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
	"github.com/zazzcode/zazzles/internal/pipeline"
)

// TestPollutionShapePolicy applies stub answers to every added write shape,
// the seven contract shapes and the four exploration shapes. A complete key
// guard can be Protected. Its bypass sibling, which skips only __proto__, lists
// constructor as open and can never be Protected.
func TestPollutionShapePolicy(t *testing.T) {
	fixture := filepath.Join("..", "langjs", "testdata", "pollution")
	entries, err := os.ReadDir(fixture)
	if err != nil {
		t.Fatal(err)
	}
	shapes := 0
	starts := 0
	for _, e := range entries {
		start := strings.HasPrefix(e.Name(), "start-") && e.Name() != "start-probes"
		if !e.IsDir() || !start && !strings.HasPrefix(e.Name(), "shapes-") && !strings.HasPrefix(e.Name(), "explore-") {
			continue
		}
		if start {
			starts++
		} else {
			shapes++
		}
		r, err := pipeline.Analyze(filepath.Join(fixture, e.Name()), "")
		if err != nil {
			t.Fatal(err)
		}
		routes := map[string]string{}
		for _, entry := range r.Entries {
			routes[entry.ID] = strings.TrimPrefix(entry.HTTPRoute().PathPattern, "/")
		}
		uses := map[string]analysis.CandidateUse{}
		for _, u := range r.Uses {
			if u.Kind == analysis.PollutionKind {
				name, _, _ := strings.Cut(u.Sink.Text, "(")
				if start {
					name = routes[u.EntryID]
				}
				uses[name] = u
			}
		}
		for _, tt := range []struct {
			witness, control, bypass, coverage, status, blocker string
		}{
			{"vulnerable", "vulnerable", "not_applicable", "incomplete", "confirmed_vulnerability", ""},
			{"guarded", "protected", "no_bypass", "complete", "protected_for_claim", ""},
			{"guarded", "vulnerable", "bypass_identified", "incomplete", "needs_evidence", "pollution_bypass_unsupported"},
			{"partial", "protected", "no_bypass", "complete", "needs_evidence", "pollution_answers_inconsistent"},
			{"partial", "vulnerable", "bypass_identified", "incomplete", "confirmed_vulnerability", ""},
		} {
			t.Run(e.Name()+"/"+tt.witness+"/"+tt.control, func(t *testing.T) {
				u, ok := uses[tt.witness]
				if !ok {
					t.Fatalf("missing parsed witness %s", tt.witness)
				}
				incomplete := slices.ContainsFunc(u.Gaps, func(g analysis.Gap) bool {
					return g.Kind == "key_guard_incomplete" && strings.Contains(g.Detail, "constructor")
				})
				if incomplete != (tt.witness == "partial") {
					t.Fatalf("incomplete listing = %v: %+v", incomplete, u.Gaps)
				}
				transport := pollutionTestTransport(func(*http.Request) (*http.Response, error) {
					var response bytes.Buffer
					_ = json.NewEncoder(&response).Encode(map[string]any{"model": "fixture-model", "answers": []map[string]string{
						{"type": "choice", "name": "prototype_key_control", "choice": tt.control},
						{"type": "choice", "name": "key_guard_bypass", "choice": tt.bypass},
						{"type": "choice", "name": "protection_coverage", "choice": tt.coverage},
					}})
					return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(&response)}, nil
				})
				client, err := New("openai", "fixture-model", "fixture-key")
				if err != nil {
					t.Fatal(err)
				}
				client.UseEndpoint("https://test.invalid/decisions", &http.Client{Transport: transport})
				a, trace := client.AssessTrace(context.Background(), u)
				if a.Status != "completed" || a.FindingStatus != tt.status || a.QuestionVersion != analysispacks.PollutionProtocol {
					t.Fatalf("assessment: %+v", a)
				}
				if tt.blocker != "" && !slices.ContainsFunc(a.BlockingGaps, func(g analysis.Gap) bool { return g.Kind == tt.blocker }) {
					t.Fatalf("missing blocker %s: %+v", tt.blocker, a.BlockingGaps)
				}
				if replay := client.Replay(u, trace); replay.RequestDigest != a.RequestDigest || replay.FindingStatus != a.FindingStatus {
					t.Fatalf("assessment changed on replay: %+v", replay)
				}
			})
		}
	}
	if shapes != 11 || starts != 7 {
		t.Fatalf("checked %d shape and %d start fixtures, want 11 and 7", shapes, starts)
	}
}

// TestPollutionAbsentSlotPolicy checks a nested write whose slot is created
// only when absent, reached through two helpers. An inherited slot skips that
// branch, so the ungated write is complete and a consistent answer can confirm
// it. The same write behind a lookup on the key, a gate the scanner does not
// read, can be neither Confirmed nor Protected.
func TestPollutionAbsentSlotPolicy(t *testing.T) {
	store := `const express = require('express');
const app = express();
app.use(express.json());
const solves = {};
const known = new Map();
function find(key) { return known.has(key) ? known.get(key) : null; }
function storeVerdict(key, phase, verdict) {
  if (!solves[key]) {
    solves[key] = { 'find it': false, attempts: { 'find it': 0 } };
  }
  if (!solves[key][phase]) {
    solves[key][phase] = verdict;
  }
}
function storeFindItVerdict(key, verdict) { storeVerdict(key, 'find it', verdict); }
`
	for _, tt := range []struct {
		name, route, guard string
		outcomes           map[string]string
	}{
		{"ungated", "app.post('/verdict', (req, res) => { storeFindItVerdict(req.body.key, false); res.end(); });", "",
			map[string]string{"vulnerable": "confirmed_vulnerability", "protected": "needs_evidence"}},
		{"gated by a lookup", "app.post('/verdict', (req, res) => { const key = req.body.key; const row = find(key); if (row == null) { res.status(404).end(); return; } storeFindItVerdict(key, false); res.end(); });", "unknown",
			map[string]string{"vulnerable": "needs_evidence", "protected": "needs_evidence"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, "server.js"), []byte(store+tt.route+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			r, err := pipeline.Analyze(root, "")
			if err != nil {
				t.Fatal(err)
			}
			var uses []analysis.CandidateUse
			for _, u := range r.Uses {
				if u.Kind == analysis.PollutionKind {
					uses = append(uses, u)
				}
			}
			if len(uses) != 1 || uses[0].Pollution.Operation != analysis.PollutionNested || uses[0].Pollution.Guard != tt.guard {
				t.Fatalf("expected one nested write with guard %q: %+v", tt.guard, uses)
			}
			if tt.guard == "" && len(uses[0].Completeness.Blockers) != 0 {
				t.Fatalf("unexpected blockers: %+v", uses[0].Completeness.Blockers)
			}
			for _, answers := range [][3]string{{"vulnerable", "not_applicable", "incomplete"}, {"protected", "no_bypass", "complete"}} {
				transport := pollutionTestTransport(func(*http.Request) (*http.Response, error) {
					var response bytes.Buffer
					_ = json.NewEncoder(&response).Encode(map[string]any{"model": "fixture-model", "answers": []map[string]string{
						{"type": "choice", "name": "prototype_key_control", "choice": answers[0]},
						{"type": "choice", "name": "key_guard_bypass", "choice": answers[1]},
						{"type": "choice", "name": "protection_coverage", "choice": answers[2]},
					}})
					return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(&response)}, nil
				})
				client, err := New("openai", "fixture-model", "fixture-key")
				if err != nil {
					t.Fatal(err)
				}
				client.UseEndpoint("https://test.invalid/decisions", &http.Client{Transport: transport})
				if a, _ := client.AssessTrace(context.Background(), uses[0]); a.Status != "completed" || a.FindingStatus != tt.outcomes[answers[0]] {
					t.Fatalf("%s: %+v", answers[0], a)
				}
			}
		})
	}
}
