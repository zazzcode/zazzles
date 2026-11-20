package judge

import (
	"encoding/json"
	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/pipeline"
	"reflect"
	"strings"
	"testing"
)

func TestWireContextProjectionAfterBudget(t *testing.T) {
	e := func(kind string, start int) analysis.Evidence {
		return analysis.Evidence{Kind: kind, Text: kind, SHA256: "snapshot", Span: analysis.Span{File: "app.ts", StartByte: start, EndByte: start + len(kind), StartLine: start, EndLine: start}}
	}
	keep, drop := e("guard_test", 20), e("helper_definition", 40)
	u := analysis.CandidateUse{Sink: e("operation", 90), Context: []analysis.Evidence{drop, keep}, Command: &analysis.CommandFacts{Operands: []analysis.CommandOperand{{Context: []int{1}}}, Paths: []analysis.CommandPath{{Controls: []int{1}}}}, Path: &analysis.PathFacts{Operands: []analysis.PathOperand{{Context: []int{1}}}, Guards: []analysis.PathGuard{{Context: 1}}, Paths: []analysis.PathFlow{{Controls: []int{0}}}, Extractor: &analysis.PathExtractor{Context: 1}}, Outbound: &analysis.OutboundFacts{Paths: []analysis.CommandPath{{Controls: []int{1}}}}}
	before, _ := json.Marshal(u)
	reduced := withoutContext(u, map[spanKey]bool{keyOf(drop): true}, []analysis.EvidenceOmission{{Span: drop.Span}})
	for _, v := range []analysis.CandidateUse{u, reduced} {
		for _, tt := range []struct {
			facts any
			path  bool
		}{{v.Command, false}, {v.Path, true}, {v.Outbound, false}} {
			refs := make([]string, len(v.Context))
			for i := range refs {
				refs[i] = "e-" + v.Context[i].Kind
			}
			b, _ := json.Marshal(wireContextFacts(tt.facts, refs, tt.path))
			text := string(b)
			if !strings.Contains(text, `"context":["e-guard_test"]`) && !strings.Contains(text, `"controls":["e-guard_test"]`) {
				t.Fatalf("missing projected context: %s", b)
			}
			if tt.path && !strings.Contains(text, `"controls":[0]`) {
				t.Fatal("path guard indices incorrectly projected")
			}
		}
	}
	after, _ := json.Marshal(u)
	if string(before) != string(after) {
		t.Fatal("projection mutated canonical use")
	}
}

func TestMaskedSpaceCompactionPreservesLinesAndLiterals(t *testing.T) {
	original := "/* a long comment */\nconst x = `first\n    \nlast  `; // hidden\n"
	masked := "                    \nconst x = `first\n    \nlast  `;          \n"
	if len(original) != len(masked) {
		t.Fatalf("fixture lengths %d %d", len(original), len(masked))
	}
	got := condenseMaskedSpaces(original, masked)
	if strings.Count(got, "\n") != strings.Count(original, "\n") || !strings.Contains(got, "`first\n    \nlast  `") {
		t.Fatalf("line/literal fidelity lost: %q", got)
	}
	if len(got) >= len(masked) {
		t.Fatal("masked comment was not condensed")
	}
}

func TestWireV7EnvelopeAndProvenance(t *testing.T) {
	c, _ := New("openai", "fixture-model", "offline")
	u := selectedSQLUse(t)
	original := cloneComponents(u.Components)
	trace, err := c.Preview(u)
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Input string `json:"input"`
	}
	if err = json.Unmarshal(trace.Request, &envelope); err != nil {
		t.Fatal(err)
	}
	input := envelope.Input
	for _, field := range []string{`"evidence_version":8`, `"compact_wire"`, `"evidence_coverage"`, `"dependencies"`, `"control_edges"`} {
		if !strings.Contains(input, field) {
			t.Fatalf("missing %s", field)
		}
	}
	for _, field := range []string{`"digest"`, `"sha256"`, `"start_byte"`, `"end_byte"`, `"evidence_roles"`, `"trace_graph"`} {
		if strings.Contains(input, field) {
			t.Fatalf("redundant wire metadata %s", field)
		}
	}
	last := -1
	for _, field := range []string{`"analysis_components"`, `"instruction"`, `"analysis_guidelines"`, `"use"`} {
		i := strings.Index(input, field)
		if i <= last {
			t.Fatalf("prefix order: %s", field)
		}
		last = i
	}
	if !reflect.DeepEqual(original, u.Components) || !reflect.DeepEqual(trace.Components, u.Components) || trace.Components.Digest == "" {
		t.Fatal("local provenance was lost or mutated")
	}
	again, err := c.Preview(u)
	if err != nil || !reflect.DeepEqual(trace, again) {
		t.Fatal("nondeterministic preview")
	}
}

func TestWireV7KeepsDependencyAndControlWitnesses(t *testing.T) {
	for _, fixture := range []string{"javascript/grpc", "typescript/graphql", "python/routes", "javascript/command-injection", "javascript/path-traversal", "python/outbound", "javascript/xss-fetch"} {
		t.Run(fixture, func(t *testing.T) {
			report, err := pipeline.Analyze(fixtureRoot(fixture), "")
			if err != nil {
				t.Fatal(err)
			}
			for _, u := range report.Uses {
				full := wireBundle(u)
				packed, err := compactBundle(full)
				if err != nil {
					t.Fatal(err)
				}
				b, _ := json.Marshal(full)
				var original map[string]any
				json.Unmarshal(b, &original)
				current := packed.(map[string]any)
				for _, field := range []string{"dependencies", "control_edges"} {
					if !reflect.DeepEqual(original[field], current[field]) {
						t.Fatalf("%s lost %s", u.Kind, field)
					}
				}
				if _, ok := current["trace_graph"]; ok {
					t.Fatal("duplicate graph sent")
				}
			}
		})
	}
}

func TestCondensedExcerptColumnsIdentifySameLineNodes(t *testing.T) {
	raw := "/* long comment */ first(x); first(y);\n"
	masked := "                   first(x); first(y);\n"
	if len(raw) != len(masked) {
		t.Fatal("fixture length mismatch")
	}
	makeEvidence := func(kind string, start, end int) analysis.Evidence {
		return analysis.Evidence{Kind: kind, Text: raw[start:end], ModelText: masked[start:end], SHA256: "snapshot", Span: analysis.Span{File: "a.ts", StartLine: 1, EndLine: 1, StartByte: start, EndByte: end}}
	}
	first, second := strings.Index(raw, "first(x)"), strings.Index(raw, "first(y)")
	records, excerpts := sharedSourceExcerpts([]analysis.Evidence{makeEvidence("handler", 0, len(raw)), makeEvidence("operation", first, first+8), makeEvidence("operation", second, second+8)})
	for i, want := range map[int]string{1: "first(x)", 2: "first(y)"} {
		r := records[i]
		if r.TextRef != "s0" {
			t.Fatal("missing shared excerpt")
		}
		text := excerpts[0].Text
		if got := text[r.StartColumn-1 : r.EndColumn-1]; got != want {
			t.Fatalf("node %d: %q want %q", i, got, want)
		}
	}
	if records[1].StartColumn == records[2].StartColumn {
		t.Fatal("same-line evidence collapsed")
	}
}

func TestWireV7UnionsSelectedEvidenceObligations(t *testing.T) {
	u := analysis.CandidateUse{Sink: analysis.Evidence{Kind: "sink"}, Completeness: &analysis.Completeness{Required: []string{"sink"}, Evidence: map[string][]analysis.Evidence{}}, Components: &analysis.ComponentSelection{Required: []string{"selected_only", "sink"}}}
	raw, _ := json.Marshal(wireBundle(u))
	var bundle struct {
		Required []string           `json:"required_evidence"`
		Coverage []evidenceCoverage `json:"evidence_coverage"`
	}
	json.Unmarshal(raw, &bundle)
	if !reflect.DeepEqual(bundle.Required, []string{"selected_only", "sink"}) {
		t.Fatalf("lost selected obligations: %s", raw)
	}
	if !strings.Contains(string(raw), `"role":"selected_only"`) {
		t.Fatalf("selected obligation absent from coverage: %s", raw)
	}
	if !reflect.DeepEqual(u.Completeness.Required, []string{"sink"}) {
		t.Fatal("mutated canonical obligations")
	}
}
