package langjs

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
)

func jsWitnessFixture(t *testing.T, body string) (*moduleSet, *sourceModule, *sitter.Node) {
	t.Helper()
	root := t.TempDir()
	writeSource(t, root, "app.js", "const {execSync,execFileSync}=require('child_process'); const fs=require('fs'); const {Sequelize}=require('sequelize'); const database=new Sequelize('sqlite::memory:');\n"+body+"\nfunction caller(req){ return leaf(req.query.password, req.query.other); }\n")
	ps, err := newParsers()
	if err != nil {
		t.Fatal(err)
	}
	s := &moduleSet{root: root, parsers: ps, modules: map[string]*sourceModule{}, allowed: map[string]bool{"app.js": true}}
	t.Cleanup(s.close)
	m, err := s.load("app.js")
	if err != nil {
		t.Fatal(err)
	}
	var call *sitter.Node
	walkCalls(m.tree.RootNode(), func(n *sitter.Node) {
		fn := n.ChildByFieldName("function")
		if fn != nil && fn.Utf8Text(m.src) == "leaf" && strings.Contains(n.Utf8Text(m.src), "req.query.password") {
			call = n
		}
	})
	if call == nil {
		t.Fatal("missing caller")
	}
	return s, m, call
}

func jsWitnessCaller(s *moduleSet, m *sourceModule, budget int) *flow {
	return &flow{module: m, set: s, entry: analysis.EntryPoint{ID: "fixture-entry", Kind: "http"}, invocation: analysis.InvocationContext{ID: "fixture-invocation"},
		env: map[string]value{}, helpers: &helperExpansion{budget: budget, stack: map[string]bool{}, storeWrites: map[string]bool{}}, facts: newInputFacts(),
		context: []analysis.Evidence{m.evidence("fixture_entry", m.tree.RootNode())}}
}
func jsWitnessArgs(m *sourceModule, call *sitter.Node) []value {
	var values []value
	for _, arg := range callArgumentsJS(call) {
		values = append(values, value{deps: []analysis.Dependency{{Source: m.evidence("input_source", arg), Transfers: []analysis.Evidence{}}}})
	}
	return values
}
func jsWitnessBytes(ret value, entered, precise bool, f *flow) []byte {
	x := struct {
		Dependencies     []analysis.Dependency
		Gaps             []analysis.Gap
		Entered, Precise bool
		Uses             []analysis.CandidateUse
		Context          []analysis.Evidence
		FlowGaps         []analysis.Gap
	}{ret.deps, ret.gaps, entered, precise, f.uses, f.context, f.gaps}
	b, _ := json.Marshal(x)
	return b
}

func TestJSWitnessInlineParity(t *testing.T) {
	for _, tt := range []struct{ name, body string }{
		{"return-transform", "function leaf(x,y){const text=String(x);return text;}"},
		{"argument-fanout", "function leaf(x,y){const text=x+y+x;return {text,other:y};}"},
		{"native-command-options", "function leaf(x,y){execSync('printf '+String(x),{shell:false});return y;}"},
		{"shell-disabled-control", "function leaf(x,y){execFileSync('/usr/bin/printf',[String(x)],{shell:false});return String(y);}"},
		{"verified-sql", "function leaf(x,y){database.query('SELECT '+x);return y;}"},
		{"native-path", "function leaf(x,y){fs.readFileSync(x);return y;}"},
		{"native-log", "function leaf(x,y){console.log(x);return y;}"},
		{"nested-quiet-sink", "function leaf(x,y){eval(execSync(x));return y;}"},
		{"helper-chain", "function inner(x){execSync(x);return String(x)} function leaf(x,y){return inner(y);}"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s, m, call := jsWitnessFixture(t, tt.body)
			args := jsWitnessArgs(m, call)
			plan := s.jsWitnessPlan(m, m.funcs["leaf"])
			if !plan.supported() {
				t.Fatalf("unsupported plan: %+v", plan.reasons)
			}
			if s.jsWitnessPlan(m, m.funcs["leaf"]) != plan {
				t.Fatal("plan not cached")
			}
			inline := jsWitnessCaller(s, m, 24)
			want, we, wp := inline.enterHelper(call, "leaf", args)
			replay := jsWitnessCaller(s, m, 0)
			got, ge, gp := replay.enterHelper(call, "leaf", args)
			if !reflect.DeepEqual(want, got) || !bytes.Equal(jsWitnessBytes(want, we, wp, inline), jsWitnessBytes(got, ge, gp, replay)) {
				t.Fatalf("summary witness differs from inline\nwant %s\ngot %s", jsWitnessBytes(want, we, wp, inline), jsWitnessBytes(got, ge, gp, replay))
			}
			if !ge || !gp {
				t.Fatal("supported summary did not instantiate precise return")
			}
			for _, u := range replay.uses {
				if u.Command != nil {
					if err := u.Command.Validate(len(u.Dependencies), len(u.Context)); err != nil {
						t.Fatal(err)
					}
				}
				for _, d := range u.Dependencies {
					if !strings.Contains(d.Source.Text, "req.query.") {
						t.Fatalf("synthetic or wrong source: %+v", d.Source)
					}
					binding := false
					for _, e := range d.Transfers {
						binding = binding || e.Kind == "parameter_binding" && e.Span.File == "app.js" && e.SHA256 != ""
					}
					if !binding {
						t.Fatal("missing concrete parameter witness")
					}
				}
			}
		})
	}
}
func TestJSWitnessParameterFactsAndMutation(t *testing.T) {
	s, m, call := jsWitnessFixture(t, "function leaf(x,y){execSync(y);return String(x);}")
	p := s.jsWitnessPlan(m, m.funcs["leaf"])
	if !p.supported() || p.returns != 1 || len(p.sinks) != 1 || p.sinks[0].Parameters != 2 || len(p.transforms) != 1 {
		t.Fatalf("parameter facts: %+v", p)
	}
	args := jsWitnessArgs(m, call)
	inline := jsWitnessCaller(s, m, 24)
	want, we, wp := inline.enterHelper(call, "leaf", args)
	// A changed source span must be detected even when the dependency count and
	// parameter values remain identical.
	saved := p.params[0].node
	p.params[0].node = p.params[1].node
	defer func() { p.params[0].node = saved }()
	replay := jsWitnessCaller(s, m, 0)
	got, ge, gp := replay.enterHelper(call, "leaf", args)
	if bytes.Equal(jsWitnessBytes(want, we, wp, inline), jsWitnessBytes(got, ge, gp, replay)) {
		t.Fatal("wrong-parameter-span mutation escaped witness oracle")
	}
	p.params[0].node = saved
	originalStatement := p.statements[0]
	p.statements[0] = p.statements[len(p.statements)-1]
	replay = jsWitnessCaller(s, m, 0)
	got, ge, gp = replay.enterHelper(call, "leaf", args)
	p.statements[0] = originalStatement
	if bytes.Equal(jsWitnessBytes(want, we, wp, inline), jsWitnessBytes(got, ge, gp, replay)) {
		t.Fatal("missing-sink recipe mutation escaped witness oracle")
	}

}
func TestJSWitnessRejectsBeforeEffects(t *testing.T) {
	for _, tt := range []struct{ name, body string }{
		{"async callable", "async function leaf(x,y){execSync(x);return y;}"},
		{"unknown receiver operand", "function leaf(x,y){execSync(x);return new Date(unknown(y)).getTime();}"},
		{"hidden receiver sink", "function leaf(x,y){return new Date(execSync(x)).getTime();}"},
		{"reassigned helper", "function inner(x){return x;} inner=external;function leaf(x,y){execSync(x);return inner(y);}"},
		{"mutated helper", "function inner(x){return x;} inner.field=external;function leaf(x,y){execSync(x);return inner(y);}"},
		{"later-unknown", "function leaf(x,y){execSync(x);unknown(y);return x;}"},
		{"later-binding", "function inner(x,y){return x} function leaf(x,y){execSync(x);return inner(x);}"},
		{"heap-write", "function leaf(x,y){execSync(x);x.key=y;return x;}"},
		{"global-write", "let state;function leaf(x,y){execSync(x);state=x;return y;}"},
		{"closure", "function leaf(x,y){execSync(x);return ()=>x;}"},
		{"default", "function leaf(x,y=unknown()){execSync(x);return y;}"},
		{"dynamic-receiver", "function leaf(x,y){execSync(x);x.run(y);return y;}"},
		{"recursion", "function leaf(x,y){execSync(x);return leaf(x,y);}"},
		{"control", "function leaf(x,y){execSync(x);if(x){return y}return x;}"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s, m, call := jsWitnessFixture(t, tt.body)
			p := s.jsWitnessPlan(m, m.funcs["leaf"])
			if p.supported() {
				t.Fatal("unsupported program accepted")
			}
			f := jsWitnessCaller(s, m, 0)
			ctx := append([]analysis.Evidence{}, f.context...)
			_, entered, _ := f.enterHelper(call, "leaf", jsWitnessArgs(m, call))
			if entered || len(f.uses) != 0 || !reflect.DeepEqual(ctx, f.context) || len(f.facts.touched) > 0 {
				t.Fatalf("failed plan leaked effects: %+v", f)
			}
			if len(f.gaps) != 1 || f.gaps[0].Kind != "helper_call_limit" {
				t.Fatalf("refusal lost gap: %+v", f.gaps)
			}
		})
	}
	body := "function cap12(x,y){return x;}\\n"
	for i := 11; i >= 0; i-- {
		body += fmt.Sprintf("function cap%d(x,y){cap%d(x,y);return cap%d(x,y);}\\n", i, i+1, i+1)
	}
	body += "function leaf(x,y){return cap0(x,y);}"
	s, m, call := jsWitnessFixture(t, body)
	p := s.jsWitnessPlan(m, m.funcs["leaf"])
	capped := false
	for _, target := range s.witnessPlans {
		capped = capped || jsWitnessReason(target, "summary_limit")
	}
	if p.supported() || !capped {
		t.Fatalf("instruction cap missing: %+v", p.reasons)
	}
	f := jsWitnessCaller(s, m, 0)
	f.enterHelper(call, "leaf", jsWitnessArgs(m, call))
	if len(f.uses) > 0 {
		t.Fatal("limit leaked effects")
	}
}
func jsWitnessReason(p *jsWitnessPlan, kind string) bool {
	for _, r := range p.reasons {
		if r.Kind == kind {
			return true
		}
	}
	return false
}

func TestJSWitnessShadowFixtures(t *testing.T) {
	expansions, supported := 0, 0
	summaryShadow = func(f *flow, call *sitter.Node, m *sourceModule, fn *sitter.Node, args []value, ret value, precise bool, uses []analysis.CandidateUse) {
		expansions++
		if f.client != nil || f.web != nil || f.setterValue != nil {
			return
		}
		p := f.set.jsWitnessPlan(m, fn)
		if !p.supported() || len(args) != len(p.params) || len(f.context) == 0 {
			return
		}
		last := f.context[len(f.context)-1]
		if last.Kind != "helper_definition" {
			t.Fatal("unexpected inline frame context")
		}
		copyFlow := *f
		copyFlow.context = append([]analysis.Evidence{}, f.context[:len(f.context)-1]...)
		copyFlow.uses = nil
		copyFlow.facts = newInputFacts()
		got, entered, gp := copyFlow.summaryWitnessCall(call, m, fn, args)
		if !entered {
			return
		}
		supported++
		if !reflect.DeepEqual(ret, got) || precise != gp {
			t.Errorf("%s:%d return/precision differs for %s: inline=%+v replay=%+v", f.module.file, call.StartByte(), fn.Utf8Text(m.src), ret, got)
		}
		a, _ := json.Marshal(uses)
		b, _ := json.Marshal(copyFlow.uses)
		if !bytes.Equal(a, b) {
			t.Errorf("%s:%d concrete use bytes differ\ninline=%s\nreplay=%s", f.module.file, call.StartByte(), a, b)
		}
	}
	defer func() { summaryShadow = nil }()
	for _, root := range shadowFixtureRoots(t) {
		if _, err := Analyze(root, ""); err != nil {
			t.Fatal(err)
		}
	}
	if expansions == 0 || supported == 0 {
		t.Fatalf("shadow checked too little: %d/%d", supported, expansions)
	}
	t.Logf("%d inline expansions; %d supported complete witnesses, zero mismatches", expansions, supported)
}

func TestJSWitnessPersistentDeepFixture(t *testing.T) {
	r, err := Analyze("testdata/javascript/summary-witnesses", "")
	if err != nil {
		t.Fatal(err)
	}
	sources := map[string]bool{}
	commands := 0
	for _, u := range r.Uses {
		if u.Kind != "command_execution_candidate" {
			continue
		}
		commands++
		if u.Command == nil || u.Command.EffectiveShellMode != "disabled" {
			t.Fatalf("lost native shell control: %+v", u.Command)
		}
		if err := u.Command.Validate(len(u.Dependencies), len(u.Context)); err != nil {
			t.Fatal(err)
		}
		for _, d := range u.Dependencies {
			sources[d.Source.Text] = true
			hasString, binding := false, 0
			for _, e := range d.Transfers {
				hasString = hasString || e.Kind == "string_conversion"
				if e.Kind == "parameter_binding" {
					binding++
				}
			}
			if !hasString || binding < 6 {
				t.Fatalf("incomplete concrete chain: %+v", d.Transfers)
			}
		}
		for _, g := range u.Gaps {
			if g.Kind == "helper_call_limit" || g.Kind == "work_limit" {
				t.Fatalf("supported summary retained inline limit: %+v", g)
			}
		}
	}
	if commands != 2 || !sources["req.query.left"] || !sources["req.query.right"] {
		t.Fatalf("caller witnesses: %d, %v", commands, sources)
	}
}

func TestJSWitnessImportedFrameParityAndNoLoad(t *testing.T) {
	root := t.TempDir()
	writeSource(t, root, "helper.js", "export function leaf(x){return String(x)}")
	writeSource(t, root, "app.js", "import {leaf} from './helper'; function wrapper(x){return leaf(x)} function caller(req){return wrapper(req.query.password)}")
	ps, err := newParsers()
	if err != nil {
		t.Fatal(err)
	}
	s := &moduleSet{root: root, parsers: ps, modules: map[string]*sourceModule{}, allowed: map[string]bool{"app.js": true, "helper.js": true}}
	defer s.close()
	m, err := s.load("app.js")
	if err != nil {
		t.Fatal(err)
	}
	p := s.jsWitnessPlan(m, m.funcs["wrapper"])
	if p.supported() || len(s.modules) != 1 || s.summaryNoLoad || len(m.calls) != 0 {
		t.Fatalf("compiler changed loaded source/resolution snapshot: supported=%v modules=%d calls=%d", p.supported(), len(s.modules), len(m.calls))
	}
	// A fresh whole-repository snapshot can compile the already-loaded import.
	s.witnessPlans = nil
	if _, err := s.load("helper.js"); err != nil {
		t.Fatal(err)
	}
	p = s.jsWitnessPlan(m, m.funcs["wrapper"])
	if !p.supported() {
		t.Fatalf("loaded imported DAG refused: %+v", p.reasons)
	}
	var call *sitter.Node
	walkCalls(m.tree.RootNode(), func(n *sitter.Node) {
		if n.Utf8Text(m.src) == "wrapper(req.query.password)" {
			call = n
		}
	})
	if call == nil {
		t.Fatal("missing wrapper caller")
	}
	args := jsWitnessArgs(m, call)
	inline := jsWitnessCaller(s, m, 24)
	want, we, wp := inline.enterHelper(call, "wrapper", args)
	replay := jsWitnessCaller(s, m, 0)
	got, ge, gp := replay.enterHelper(call, "wrapper", args)
	if !reflect.DeepEqual(want, got) || !bytes.Equal(jsWitnessBytes(want, we, wp, inline), jsWitnessBytes(got, ge, gp, replay)) {
		t.Fatal("imported callee witness differs")
	}
	files := map[string]bool{}
	for _, d := range got.deps {
		for _, e := range d.Transfers {
			if e.Kind == "parameter_binding" {
				files[e.Span.File] = true
			}
		}
	}
	if !files["app.js"] || !files["helper.js"] {
		t.Fatalf("cross-file binding spans lost: %v", files)
	}
}

func TestJSWitnessReassignedOuterTarget(t *testing.T) {
	s, m, call := jsWitnessFixture(t, "function leaf(x,y){return x;} leaf=external;")
	f := jsWitnessCaller(s, m, 0)
	if _, entered, _ := f.enterHelper(call, "leaf", jsWitnessArgs(m, call)); entered {
		t.Fatal("reassigned outer callable acquired a new summary")
	}
	if len(f.uses) != 0 {
		t.Fatal("reassigned callable leaked uses")
	}
}
