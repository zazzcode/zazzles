package langphp

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/parse"
)

func phpWitnessHarness(t *testing.T, source string) (*phpSet, *phpModule, *sitter.Node, *phpBoundCallable, []phpValue) {
	t.Helper()
	s, err := newPHPSet(phpFixture(t, map[string]string{"index.php": "<?php " + source + "\nf('first', 'second');"}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.close)
	m := s.modules["index.php"]
	var call *sitter.Node
	phpWalk(m.tree.RootNode(), func(n *sitter.Node) {
		if n.Kind() == "function_call_expression" && phpText(m, phpCallee(n)) == "f" {
			call = n
		}
	})
	if call == nil {
		t.Fatal("missing invocation")
	}
	var args []phpValue
	for _, n := range phpArgs(call) {
		args = append(args, phpValue{deps: []phpDep{{dep: analysis.Dependency{Source: m.evidence("input_source", n)}, protection: "raw"}}})
	}
	return s, m, call, &phpBoundCallable{module: m, fn: m.funcs["f"]}, args
}
func newPHPWitnessFlow(s *phpSet, m *phpModule) *phpFlow {
	work := 0
	return &phpFlow{set: s, module: m, entryModule: m, entryModuleRoot: m.tree.RootNode(), entry: analysis.EntryPoint{ID: "entry"}, invocation: analysis.InvocationContext{ID: "invocation", EntryID: "entry"}, report: &analysis.AnalysisReport{}, env: map[string]phpValue{}, globals: map[string]phpValue{}, stack: map[string]bool{}, work: &work, constants: map[string]string{}}
}
func TestPHPSummaryWitnessParity(t *testing.T) {
	for _, tt := range []struct{ name, source string }{
		{"return", "function f($a,$b){return $b.$a.$a;}"},
		{"controls and echo", "function f($a,$b){$x=htmlspecialchars($a);echo $x;return $b;}"},
		{"command", "function f($a,$b){$x=escapeshellarg($a);system('echo '.$x);return $b;}"},
		{"path", "function f($a,$b){file_get_contents($a);return $b;}"},
		{"code", "function f($a,$b){eval($a);return $b;}"},
		{"cast", "function f($a,$b){return (int)$a;}"},
		{"sql", "function f($a,$b){mysqli_query($b,'SELECT name FROM users WHERE id='.$a);return $a;}"},
		{"chain", "function g($a,$b){echo $b;return intval($a);}function f($a,$b){return g($b,$a);}"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s, m, call, target, args := phpWitnessHarness(t, tt.source)
			inline := newPHPWitnessFlow(s, m)
			want := inline.boundHelper(call, target, args)
			witness := newPHPWitnessFlow(s, m)
			got, ok := witness.applyPHPWitness(call, target, args)
			if !ok {
				t.Fatal("supported witness rejected")
			}
			if !reflect.DeepEqual(want, got) {
				t.Fatalf("return differs\nwant %#v\ngot %#v", want, got)
			}
			a, _ := json.Marshal(inline.report.Uses)
			b, _ := json.Marshal(witness.report.Uses)
			if string(a) != string(b) {
				t.Fatalf("uses differ\nwant %s\ngot %s", a, b)
			}
			if !reflect.DeepEqual(inline.context, witness.context) {
				t.Fatalf("context differs\nwant %#v\ngot %#v", inline.context, witness.context)
			}
			if s.phpWitness(m, target.fn) != s.phpWitness(m, target.fn) {
				t.Fatal("program not cached")
			}
		})
	}
}

func TestPHPSummaryWitnessAfterLimit(t *testing.T) {
	r := phpAnalyze(t, "testdata/summary-witnesses", "")
	commands := phpUsesOfKind(r, "command_execution_candidate")
	renders := phpUsesOfKind(r, "xss_candidate")
	if len(commands) != 2 || len(renders) != 2 {
		t.Fatalf("commands=%d renders=%d", len(commands), len(renders))
	}
	origins := map[string]bool{}
	for _, u := range commands {
		if len(u.Dependencies) != 1 {
			t.Fatalf("command dependencies: %+v", u.Dependencies)
		}
		d := u.Dependencies[0]
		origins[d.Source.Span.File] = true
		if len(u.Command.Paths) != 1 || u.Command.Paths[0].Protection != "guarded" || len(u.Command.Paths[0].Controls) == 0 {
			t.Fatalf("native control missing: %+v", u.Command)
		}
		params, returns := 0, 0
		for _, e := range d.Transfers {
			if e.Kind == "argument_to_parameter" {
				params++
				if e.Span.File != "helpers.php" || e.Span.StartByte == 0 {
					t.Fatalf("fabricated parameter span: %+v", e)
				}
			}
			if e.Kind == "helper_return" {
				returns++
			}
		}
		if params < 5 {
			t.Fatalf("incomplete witness: params=%d returns=%d %+v", params, returns, d.Transfers)
		}
		for _, g := range u.Gaps {
			if g.Kind == "work_limit" {
				t.Fatal("supported sink retained limit", g)
			}
		}
	}
	if !origins["index.php"] || !origins["alternate.php"] {
		t.Fatalf("caller origins leaked: %+v", origins)
	}
	for _, u := range renders {
		count := 0
		for _, e := range u.Dependencies[0].Transfers {
			if e.Kind == "helper_return" {
				count++
			}
		}
		if count < 5 {
			t.Fatalf("return witness missing helper spans: %+v", u.Dependencies[0].Transfers)
		}
		if u.XSS.Protection != "encoded" {
			t.Fatalf("native encoding missing: %+v", u.XSS)
		}
	}
}

func TestPHPSummaryWitnessRejectsAtomically(t *testing.T) {
	cases := []struct{ name, source string }{
		{"namespace", "namespace Other; function f($a,$b){return $a;}"},
		{"branch", "function f($a,$b){echo $a;if($b){echo $a;}return $a;}"},
		{"global", "function f($a,$b){echo $a;global $state;return $state;}"},
		{"include", "function f($a,$b){echo $a;include $b;return $a;}"},
		{"heap", "function f($a,$b){echo $a;$b['x']=$a;return $b;}"},
		{"default", "function f($a,$b='x'){echo $a;return $b;}"},
		{"reference", "function f(&$a,$b){echo $a;return $b;}"},
		{"return reference", "function &f($a,$b){echo $a;return $b;}"},
		{"duplicate parameter", "function f($a,$a){echo $a;return $a;}"},
		{"superglobal parameter", "function f($_GET,$b){echo $b;return $_GET;}"},
		{"variadic", "function f($a,...$b){echo $a;return $b;}"},
		{"cycle", "function f($a,$b){echo $a;return f($a,$b);}"},
		{"unknown", "function f($a,$b){echo $a;return mystery($a);}"},
		{"aggregate mutation", "function f($a,$b){echo $a;return array_shift($b);}"},
		{"missing parameter", "function f($a){echo $a;return $a;}"},
		{"instruction cap", "function f($a,$b){echo $a;" + strings.Repeat("$x=$a;", 600) + "return $b;}"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			s, m, call, target, args := phpWitnessHarness(t, tt.source)
			f := newPHPWitnessFlow(s, m)
			f.env["before"] = args[0]
			beforeEnv := map[string]phpValue{"before": args[0]}
			if _, ok := f.applyPHPWitness(call, target, args); ok {
				t.Fatal("unsupported witness applied")
			}
			if len(f.report.Uses) != 0 || len(f.context) != 0 || len(f.gaps) != 0 || !reflect.DeepEqual(f.env, beforeEnv) {
				t.Fatal("rejected plan leaked state or uses")
			}
			f.depth = phpHelperDepthLimit
			got := f.boundHelper(call, target, args)
			found := false
			for _, g := range got.gaps {
				found = found || g.Kind == "work_limit"
			}
			if !found {
				t.Fatal("unsupported refusal lost its limit")
			}
		})
	}
}
func TestPHPSummaryWitnessCallerAndMutation(t *testing.T) {
	s, m, call, target, args := phpWitnessHarness(t, "function f($a,$b){return $a;}")
	first := newPHPWitnessFlow(s, m)
	a, ok := first.applyPHPWitness(call, target, args)
	if !ok {
		t.Fatal("no witness")
	}
	reversed := []phpValue{args[1], args[0]}
	second := newPHPWitnessFlow(s, m)
	b, ok := second.applyPHPWitness(call, target, reversed)
	if !ok {
		t.Fatal("no second witness")
	}
	if len(a.deps) != 1 || len(b.deps) != 1 || a.deps[0].dep.Source == b.deps[0].dep.Source {
		t.Fatal("cached caller provenance leaked")
	}
	inline := newPHPWitnessFlow(s, m)
	want := inline.boundHelper(call, target, args)
	p := s.phpWitness(m, target.fn)
	original := p.params[0].node
	p.params[0].node = p.params[1].node
	defer func() { p.params[0].node = original }()
	mutated := newPHPWitnessFlow(s, m)
	got, _ := mutated.applyPHPWitness(call, target, args)
	if reflect.DeepEqual(want, got) {
		t.Fatal("parity oracle did not detect wrong parameter span")
	}
}
func TestPHPSummaryWitnessAggregateArguments(t *testing.T) {
	s, m, call, target, args := phpWitnessHarness(t, "function f($a,$b){return $a;}")
	args[0].fields = map[string]phpValue{"child": args[1]}
	inline := newPHPWitnessFlow(s, m)
	want := inline.boundHelper(call, target, args)
	witness := newPHPWitnessFlow(s, m)
	got, ok := witness.applyPHPWitness(call, target, args)
	if !ok || !reflect.DeepEqual(want, got) {
		t.Fatal("aggregate argument was templated rather than bound natively")
	}
}

func TestPHPSummaryWitnessParameterFacts(t *testing.T) {
	for _, tt := range []struct {
		name, source        string
		returns, sinkParams uint64
		family              string
	}{
		{"fanout", "function f($a,$b){return $a.$a.$b;}", 3, 0, ""},
		{"assignment control", "function f($a,$b){$x=htmlspecialchars($a);echo $x;return $b;}", 2, 1, "xss"},
		{"SQL text operand", "function f($a,$b){mysqli_query($b,\"SELECT id FROM users WHERE id=\".$a);return $b;}", 2, 1, "sql"},
		{"callee mapping", "function g($x,$y){system($y);return $x;}function f($a,$b){return g($b,$a);}", 2, 1, "command"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s, m, _, target, _ := phpWitnessHarness(t, tt.source)
			p := s.phpWitness(m, target.fn)
			if !p.supported() || p.returns != tt.returns {
				t.Fatalf("returns=%b reason=%s", p.returns, p.reason)
			}
			if tt.family == "" {
				if len(p.sinks) != 0 {
					t.Fatal("fabricated effect")
				}
				return
			}
			if len(p.sinks) != 1 || p.sinks[0].family != tt.family || p.sinks[0].parameters != tt.sinkParams {
				t.Fatalf("sink map: %+v", p.sinks)
			}
			at := p.sinks[0].at
			if at.File != "index.php" || at.EndByte <= at.StartByte {
				t.Fatalf("sink lacks source: %+v", at)
			}
		})
	}
}

func TestPHPSummaryWitnessNamedBindingRejected(t *testing.T) {
	s, err := newPHPSet(phpFixture(t, map[string]string{"index.php": "<?php function f($a,$b){echo $a;return $b;} f(a:'x',b:'y');"}))
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	m := s.modules["index.php"]
	var call *sitter.Node
	phpWalk(m.tree.RootNode(), func(n *sitter.Node) {
		if n.Kind() == "function_call_expression" {
			call = n
		}
	})
	f := newPHPWitnessFlow(s, m)
	if _, ok := f.applyPHPWitness(call, &phpBoundCallable{module: m, fn: m.funcs["f"]}, []phpValue{{}, {}}); ok {
		t.Fatal("named binding guessed")
	}
	if len(f.report.Uses) != 0 || len(f.context) != 0 {
		t.Fatal("binding failure partially emitted")
	}
}

func TestPHPSummaryWitnessImplicitReturnGaps(t *testing.T) {
	for _, body := range []string{"function f($a,$b){echo $a;}", "function f($a,$b){echo $a;return;}"} {
		s, m, call, target, args := phpWitnessHarness(t, body)
		gap := analysis.Gap{Kind: "php_expression_unresolved", Detail: "caller uncertainty", At: parse.Span(m.file, call)}
		inline := newPHPWitnessFlow(s, m)
		inline.gaps = []analysis.Gap{gap}
		want := inline.boundHelper(call, target, args)
		witness := newPHPWitnessFlow(s, m)
		witness.gaps = []analysis.Gap{gap}
		got, ok := witness.applyPHPWitness(call, target, args)
		if !ok || !reflect.DeepEqual(want, got) {
			t.Fatalf("implicit/explicit return gap mismatch: body=%s want=%+v got=%+v", body, want, got)
		}
		a, _ := json.Marshal(inline.report.Uses)
		b, _ := json.Marshal(witness.report.Uses)
		if string(a) != string(b) {
			t.Fatal("inherited caller gaps changed sink witness")
		}
	}
}
