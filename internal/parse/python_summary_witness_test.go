package parse

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
)

func pythonWitnessTestFixture(t *testing.T, body string) (*pythonSet, *pythonModule, *sitter.Node, *sitter.Node) {
	t.Helper()
	root := pythonFixture(t, map[string]string{"app.py": body + "\nf('caller-left')\nf('caller-right')\n"})
	s, err := newPythonSet(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.close)
	m := s.modules["app.py"]
	var calls []*sitter.Node
	pyWalk(m.tree.RootNode(), func(n *sitter.Node) {
		if n.Kind() == "call" && pyText(m, n.ChildByFieldName("function")) == "f" {
			calls = append(calls, n)
		}
	})
	if len(calls) < 2 {
		t.Fatal("missing test callers")
	}
	return s, m, calls[len(calls)-2], calls[len(calls)-1]
}
func pythonWitnessTestFlow(s *pythonSet, m *pythonModule, work *int) *pythonFlow {
	return &pythonFlow{set: s, module: m, route: pythonRoute{module: m, fn: m.funcs["f"]}, invocation: analysis.InvocationContext{ID: "ctx", EntryID: "entry"}, report: &analysis.AnalysisReport{}, env: map[string]pythonValue{}, inputs: map[string]pythonValue{}, guards: map[string][]analysis.Gap{}, imports: map[string]pythonImport{}, stack: map[string]bool{}, work: work}
}
func TestPythonSummaryWitnessParity(t *testing.T) {
	for _, tt := range []struct{ name, body string }{
		{"return fanout", "def f(x):\n y=x+x\n return y\n"},
		{"controlled return", "import shlex\ndef f(x):\n y=shlex.quote(x)\n return y\n"},
		{"sink and return", "import os\ndef f(x):\n os.system(x)\n return x\n"},
		{"helper DAG", "import os\ndef g(x):\n y=x+x\n os.system(y)\n return y\ndef f(x):\n return g(x)\n"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s, m, call, _ := pythonWitnessTestFixture(t, tt.body)
			plan := s.witnessPlan(m, m.funcs["f"])
			if plan.reason != "" {
				t.Fatal(plan.reason)
			}
			if plan != s.witnessPlan(m, m.funcs["f"]) {
				t.Fatal("plan not cached")
			}
			source := m.evidence("input_source", pyArgs(call)[0])
			arg := pythonValue{deps: []pythonDep{{dep: analysis.Dependency{Source: source}, protection: "raw", container: "args", key: "left"}}}
			var lastReturn pythonValue
			run := func(p *pythonWitnessPlan) []byte {
				work := 0
				f := pythonWitnessTestFlow(s, m, &work)
				ret := f.helperFrame(call, &pythonBoundCallable{module: m, fn: m.funcs["f"]}, []pythonValue{arg}, p)
				lastReturn = ret
				raw, err := json.Marshal(struct {
					Return       pythonValue
					Dependencies []analysis.Dependency
					Gaps         []analysis.Gap
					Context      []analysis.Evidence
					Uses         []analysis.CandidateUse
				}{ret, pythonPublicDeps(ret.deps), ret.gaps, f.context, f.report.Uses})
				if err != nil {
					t.Fatal(err)
				}
				return raw
			}
			a := run(nil)
			nativeReturn := lastReturn
			b := run(plan)
			if !reflect.DeepEqual(nativeReturn, lastReturn) {
				t.Fatalf("complete native/summary return mismatch: native=%+v summary=%+v", nativeReturn, lastReturn)
			}
			if string(a) != string(b) {
				t.Fatalf("native/summary witness mismatch\ninline=%s\nsummary=%s", a, b)
			}
			old := plan.ops[0].expr.node
			plan.ops[0].expr.node = pyArgs(call)[0]
			if reflect.DeepEqual(a, run(plan)) {
				t.Fatal("mutated span binding escaped differential oracle")
			}
			plan.ops[0].expr.node = old
		})
	}
}
func TestPythonSummaryWitnessTwoCallers(t *testing.T) {
	s, m, left, right := pythonWitnessTestFixture(t, "import os\ndef f(x):\n y=x+x\n os.system(y)\n return y\n")
	sources := map[int]bool{}
	for _, call := range []*sitter.Node{left, right} {
		source := m.evidence("input_source", pyArgs(call)[0])
		arg := pythonValue{deps: []pythonDep{{dep: analysis.Dependency{Source: source}, protection: "raw"}}}
		work := 24
		f := pythonWitnessTestFlow(s, m, &work)
		v, ok := f.applyWitness(call, &pythonBoundCallable{module: m, fn: m.funcs["f"]}, []pythonValue{arg})
		if !ok {
			t.Fatal("supported summary refused")
		}
		if len(f.report.Uses) != 1 || len(v.deps) == 0 {
			t.Fatalf("uses/return %+v %v", f.report.Uses, v.deps)
		}
		d := f.report.Uses[0].Dependencies[0]
		if d.Source.Span != source.Span {
			t.Fatal("caller source leaked")
		}
		seenParam, seenAssignment := false, false
		for _, e := range d.Transfers {
			seenParam = seenParam || e.Kind == "argument_to_parameter"
			seenAssignment = seenAssignment || e.Kind == "assignment"
			if e.Span.File != "app.py" || e.SHA256 == "" {
				t.Fatalf("unbacked witness: %+v", e)
			}
		}
		if !seenParam || !seenAssignment {
			t.Fatalf("missing concrete transfer %v", d.Transfers)
		}
		sources[d.Source.Span.StartByte] = true
	}
	if len(sources) != 2 {
		t.Fatal("callers shared a source")
	}
}
func TestPythonSummaryWitnessRejectsBeforeEffects(t *testing.T) {
	for _, body := range []string{
		"import os\ndef f(x):\n os.system(x)\n if x:\n  return x\n",
		"def f(x):\n return f(x)\n",
		"async def f(x):\n return x\n",
		"def f(x,x):\n return x\n",
		"import os\ndel os.system\ndef f(x):\n return os.system(x)\n",
		"import os\ndelattr(os,'system')\ndef f(x):\n return os.system(x)\n",
		"def f(x):\n return x()\n",
		"def f(x=1):\n return x\n",
		"def f(x):\n global g\n g=x\n return x\n",
		"def f(x):\n x[0]=1\n return x\n",
		"def f(x):\n return x.replace('a','b')\n",
		"C='fixed'\nC=unknown()\ndef f(x):\n return C+x\n",
		"from importlib import import_module\ndef f(x):\n print(x)\n return import_module(x)\n",
		"from foreign import open\ndef f(x):\n return open(x)\n",
		"import os\ndef f(os):\n return os.system(os)\n",
		"import os\nexternal(os)\ndef f(x):\n return os.system(x)\n",
		"import os\nmutate=setattr\nmutate(os,'system',external)\ndef f(x):\n return os.system(x)\n",
		"import os\ndef patch():\n alias=os\n external(alias)\ndef f(x):\n return os.system(x)\n",
		"def g(x):\n return x\ndef f(x):\n print(x)\n return g(x,x)\n",
	} {
		s, m, call, _ := pythonWitnessTestFixture(t, body)
		work := 24
		f := pythonWitnessTestFlow(s, m, &work)
		if _, ok := f.applyWitness(call, &pythonBoundCallable{module: m, fn: m.funcs["f"]}, []pythonValue{{}}); ok {
			t.Fatalf("unsupported recipe applied: %s", body)
		}
		if len(f.report.Uses) != 0 || len(f.context) != 0 || len(f.env) != 0 {
			t.Fatal("rejected plan leaked effects")
		}
	}
	source := "def f(x):\n" + strings.Repeat(" x=x+x\n", 1500) + " return x\n"
	s, m, call, _ := pythonWitnessTestFixture(t, source)
	work := 24
	f := pythonWitnessTestFlow(s, m, &work)
	if _, ok := f.applyWitness(call, &pythonBoundCallable{module: m, fn: m.funcs["f"]}, []pythonValue{{}}); ok {
		t.Fatal("oversized recipe applied")
	}
}

func pythonPublicDeps(deps []pythonDep) []analysis.Dependency {
	out := make([]analysis.Dependency, len(deps))
	for i, d := range deps {
		out[i] = d.dep
	}
	return out
}

func TestPythonFiniteSelectionVulnpy(t *testing.T) {
	root := os.Getenv("ZAZZLES_VULNPY")
	if root == "" {
		t.Skip("set ZAZZLES_VULNPY for pinned diagnostic")
	}
	report, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	work := 0
	for _, u := range report.Uses {
		for _, g := range u.Gaps {
			if g.Kind == "work_limit" && g.At.File == "src/vulnpy/trigger/util.py" && g.At.StartLine == 54 {
				work++
			}
		}
	}
	if baseline := os.Getenv("ZAZZLES_VULNPY_BASELINE"); baseline != "" {
		raw, err := os.ReadFile(baseline)
		if err != nil {
			t.Fatal(err)
		}
		var old analysis.AnalysisReport
		if err := json.Unmarshal(raw, &old); err != nil {
			t.Fatal(err)
		}
		key := func(u analysis.CandidateUse) string {
			return fmt.Sprintf("%s|%s|%s:%d:%d", u.Kind, u.EntryID, u.Sink.Span.File, u.Sink.Span.StartByte, u.Sink.Span.EndByte)
		}
		current := map[string][]analysis.CandidateUse{}
		for _, u := range report.Uses {
			current[key(u)] = append(current[key(u)], u)
		}
		for _, u := range old.Uses {
			rows := current[key(u)]
			if len(rows) == 0 {
				t.Fatalf("HALT: removed sample candidate %s", key(u))
			}
			found := map[analysis.Span]bool{}
			for _, v := range rows {
				for _, d := range v.Dependencies {
					found[d.Source.Span] = true
				}
			}
			for _, d := range u.Dependencies {
				if !found[d.Source.Span] {
					t.Fatalf("source removed from existing sample candidate %s: %+v", key(u), d.Source.Span)
				}
			}
		}
		if len(old.Uses) != len(report.Uses) {
			t.Fatalf("candidate count delta needs source-guide review: %d -> %d", len(old.Uses), len(report.Uses))
		}
		t.Logf("all %d prior semantic candidate keys and source spans retained", len(old.Uses))
	}
	t.Logf("uses=%d targeted remaining=%d", len(report.Uses), work)
	if work != 0 {
		t.Fatalf("targeted import-selector work gaps remain: %d", work)
	}
}

func TestPythonSummaryWitnessEffectAssignment(t *testing.T) {
	s, m, _, _ := pythonWitnessTestFixture(t, "import os\ndef f(x):\n y=os.system(x)\n return y\n")
	p := s.witnessPlan(m, m.funcs["f"])
	if p.reason != "" || !p.effectful {
		t.Fatalf("assignment hid sink effect: %+v", p)
	}
}
