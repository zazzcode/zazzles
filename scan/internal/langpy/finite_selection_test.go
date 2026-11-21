package langpy

import (
	"fmt"
	"strings"
	"testing"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

func pythonFiniteFixture(t *testing.T, importLine, extra string) (*pythonFlow, *pythonModule, *sitter.Node, []pythonValue) {
	t.Helper()
	util := importLine + "\ndef module_for(name):\n module_name='targets.{}'.format(name)\n return load(module_name)\ndef select(name,which):\n module=module_for(name)\n return getattr(module,'do_{}'.format(which))\n" + extra
	root := pythonFixture(t, map[string]string{
		"util.py":          util,
		"targets/alpha.py": "def do_good(x):\n return x\ndef do_other(x):\n return x\n",
		"targets/beta.py":  "def do_good(x):\n return x\n",
		"app.py":           "from util import select\ndef app(environ,start_response):\n parts=[s for s in environ['PATH_INFO'].split('/') if s!='']\n name=parts[1]\n which=parts[2]\n select(name,which)\n start_response('200 OK',[])\n",
	})
	set, err := newPythonSet(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(set.close)
	m := set.modules["util.py"]
	app := set.modules["app.py"]
	target := set.modules["targets/alpha.py"]
	work := 24
	f := pythonWitnessTestFlow(set, app, &work)
	f.route = pythonRoute{module: app, fn: app.funcs["app"], generated: true, route: analysis.Route{Framework: "wsgi", PathPattern: "/app/alpha/good"}, selector: &pythonSelectorBinding{
		selector: &pythonBoundCallable{module: m, fn: m.funcs["select"]}, arguments: []string{"alpha", "good"}, target: &pythonBoundCallable{module: target, fn: target.funcs["do_good"]},
	}}
	f.env["environ"] = pythonValue{binding: "flask_request"}
	body := app.funcs["app"].ChildByFieldName("body")
	for i := uint(0); i < 3; i++ {
		f.stmt(body.NamedChild(i))
	}
	args := []pythonValue{f.env["name"], f.env["which"]}
	for _, v := range args {
		if v.finite == nil {
			t.Fatal("source PATH_INFO did not produce finite argument proof")
		}
	}
	var call *sitter.Node
	pyWalk(m.funcs["select"], func(n *sitter.Node) {
		if n.Kind() == "call" && pyText(m, n.ChildByFieldName("function")) == "module_for" {
			call = n
		}
	})
	if call == nil {
		t.Fatal("missing helper call")
	}
	return f, m, call, args
}
func TestPythonFiniteSelectorArguments(t *testing.T) {
	for _, tt := range []struct {
		name   string
		mutate func(*pythonFlow, *pythonModule, []pythonValue)
	}{
		{"exact", nil},
		{"wrong value", func(f *pythonFlow, m *pythonModule, args []pythonValue) {
			args[0].finite = &pythonFiniteValue{staticText("beta"), f.invocation.ID}
		}},
		{"wrong invocation", func(f *pythonFlow, m *pythonModule, args []pythonValue) {
			args[0].finite = &pythonFiniteValue{staticText("alpha"), "sibling"}
		}},
		{"query origin", func(f *pythonFlow, m *pythonModule, args []pythonValue) {
			args[0].deps = append([]pythonDep{}, args[0].deps...)
			for i := range args[0].deps {
				args[0].deps[i].container = "query"
			}
		}},
		{"nonfinite", func(f *pythonFlow, m *pythonModule, args []pythonValue) { args[0].finite = nil }},
		{"shadowed selector", func(f *pythonFlow, m *pythonModule, args []pythonValue) { f.set.staticInvalid[m.file+":select"] = true }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f, m, _, args := pythonFiniteFixture(t, "from importlib import import_module as load", "")
			if tt.mutate != nil {
				tt.mutate(f, m, args)
			}
			got := f.selectorMatches(&pythonBoundCallable{module: m, fn: m.funcs["select"]}, args)
			if got != (tt.mutate == nil) {
				t.Fatalf("selector match=%v", got)
			}
			wrong := &pythonBoundCallable{module: m, fn: m.funcs["module_for"]}
			if f.selectorMatches(wrong, args) {
				t.Fatal("same arguments matched a different selector")
			}
		})
	}
}
func TestPythonFiniteImportWitness(t *testing.T) {
	for _, line := range []string{"from importlib import import_module as load", "import importlib as il\nload=il.import_module"} {
		t.Run(line, func(t *testing.T) {
			// Assignment aliases are not accepted merely because their name resembles
			// an importer; a real import alias is supported.
			f, m, call, args := pythonFiniteFixture(t, line, "")
			f.selectionActive = f.selectorMatches(f.route.selector.selector, args)
			f.module = m
			f.env = map[string]pythonValue{"name": args[0], "which": args[1]}
			v, ok := f.applyWitness(call, &pythonBoundCallable{module: m, fn: m.funcs["module_for"]}, args[:1])
			want := strings.HasPrefix(line, "from importlib")
			if ok != want {
				t.Fatalf("applied=%v plan=%+v", ok, f.set.witnessPlan(m, m.funcs["module_for"]))
			}
			if !ok {
				return
			}
			if len(v.deps) == 0 || v.finite == nil || v.finite.value.module != f.route.selector.target.module {
				t.Fatalf("lost content/module witness: %+v", v)
			}
			for _, d := range v.deps {
				if d.container != "environ" || d.key != "PATH_INFO" || d.protection != "unknown" {
					t.Fatalf("changed input/protection: %+v", d)
				}
			}
			for _, g := range v.gaps {
				if g.Kind == "work_limit" || g.Kind == "python_call_unresolved" {
					t.Fatal("proven module kept call/limit gap", g)
				}
			}
			before := fmt.Sprint(f.context)
			f.selectionActive = false
			if _, ok := f.applyWitness(call, &pythonBoundCallable{module: m, fn: m.funcs["module_for"]}, args[:1]); ok {
				t.Fatal("unmatched import acquired summary")
			}
			if fmt.Sprint(f.context) != before {
				t.Fatal("refused import leaked context")
			}
		})
	}
}
func TestPythonFiniteImportBounds(t *testing.T) {
	for _, tt := range []struct {
		name, extra string
		mutate      func(*pythonFlow, *pythonModule, []pythonValue)
	}{
		{"wrong module", "", func(f *pythonFlow, m *pythonModule, args []pythonValue) {
			args[0].finite = &pythonFiniteValue{staticText("beta"), f.invocation.ID}
		}},
		{"missing module", "", func(f *pythonFlow, m *pythonModule, args []pythonValue) {
			args[0].finite = &pythonFiniteValue{staticText("missing"), f.invocation.ID}
		}},
		{"outside root", "", func(f *pythonFlow, m *pythonModule, args []pythonValue) {
			args[0].finite = &pythonFiniteValue{staticText("../../outside"), f.invocation.ID}
		}},
		{"shadowed alias", "\nload=unknown\n", nil},
		{"deleted alias", "\ndel load\n", nil},
		{"escaped alias", "\nexternal(load)\n", nil},
		{"delattr alias", "\ndelattr(importlib,'import_module')\n", nil},
		{"reflection mutation", "\nsetattr(importlib,'import_module',unknown)\n", nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			line := "from importlib import import_module as load"
			if tt.name == "reflection mutation" || tt.name == "delattr alias" {
				line = "import importlib\nfrom importlib import import_module as load"
			}
			f, m, call, args := pythonFiniteFixture(t, line, tt.extra)
			f.selectionActive = true
			f.module = m
			f.env = map[string]pythonValue{"name": args[0], "which": args[1]}
			if tt.mutate != nil {
				tt.mutate(f, m, args)
			}
			before := len(f.report.Uses)
			if _, ok := f.applyWitness(call, &pythonBoundCallable{module: m, fn: m.funcs["module_for"]}, args[:1]); ok {
				t.Fatal("unsupported import closed")
			}
			if len(f.report.Uses) != before {
				t.Fatal("unsupported import emitted a partial sink")
			}
		})
	}
}

func TestPythonFiniteRegistryFreezeBounds(t *testing.T) {
	cycle := &pythonStaticValue{known: true, fields: map[string]*pythonStaticValue{}}
	cycle.fields["self"] = cycle
	if cloneFiniteRegistry(cycle) != nil {
		t.Fatal("cyclic registry freeze succeeded")
	}
	large := &pythonStaticValue{known: true, items: make([]*pythonStaticValue, 4097)}
	for i := range large.items {
		large.items[i] = staticText("x")
	}
	if cloneFiniteRegistry(large) != nil {
		t.Fatal("unbounded registry freeze succeeded")
	}
	deep := staticText("leaf")
	for range 65 {
		deep = &pythonStaticValue{known: true, items: []*pythonStaticValue{deep}}
	}
	if cloneFiniteRegistry(deep) != nil {
		t.Fatal("deep registry freeze succeeded")
	}
	simple := &pythonStaticValue{known: true, fields: map[string]*pythonStaticValue{"a": {known: true, items: []*pythonStaticValue{staticText("x")}}}}
	frozen := cloneFiniteRegistry(simple)
	if frozen == nil {
		t.Fatal("simple registry rejected")
	}
	simple.fields["a"].items[0].text = "changed"
	if frozen.fields["a"].items[0].text != "x" {
		t.Fatal("frozen proof retained mutable alias")
	}
}

func TestPythonFiniteStringReceivers(t *testing.T) {
	f, m, _, _ := pythonFiniteFixture(t, "from importlib import import_module as load", "")
	// A source module's same-named method must never be interpreted as a
	// string transform merely because the module is a known static value.
	fakeRoot := pythonFixture(t, map[string]string{"fake.py": "def replace(a,b):\n return 'beta'\n", "app.py": "import fake\ndef f():\n return fake.replace('', 'alpha')\n"})
	s, err := newPythonSet(fakeRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	fakeApp := s.modules["app.py"]
	var fakeCall *sitter.Node
	pyWalk(fakeApp.tree.RootNode(), func(n *sitter.Node) {
		if n.Kind() == "call" {
			fakeCall = n
		}
	})
	h := &pythonStatic{set: s, module: fakeApp, env: map[string]*pythonStaticValue{}, stack: map[string]bool{}, work: new(int), proof: true}
	if got := h.eval(fakeCall); got.known {
		t.Fatalf("module method acquired string proof: %+v", got)
	}
	for _, tc := range []struct {
		source string
		known  bool
	}{
		{"'42'.replace('42','alpha')", true},
		{"(42).replace('42','alpha')", false},
		{"(True).replace('True','alpha')", false},
		{"(None).replace('None','alpha')", false},
	} {
		root := pythonFixture(t, map[string]string{"a.py": "def g():\n return " + tc.source + "\n"})
		set, err := newPythonSet(root)
		if err != nil {
			t.Fatal(err)
		}
		mod := set.modules["a.py"]
		var call *sitter.Node
		pyWalk(mod.tree.RootNode(), func(n *sitter.Node) {
			if n.Kind() == "call" {
				call = n
			}
		})
		proof := &pythonStatic{set: set, module: mod, env: map[string]*pythonStaticValue{}, stack: map[string]bool{}, work: new(int), proof: true}
		got := proof.eval(call)
		if got.known != tc.known {
			t.Errorf("%s: proof=%+v", tc.source, got)
		}
		set.close()
	}
	// A primitive proof remains primitive after being bound through an env.
	count := 0
	h = &pythonStatic{set: f.set, module: m, env: map[string]*pythonStaticValue{"v": {known: true, text: "42", proofString: false}}, stack: map[string]bool{}, work: &count, proof: true}
	n := &pythonStaticValue{known: true, text: "42", proofString: false}
	if value, ok := h.method(nil, n, "replace", []*pythonStaticValue{staticText("42"), staticText("alpha")}); !ok || value.known {
		t.Fatal("numeric env value acquired string proof")
	}
	if value, ok := h.method(nil, staticText("targets.{}"), "format", []*pythonStaticValue{{known: true, module: m}}); !ok || value.known {
		t.Fatal("module argument acquired string formatting proof")
	}
}
func TestPythonWitnessImportAliasLimit(t *testing.T) {
	source := "import os\n"
	for i := 0; i < 10; i++ {
		rhs := "os"
		if i < 9 {
			rhs = fmt.Sprintf("a%d", i+1)
		}
		source += fmt.Sprintf("a%d=%s\n", i, rhs)
	}
	source += "external(a0)\ndef f(x):\n return os.system(x)\n"
	s, m, _, _ := pythonWitnessTestFixture(t, source)
	if !m.unsafeWitnessBindings() {
		t.Fatal("alias inference cap was silently accepted")
	}
	if p := s.witnessPlan(m, m.funcs["f"]); p.reason == "" {
		t.Fatal("capped alias chain resolved imported API")
	}
}

func TestPythonFiniteProofComparisonTypes(t *testing.T) {
	for _, source := range []string{"'1'==1", "1=='1'", "True=='True'"} {
		root := pythonFixture(t, map[string]string{"a.py": "value=" + source + "\n"})
		s, err := newPythonSet(root)
		if err != nil {
			t.Fatal(err)
		}
		m := s.modules["a.py"]
		count := 0
		f := &pythonStatic{set: s, module: m, env: map[string]*pythonStaticValue{}, stack: map[string]bool{}, work: &count, proof: true}
		if value := f.eval(m.vars["value"]); value.known {
			t.Fatalf("mixed scalar types compared as text: %s -> %+v", source, value)
		}
		s.close()
	}
}

func TestPythonFiniteProofJoin(t *testing.T) {
	a := pythonValue{constant: true, literal: "alpha", finite: &pythonFiniteValue{staticText("alpha"), "one"}}
	same := a
	if pyJoin(a, same, 0).finite == nil {
		t.Fatal("unchanged branch lost proof")
	}
	b := pythonValue{constant: true, literal: "beta", finite: &pythonFiniteValue{staticText("beta"), "one"}}
	if pyJoin(a, b, 0).finite != nil {
		t.Fatal("different branch retained stale proof")
	}
	if pyJoin(a, pythonValue{unknown: true}, 0).finite != nil {
		t.Fatal("unknown branch retained proof")
	}
	b = a
	b.finite = &pythonFiniteValue{staticText("alpha"), "other"}
	if pyJoin(a, b, 0).finite != nil {
		t.Fatal("proof crossed invocation")
	}
	if pyCombine(a, same).finite != nil {
		t.Fatal("expression aggregation retained unrelated proof")
	}
}

func TestPythonFiniteProofIndexTypes(t *testing.T) {
	for _, tc := range []struct {
		expr  string
		known bool
	}{
		{"['alpha'][0]", true},
		{"['alpha']['0']", false},
	} {
		root := pythonFixture(t, map[string]string{"a.py": "def f():\n return " + tc.expr + "\n"})
		set, err := newPythonSet(root)
		if err != nil {
			t.Fatal(err)
		}
		m := set.modules["a.py"]
		var index *sitter.Node
		pyWalk(m.tree.RootNode(), func(n *sitter.Node) {
			if n.Kind() == "subscript" {
				index = n
			}
		})
		h := &pythonStatic{set: set, module: m, env: map[string]*pythonStaticValue{}, stack: map[string]bool{}, work: new(int), proof: true}
		got := h.eval(index)
		if got.known != tc.known {
			t.Fatalf("%s proof=%+v", tc.expr, got)
		}
		set.close()
	}
	f, _, _, _ := pythonFiniteFixture(t, "from importlib import import_module as load", "")
	f.env["untyped"] = pythonValue{constant: true, literal: "0"}
	if f.finiteEnvironment()["untyped"].known {
		t.Fatal("untyped native constant acquired numeric/string proof")
	}
}
