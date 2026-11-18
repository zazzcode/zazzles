package langpy

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
)

func TestPythonClosedSummaries(t *testing.T) {
	for _, tt := range []struct {
		name, source string
		closed       bool
	}{
		{"decorated", "def decorate(x):\n return x\n@decorate\ndef f(x):\n return x\n", false},
		{"receiver shadow", "import helper as mod\ndef f(mod):\n return mod.g(1)\n", false},
		{"identity", "def f(x):\n return x\n", true},
		{"constant", "def f(x):\n return 1\n", true},
		{"chain", "def g(x):\n return x\ndef f(x):\n return g(x)\n", true},
		{"source", "def f(x):\n return request.args.get('x')\n", false},
		{"sink", "def f(x):\n print(x)\n", false},
		{"global", "def f(x):\n global y\n y=x\n", false},
		{"heap", "def f(x):\n x[0]=1\n", false},
		{"ambient", "def f(x):\n return y\n", false},
		{"default", "def f(x=acquire()):\n return x\n", false},
		{"variadic", "def f(*x):\n return x\n", false},
		{"nested", "def f(x):\n def g():\n  return x\n return g()\n", false},
		{"recursion", "def f(x):\n return f(x)\n", false},
		{"shadow", "def g(x):\n return 1\ndef f(g):\n return g()\n", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := pythonFixture(t, map[string]string{"app.py": tt.source})
			s, err := newPythonSet(root)
			if err != nil {
				t.Fatal(err)
			}
			defer s.close()
			m := s.modules["app.py"]
			c := s.callableSummary(m, m.funcs["f"])
			if c.Closed() != tt.closed {
				t.Fatalf("closed=%v reasons=%v", c.Closed(), c.Reasons)
			}
			if c != s.callableSummary(m, m.funcs["f"]) {
				t.Fatal("summary not cached")
			}
		})
	}
}

// The PHP halves of these tests live in internal/langphp/closed_summary_test.go
// under the same test names.

func TestClosedAndDependentSummaryRefusals(t *testing.T) {
	t.Run("python", func(t *testing.T) {
		root := pythonFixture(t, map[string]string{"app.py": "def f(x):\n return x\nf(1)\n"})
		s, err := newPythonSet(root)
		if err != nil {
			t.Fatal(err)
		}
		defer s.close()
		m := s.modules["app.py"]
		fn := m.funcs["f"]
		var call *sitter.Node
		pyWalk(m.tree.RootNode(), func(n *sitter.Node) {
			if n.Kind() == "call" {
				call = n
			}
		})
		work := 24
		f := &pythonFlow{set: s, module: m, work: &work, report: &analysis.AnalysisReport{}}
		for _, tainted := range []bool{false, true} {
			v := pythonValue{constant: true}
			if tainted {
				v.deps = []pythonDep{{}}
			}
			got := f.boundHelper(call, &pythonBoundCallable{module: m, fn: fn}, []pythonValue{v})
			if len(got.gaps) > 0 {
				t.Fatalf("supported identity retained refusal: tainted=%v gaps=%v", tainted, got.gaps)
			}
			want := 0
			if tainted {
				want = 1
			}
			if len(got.deps) != want {
				t.Fatalf("tainted=%v dependencies=%d want=%d", tainted, len(got.deps), want)
			}
			if tainted {
				binding := false
				for _, e := range got.deps[0].dep.Transfers {
					binding = binding || e.Kind == "argument_to_parameter"
				}
				if !binding {
					t.Fatal("dependent identity lost concrete parameter witness")
				}
			}
		}
	})
}

func TestPythonSummaryShadow(t *testing.T) {
	count, applicable, failures := 0, 0, 0
	check := func(closed, inert bool, deps, gaps, uses int) {
		count++
		if closed && inert {
			applicable++
			if deps+gaps+uses > 0 {
				failures++
			}
		}
	}
	pythonSummaryShadow = func(f *pythonFlow, n *sitter.Node, c *pythonBoundCallable, args []pythonValue, ret pythonValue, uses int) {
		check(f.set.callableSummary(c.module, c.fn).Closed(), f.closedSummaryCall(n, c, args), len(ret.deps), len(ret.gaps), uses)
	}
	defer func() { pythonSummaryShadow = nil }()
	dirs, err := os.ReadDir(filepath.Join("testdata"))
	if err != nil {
		t.Fatal(err)
	}
	roots := []string{}
	for _, d := range dirs {
		if d.IsDir() {
			roots = append(roots, filepath.Join("testdata", d.Name()))
		}
	}
	if sample := os.Getenv("ZAZZLES_VULNPY"); sample != "" {
		roots = append(roots, sample)
	}
	roots = append(roots, pythonFixture(t, map[string]string{"app.py": "from flask import Flask\napp=Flask(__name__)\ndef identity(x):\n return x\n@app.get('/')\ndef index():\n return identity(1)\n"}))
	for _, root := range roots {
		if _, err := Analyze(root, ""); err != nil {
			t.Fatal(err)
		}
	}
	if failures != 0 || count == 0 || applicable == 0 {
		t.Fatalf("expansions=%d applicable=%d failures=%d", count, applicable, failures)
	}
	before := failures
	check(true, true, 1, 0, 1)
	if failures != before+1 {
		t.Fatal("shadow mutation oracle is inert")
	}
	t.Logf("expansions=%d applicable=%d disagreements=%d; mutation detected", count, applicable, before)
}

func TestSummaryShadowMutation(t *testing.T) {
	t.Run("python", func(t *testing.T) {
		detected := false
		pythonSummaryShadow = func(f *pythonFlow, n *sitter.Node, c *pythonBoundCallable, args []pythonValue, ret pythonValue, uses int) {
			if pyText(c.module, c.fn.ChildByFieldName("name")) != "leak" {
				return
			}
			sum := f.set.callableSummary(c.module, c.fn)
			sum.Reasons = nil
			detected = f.closedSummaryCall(n, c, args) && (len(ret.deps) > 0 || uses > 0)
		}
		defer func() { pythonSummaryShadow = nil }()
		root := pythonFixture(t, map[string]string{"app.py": "from flask import Flask,request\napp=Flask(__name__)\ndef leak(x):\n return request.args.get('x')\n@app.get('/')\ndef index():\n return leak(1)\n"})
		if _, err := Analyze(root, ""); err != nil {
			t.Fatal(err)
		}
		if !detected {
			t.Fatal("unsound closed summary escaped the inline oracle")
		}
	})
}

func TestClosedSummaryLimits(t *testing.T) {
	t.Run("python", func(t *testing.T) {
		source := ""
		for i := 0; i < 66; i++ {
			source += fmt.Sprintf("def f%d(x):\n return f%d(x)\n", i, i+1)
		}
		s, err := newPythonSet(pythonFixture(t, map[string]string{"a.py": source}))
		if err != nil {
			t.Fatal(err)
		}
		defer s.close()
		c := s.callableSummary(s.modules["a.py"], s.modules["a.py"].funcs["f0"])
		if c.Closed() {
			t.Fatal("depth cap closed")
		}
		found := false
		for _, sum := range s.summaries {
			for _, r := range sum.Reasons {
				found = found || r.Kind == "summary_limit"
			}
		}
		if !found {
			t.Fatal("missing summary_limit")
		}
	})
}

func TestPythonSummaryBindingRegressions(t *testing.T) {
	for _, tt := range []struct{ name, src string }{
		{"decorated", "@unknown\ndef f(x):\n return x\n"},
		{"module_receiver_write", "import helper as mod\nmod = acquire()\ndef f(x):\n return mod.g(x)\n"},
		{"parameter_receiver", "import helper as mod\ndef f(mod):\n return mod.g(1)\n"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s, e := newPythonSet(pythonFixture(t, map[string]string{"a.py": tt.src, "helper.py": "def g(x):\n return x\n"}))
			if e != nil {
				t.Fatal(e)
			}
			defer s.close()
			m := s.modules["a.py"]
			c := s.callableSummary(m, m.funcs["f"])
			t.Logf("closed=%v reasons=%v", c.Closed(), c.Reasons)
			if c.Closed() {
				t.Error("unsupported decorated or receiver binding closed")
			}
		})
	}
}
