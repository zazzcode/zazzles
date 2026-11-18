package langphp

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
)

// The PHP halves of the shared closed-summary tests; the Python halves stay in
// internal/parse/closed_summary_test.go under the same test names.

func TestPHPClosedSummaries(t *testing.T) {
	for _, tt := range []struct {
		name, source string
		closed       bool
	}{
		{"identity", "function f($x){return $x;}", true},
		{"constant", "function f($x){return 1;}", true},
		{"chain", "function g($x){return $x;} function f($x){return g($x);}", true},
		{"source", "function f($x){return $_GET['x'];}", false},
		{"sink", "function f($x){echo $x;}", false},
		{"global", "function f($x){global $y; $y=$x;}", false},
		{"heap", "function f($x){$x[0]=1;}", false},
		{"ambient", "function f($x){return $y;}", false},
		{"default", "function f($x=1){return $x;}", false},
		{"variadic", "function f(...$x){return $x;}", false},
		{"reference", "function f(&$x){return $x;}", false},
		{"nested", "function f($x){return function() use ($x){return $x;};}", false},
		{"recursion", "function f($x){return f($x);}", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := phpFixture(t, map[string]string{"app.php": "<?php " + tt.source})
			s, err := newPHPSet(root)
			if err != nil {
				t.Fatal(err)
			}
			defer s.close()
			m := s.modules["app.php"]
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

func TestClosedAndDependentSummaryRefusals(t *testing.T) {
	t.Run("php", func(t *testing.T) {
		root := phpFixture(t, map[string]string{"app.php": "<?php function f($x){return $x;} f(1);"})
		s, err := newPHPSet(root)
		if err != nil {
			t.Fatal(err)
		}
		defer s.close()
		m := s.modules["app.php"]
		var call *sitter.Node
		phpWalk(m.tree.RootNode(), func(n *sitter.Node) {
			if n.Kind() == "function_call_expression" {
				call = n
			}
		})
		work := phpHelperWorkLimit
		f := &phpFlow{set: s, module: m, work: &work, report: &analysis.AnalysisReport{}}
		for _, tainted := range []bool{false, true} {
			v := phpValue{constant: true}
			if tainted {
				v.deps = []phpDep{{}}
			}
			got := f.boundHelper(call, &phpBoundCallable{module: m, fn: m.funcs["f"]}, []phpValue{v})
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

func TestPHPSummaryShadow(t *testing.T) {
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
	phpSummaryShadow = func(f *phpFlow, n *sitter.Node, c *phpBoundCallable, args []phpValue, ret phpValue, uses int) {
		check(f.set.callableSummary(c.module, c.fn).Closed(), f.closedSummaryCall(n, c, args), len(ret.deps), len(ret.gaps), uses)
	}
	defer func() { phpSummaryShadow = nil }()
	dirs, err := os.ReadDir("testdata")
	if err != nil {
		t.Fatal(err)
	}
	roots := []string{}
	for _, d := range dirs {
		if d.IsDir() {
			roots = append(roots, filepath.Join("testdata", d.Name()))
		}
	}
	if sample := os.Getenv("ZAZZLES_DVWA"); sample != "" {
		roots = append(roots, sample)
	}
	roots = append(roots, phpFixture(t, map[string]string{"app.php": "<?php function identity($x){return $x;} echo identity(1);"}))
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
	t.Run("php", func(t *testing.T) {
		detected := false
		phpSummaryShadow = func(f *phpFlow, n *sitter.Node, c *phpBoundCallable, args []phpValue, ret phpValue, uses int) {
			if phpText(c.module, phpField(c.fn, "name")) != "leak" {
				return
			}
			sum := f.set.callableSummary(c.module, c.fn)
			sum.Reasons = nil
			detected = f.closedSummaryCall(n, c, args) && (len(ret.deps) > 0 || uses > 0)
		}
		defer func() { phpSummaryShadow = nil }()
		root := phpFixture(t, map[string]string{"index.php": "<?php function leak($x){echo $_GET['x']; return $_GET['x'];} echo leak(1);"})
		if _, err := Analyze(root, ""); err != nil {
			t.Fatal(err)
		}
		if !detected {
			t.Fatal("unsound closed summary escaped the inline oracle")
		}
	})
}

func TestClosedSummaryLimits(t *testing.T) {
	t.Run("php", func(t *testing.T) {
		source := ""
		for i := 0; i < 66; i++ {
			source += fmt.Sprintf("function f%d($x){return f%d($x);}\n", i, i+1)
		}
		s, err := newPHPSet(phpFixture(t, map[string]string{"a.php": "<?php " + source}))
		if err != nil {
			t.Fatal(err)
		}
		defer s.close()
		c := s.callableSummary(s.modules["a.php"], s.modules["a.php"].funcs["f0"])
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
