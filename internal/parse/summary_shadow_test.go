package parse

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
)

// TestSummaryShadowParity compares every inline helper expansion with the
// callee's summary (spec §8b AC2). Inline expansion is the oracle:
//   - each dependency of a precise inline result comes from an argument at a
//     parameter the summary says may reach the result, or was acquired inside
//     the callee, which only a summary that does not apply may allow;
//   - where the summary is closed and the arguments it reads are inert, the
//     inline body records no use and the result has no dependency.
//
// It runs on every JS/TS fixture repository, and on juice-shop when
// ZAZZLES_JUICE_SHOP is set. Fixture uses must also carry no expansion-limit gap.
func TestSummaryShadowParity(t *testing.T) {
	roots := shadowFixtureRoots(t)
	fixtures := len(roots)
	if js := os.Getenv("ZAZZLES_JUICE_SHOP"); js != "" {
		roots = append(roots, js)
	}
	total := shadowCounts{}
	for i, root := range roots {
		got, report, failures := shadowRun(t, root)
		for _, f := range failures {
			t.Errorf("%s: %s", root, f)
		}
		// AC3: no fixture keeps an expansion-limit gap on a closed helper.
		for _, u := range report.Uses {
			for _, g := range u.Gaps {
				if i < fixtures && (g.Kind == "helper_call_limit" || g.Kind == "path_unrelated_helper_limit") {
					t.Errorf("%s: fixture use %s keeps %s: %s", root, u.ID, g.Kind, g.Detail)
				}
			}
		}
		total.add(got)
		t.Logf("%s: %+v", filepath.Base(root), got)
	}
	t.Logf("total: %+v", total)
	if total.precise == 0 || total.applicable == 0 {
		t.Fatalf("the shadow test checked too little: %+v", total)
	}
}

type shadowCounts struct {
	expansions, precise, applicable, argumentDeps, insideDeps int
}

func (c *shadowCounts) add(o shadowCounts) {
	c.expansions += o.expansions
	c.precise += o.precise
	c.applicable += o.applicable
	c.argumentDeps += o.argumentDeps
	c.insideDeps += o.insideDeps
}

func shadowFixtureRoots(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, group := range []string{"javascript", "typescript", "mixed"} {
		entries, err := os.ReadDir(filepath.Join("testdata", group))
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if e.IsDir() {
				out = append(out, filepath.Join("testdata", group, e.Name()))
			}
		}
	}
	out = append(out, filepath.Join("testdata", "express-login"), filepath.Join("testdata", "string-flow"))
	sort.Strings(out)
	return out
}

func shadowRun(t *testing.T, root string) (shadowCounts, *analysis.AnalysisReport, []string) {
	t.Helper()
	var counts shadowCounts
	var failures []string
	seen := map[string]bool{}
	summaryShadow = func(f *flow, call *sitter.Node, hm *sourceModule, helper *sitter.Node, args []value, ret value, precise bool, uses []analysis.CandidateUse) {
		counts.expansions++
		sum := f.set.callableSummary(hm, helper)
		applies := f.closedSummaryCall(call, hm, helper, args)
		site := fmt.Sprintf("%s:%d -> %s", f.module.file, call.StartByte(), sum.key)
		fail := func(format string, a ...any) {
			msg := site + ": " + fmt.Sprintf(format, a...)
			if !seen[msg] {
				seen[msg] = true
				failures = append(failures, msg)
			}
		}
		if applies {
			counts.applicable++
			if len(uses) > 0 {
				fail("closed summary with inert arguments, but the inline body recorded %d uses (first %s)", len(uses), uses[0].Kind)
			}
		}
		if !precise {
			return
		}
		counts.precise++
		sources := make([]map[string]bool, len(args))
		for i, a := range args {
			sources[i] = map[string]bool{}
			for _, d := range valueDeps(a, 0) {
				sources[i][evidenceKey(d.Source)] = true
			}
		}
		for _, d := range valueDeps(ret, 0) {
			key := evidenceKey(d.Source)
			from, allowed := false, false
			for i := range args {
				if sources[i][key] {
					from = true
					allowed = allowed || (sum.indexed && sum.returns&(1<<uint(i)) != 0)
				}
			}
			switch {
			case from && !allowed && sum.indexed:
				fail("result dependency %s comes from an argument at a parameter outside returns %b", key, sum.returns)
			case from:
				counts.argumentDeps++
			default:
				counts.insideDeps++
				if applies {
					fail("closed summary with inert arguments, but the result acquired %s inside the callee", key)
				}
			}
		}
	}
	defer func() { summaryShadow = nil }()
	report, err := Analyze(root, "")
	if err != nil {
		t.Fatalf("%s: %v", root, err)
	}
	return counts, report, failures
}

// valueDeps lists a value's dependencies and those of its nested fields.
func valueDeps(v value, depth int) []analysis.Dependency {
	out := append([]analysis.Dependency{}, v.deps...)
	if depth > 8 {
		return out
	}
	keys := make([]string, 0, len(v.fields))
	for k := range v.fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		out = append(out, valueDeps(v.fields[k], depth+1)...)
	}
	return out
}

func evidenceKey(e analysis.Evidence) string {
	return fmt.Sprintf("%s@%s:%d-%d", e.Kind, e.Span.File, e.Span.StartByte, e.Span.EndByte)
}

// TestSummaryRemainingReasons attributes every expansion-limit gap, and every
// unknown_call_result on an in-repository callee, that remains on juice-shop to
// the callee summary's first blocking reason (spec §8b AC4). A closed summary
// that still left a gap names "arguments_not_inert". Env-gated: ZAZZLES_JUICE_SHOP.
func TestSummaryRemainingReasons(t *testing.T) {
	root := os.Getenv("ZAZZLES_JUICE_SHOP")
	if root == "" {
		t.Skip("set ZAZZLES_JUICE_SHOP")
	}
	report, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	ps, err := newParsers()
	if err != nil {
		t.Fatal(err)
	}
	set := &moduleSet{root: root, parsers: ps, modules: map[string]*sourceModule{}, allowed: map[string]bool{}}
	defer set.close()
	for _, f := range report.Files {
		set.allowed[f.Span.File] = true
	}
	// Load every file first, as the scan does, so no summary sees a missing module.
	for _, f := range report.Files {
		_, _ = set.load(f.Span.File)
	}
	var gaps []analysis.Gap
	for _, u := range report.Uses {
		gaps = append(gaps, u.Gaps...)
	}
	for _, e := range report.Entries {
		gaps = append(gaps, e.Gaps...)
	}
	counts := map[string]int{}
	closedLeft := 0
	for _, g := range gaps {
		switch g.Kind {
		case "path_unrelated_helper_limit", "helper_call_limit", "recursive_helper", "unknown_call_result":
		default:
			continue
		}
		set.allowed[g.At.File] = true
		m, err := set.load(g.At.File)
		if err != nil {
			continue
		}
		call := nodeAt(m.tree.RootNode(), g.At.StartByte, g.At.EndByte)
		if call == nil || call.Kind() != "call_expression" {
			continue
		}
		hm, helper := set.resolveCall(m, call)
		if helper == nil {
			continue // not an in-repository callee
		}
		reason := "unsupported_callee"
		where := ""
		if supportedCallee(helper) {
			sum := set.callableSummary(hm, helper)
			reason = sum.firstReason()
			if len(sum.reasons) > 0 {
				r := sum.reasons[0]
				where = fmt.Sprintf(" at %s:%d", r.At.File, r.At.StartLine)
			}
			if reason == "" {
				reason = "arguments_not_inert"
				closedLeft++
			}
		}
		name := call.ChildByFieldName("function").Utf8Text(m.src)
		counts[fmt.Sprintf("%s | %s | %s%s", g.Kind, name, reason, where)]++
	}
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if counts[keys[i]] != counts[keys[j]] {
			return counts[keys[i]] > counts[keys[j]]
		}
		return keys[i] < keys[j]
	})
	for _, k := range keys {
		t.Logf("%4d  %s", counts[k], k)
	}
	t.Logf("remaining on closed callees (arguments not inert): %d", closedLeft)
}
