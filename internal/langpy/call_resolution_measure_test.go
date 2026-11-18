package langpy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sitter "github.com/tree-sitter/go-tree-sitter"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/lang"
)

// TestPythonCallResolutionMeasure is the Python part of the step 1C measurement
// (source index spec §8); internal/parse's TestCallResolutionMeasure covers
// JS/TS and internal/langphp's TestPHPCallResolutionMeasure covers PHP. It
// classifies every Python call site with the analyzer's own module set and
// attributes each call-site gap on the report to those classes. It never
// changes analysis output. Set ZAZZLES_MEASURE_ROOT to a target and optionally
// ZAZZLES_MEASURE_PY_OUT to a JSON output path.
func TestPythonCallResolutionMeasure(t *testing.T) {
	root := os.Getenv("ZAZZLES_MEASURE_ROOT")
	if root == "" {
		t.Skip("set ZAZZLES_MEASURE_ROOT to a target checkout")
	}
	report, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	set, err := newPythonSet(root)
	if err != nil {
		t.Fatal(err)
	}
	defer set.close()
	c := &pyCallClassifier{py: set}
	sites := map[string]int{}
	for _, file := range set.files {
		if m := set.modules[file]; m != nil {
			pyWalk(m.tree.RootNode(), func(n *sitter.Node) {
				if pyCallKinds[n.Kind()] {
					sites[c.classifyPython(m, n)]++
				}
			})
		}
	}
	gapClasses := map[string]map[string]int{}
	var gaps []analysis.Gap
	for _, u := range report.Uses {
		gaps = append(gaps, u.Gaps...)
	}
	for _, e := range report.Entries {
		gaps = append(gaps, e.Gaps...)
	}
	for _, g := range gaps {
		if class, ok := c.classifyAt(g.At); ok {
			if gapClasses[g.Kind] == nil {
				gapClasses[g.Kind] = map[string]int{}
			}
			gapClasses[g.Kind][class]++
		}
	}
	data, err := json.MarshalIndent(map[string]any{"call_sites": map[string]map[string]int{"python": sites}, "call_site_gaps": gapClasses}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if path := os.Getenv("ZAZZLES_MEASURE_PY_OUT"); path != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Log(string(data))
}

var pyCallKinds = map[string]bool{"call": true}

type pyCallClassifier struct{ py *pythonSet }

// classifyAt finds the Python call node whose span is exactly the gap span.
func (c *pyCallClassifier) classifyAt(at analysis.Span) (string, bool) {
	language, ok := lang.Detect(at.File)
	if !ok || language != lang.Python || at.EndByte <= at.StartByte {
		return "", false
	}
	m := c.py.modules[at.File]
	if m == nil {
		return "", false
	}
	n := m.tree.RootNode().NamedDescendantForByteRange(uint(at.StartByte), uint(at.EndByte))
	for ; n != nil && n.StartByte() == uint(at.StartByte) && n.EndByte() == uint(at.EndByte); n = n.Parent() {
		if pyCallKinds[n.Kind()] {
			return c.classifyPython(m, n), true
		}
	}
	return "", false
}

func calleeRoot(text string) string {
	return strings.FieldsFunc(text, func(r rune) bool { return r == '.' || r == '?' })[0]
}

func (c *pyCallClassifier) classifyPython(m *pythonModule, call *sitter.Node) string {
	fn := call.ChildByFieldName("function")
	if fn == nil || (fn.Kind() != "identifier" && fn.Kind() != "attribute") {
		return "dynamic"
	}
	name := pyText(m, fn)
	root := calleeRoot(name)
	target, key := c.py.resolve(m, name, 0)
	if target == nil {
		return "dynamic"
	}
	parts := strings.Split(key, ".")
	if target != m { // resolved through an import of an in-repository module
		if len(parts) == 1 && target.funcs[parts[0]] != nil {
			return "in_repo"
		}
		return "in_repo_member_unresolved"
	}
	if _, imported := m.imports[root]; imported {
		return "package"
	}
	if len(parts) == 1 && m.funcs[parts[0]] != nil {
		return "in_repo"
	}
	if m.funcs[root] != nil || m.vars[root] != nil {
		return "member_on_value"
	}
	if fn.Kind() == "identifier" {
		return "builtin_or_local"
	}
	return "member_on_value"
}
