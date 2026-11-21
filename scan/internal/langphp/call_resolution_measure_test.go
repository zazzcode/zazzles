package langphp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sitter "github.com/tree-sitter/go-tree-sitter"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/lang"
)

// TestPHPCallResolutionMeasure is the PHP part of the step 1C measurement
// (source index spec §8); internal/parse's TestCallResolutionMeasure covers
// JS/TS and Python. It classifies every PHP call site with the analyzer's own
// module set and attributes each call-site gap on the report to those classes.
// It never changes analysis output. Set ZAZZLES_MEASURE_ROOT to a target and
// optionally ZAZZLES_MEASURE_PHP_OUT to a JSON output path.
func TestPHPCallResolutionMeasure(t *testing.T) {
	root := os.Getenv("ZAZZLES_MEASURE_ROOT")
	if root == "" {
		t.Skip("set ZAZZLES_MEASURE_ROOT to a target checkout")
	}
	report, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	set, err := newPHPSet(root)
	if err != nil {
		t.Fatal(err)
	}
	defer set.close()
	c := &phpCallClassifier{php: set}
	sites := map[string]int{}
	for _, file := range set.files {
		if m := set.modules[file]; m != nil {
			phpWalk(m.tree.RootNode(), func(n *sitter.Node) {
				if phpCallKinds[n.Kind()] {
					sites[c.classifyPHP(m, n)]++
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
	data, err := json.MarshalIndent(map[string]any{"call_sites": map[string]map[string]int{"php": sites}, "call_site_gaps": gapClasses}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if path := os.Getenv("ZAZZLES_MEASURE_PHP_OUT"); path != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Log(string(data))
}

var phpCallKinds = map[string]bool{"function_call_expression": true, "member_call_expression": true, "nullsafe_member_call_expression": true, "scoped_call_expression": true}

type phpCallClassifier struct{ php *phpSet }

// classifyAt finds the PHP call node whose span is exactly the gap span.
func (c *phpCallClassifier) classifyAt(at analysis.Span) (string, bool) {
	language, ok := lang.Detect(at.File)
	if !ok || language != lang.PHP || at.EndByte <= at.StartByte {
		return "", false
	}
	m := c.php.modules[at.File]
	if m == nil {
		return "", false
	}
	n := m.tree.RootNode().NamedDescendantForByteRange(uint(at.StartByte), uint(at.EndByte))
	for ; n != nil && n.StartByte() == uint(at.StartByte) && n.EndByte() == uint(at.EndByte); n = n.Parent() {
		if phpCallKinds[n.Kind()] {
			return c.classifyPHP(m, n), true
		}
	}
	return "", false
}

func (c *phpCallClassifier) classifyPHP(m *phpModule, call *sitter.Node) string {
	switch call.Kind() {
	case "function_call_expression":
		fn := call.ChildByFieldName("function")
		if fn == nil || fn.Kind() != "name" && fn.Kind() != "qualified_name" {
			return "dynamic"
		}
		name := strings.TrimPrefix(string(m.src[fn.StartByte():fn.EndByte()]), "\\")
		if m.funcs[name] != nil || c.uniquePHPFunction(name) {
			return "in_repo"
		}
		return "builtin"
	case "scoped_call_expression":
		scope := call.ChildByFieldName("scope")
		if scope == nil {
			return "dynamic"
		}
		name := strings.TrimPrefix(string(m.src[scope.StartByte():scope.EndByte()]), "\\")
		for _, file := range c.php.files {
			if mod := c.php.modules[file]; mod != nil && mod.classes[name] != nil {
				return "in_repo_member_unresolved"
			}
		}
		if name == "self" || name == "static" || name == "parent" {
			return "in_repo_member_unresolved"
		}
		return "package"
	}
	return "member_on_value"
}

func (c *phpCallClassifier) uniquePHPFunction(name string) bool {
	found := 0
	for _, file := range c.php.files {
		if mod := c.php.modules[file]; mod != nil && mod.funcs[name] != nil {
			found++
		}
	}
	return found == 1
}
