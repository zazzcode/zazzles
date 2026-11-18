package langjs

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	sitter "github.com/tree-sitter/go-tree-sitter"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/lang"
	"github.com/zazzcode/zazzles/internal/parse"
	"github.com/zazzcode/zazzles/internal/walk"
)

// TestCallResolutionMeasure is the step 1C measurement (source index spec §8).
// It classifies every call site of a target with the analyzers' own module sets
// and resolvers, and attributes each call-site gap on the report to those
// classes. It never changes analysis output. Set ZAZZLES_MEASURE_ROOT to a target
// and optionally ZAZZLES_MEASURE_OUT to a JSON output path. Python and PHP call
// sites are measured by internal/langpy's TestPythonCallResolutionMeasure and
// internal/langphp's TestPHPCallResolutionMeasure.
func TestCallResolutionMeasure(t *testing.T) {
	root := os.Getenv("ZAZZLES_MEASURE_ROOT")
	if root == "" {
		t.Skip("set ZAZZLES_MEASURE_ROOT to a target checkout")
	}
	report, err := AnalyzeWithOptions(root, "", nil, parse.Options{})
	if err != nil {
		t.Fatal(err)
	}
	c, err := newCallClassifier(root)
	if err != nil {
		t.Fatal(err)
	}
	defer c.close()
	out := callMeasurement{Sites: map[string]map[string]int{}, Gaps: map[string]map[string]int{}, Index: c.jsIndex()}
	for _, site := range c.sites() {
		bump(out.Sites, site.language, site.class)
	}
	var gaps []analysis.Gap
	for _, u := range report.Uses {
		gaps = append(gaps, u.Gaps...)
	}
	for _, e := range report.Entries {
		gaps = append(gaps, e.Gaps...)
	}
	for _, g := range gaps {
		if class, ok := c.classifyAt(g.At); ok {
			bump(out.Gaps, g.Kind, class)
		}
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if path := os.Getenv("ZAZZLES_MEASURE_OUT"); path != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Log(string(data))
}

type callMeasurement struct {
	// Sites counts call sites per language and class.
	Sites map[string]map[string]int `json:"call_sites"`
	// Gaps counts report gaps whose span is a call site, per gap kind and class.
	Gaps map[string]map[string]int `json:"call_site_gaps"`
	// Index counts JS/TS call sites by production call-index kind and receiver or reason.
	Index map[string]int `json:"js_call_index"`
}

func bump(m map[string]map[string]int, a, b string) {
	if m[a] == nil {
		m[a] = map[string]int{}
	}
	m[a][b]++
}

type callSite struct{ language, class string }

type callClassifier struct {
	js *moduleSet
}

func newCallClassifier(root string) (*callClassifier, error) {
	files, err := walk.Walk(root, walk.Options{})
	if err != nil {
		return nil, err
	}
	ps, err := newParsers()
	if err != nil {
		return nil, err
	}
	js := &moduleSet{root: root, parsers: ps, modules: map[string]*sourceModule{}, allowed: map[string]bool{}}
	for _, f := range files.Files {
		if f.Language == lang.JavaScript || f.Language == lang.TypeScript {
			js.allowed[f.Path] = true
		}
	}
	for _, f := range files.Files {
		if js.allowed[f.Path] {
			if _, err := js.load(f.Path); err != nil {
				continue // the analyzer records unreadable or oversized files itself
			}
		}
	}
	return &callClassifier{js: js}, nil
}

func (c *callClassifier) close() { c.js.close() }

func (c *callClassifier) sites() []callSite {
	var out []callSite
	keys := make([]string, 0, len(c.js.modules))
	for k := range c.js.modules {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		m := c.js.modules[k]
		walkKinds(m.tree.RootNode(), jsCallKinds, func(n *sitter.Node) {
			out = append(out, callSite{"javascript", c.classifyJS(m, n)})
		})
	}
	return out
}

var (
	jsCallKinds = map[string]bool{"call_expression": true}
	jsGlobals   = map[string]bool{"console": true, "JSON": true, "Math": true, "Object": true, "Array": true, "Promise": true, "String": true, "Number": true, "Boolean": true, "Date": true, "RegExp": true, "Error": true, "Symbol": true, "Reflect": true, "process": true, "require": true, "Buffer": true, "setTimeout": true, "setInterval": true, "clearTimeout": true, "parseInt": true, "parseFloat": true, "isNaN": true, "encodeURIComponent": true, "decodeURIComponent": true, "encodeURI": true, "decodeURI": true, "escape": true, "unescape": true, "window": true, "document": true, "fetch": true, "alert": true, "localStorage": true, "sessionStorage": true, "describe": true, "it": true, "expect": true, "beforeEach": true, "afterEach": true}
)

func walkKinds(n *sitter.Node, kinds map[string]bool, fn func(*sitter.Node)) {
	cursor := n.Walk()
	defer cursor.Close()
	for {
		node := cursor.Node()
		if kinds[node.Kind()] {
			fn(node)
		}
		if cursor.GotoFirstChild() {
			continue
		}
		for !cursor.GotoNextSibling() {
			if !cursor.GotoParent() {
				return
			}
		}
	}
}

// classifyAt finds the call node whose span is exactly the gap span.
func (c *callClassifier) classifyAt(at analysis.Span) (string, bool) {
	language, ok := lang.Detect(at.File)
	if !ok || at.EndByte <= at.StartByte {
		return "", false
	}
	switch language {
	case lang.JavaScript, lang.TypeScript:
		m := c.js.modules[at.File]
		if m == nil {
			return "", false
		}
		if n := exactNode(m.tree, at, jsCallKinds); n != nil {
			return c.classifyJS(m, n), true
		}
	}
	return "", false
}

func exactNode(tree *sitter.Tree, at analysis.Span, kinds map[string]bool) *sitter.Node {
	n := tree.RootNode().NamedDescendantForByteRange(uint(at.StartByte), uint(at.EndByte))
	for ; n != nil && n.StartByte() == uint(at.StartByte) && n.EndByte() == uint(at.EndByte); n = n.Parent() {
		if kinds[n.Kind()] {
			return n
		}
	}
	return nil
}

func calleeRoot(text string) string {
	return strings.FieldsFunc(text, func(r rune) bool { return r == '.' || r == '?' })[0]
}

func (c *callClassifier) classifyJS(m *sourceModule, call *sitter.Node) string {
	if _, def := c.js.resolveCall(m, call); def != nil {
		return "in_repo"
	}
	fn := call.ChildByFieldName("function")
	if fn == nil || (fn.Kind() != "identifier" && fn.Kind() != "member_expression") {
		return "dynamic"
	}
	root := fn
	for root.Kind() == "member_expression" {
		root = root.ChildByFieldName("object")
		if root == nil {
			return "dynamic"
		}
	}
	if root.Kind() != "identifier" && root.Kind() != "this" {
		return "dynamic"
	}
	name := root.Utf8Text(m.src)
	if imp, ok := m.imports[name]; ok {
		if c.js.importModule(m, imp.module) != nil {
			return "in_repo_member_unresolved"
		}
		return "package"
	}
	if fn.Kind() == "identifier" {
		if m.funcs[name] != nil {
			return "in_repo_member_unresolved"
		}
		if jsGlobals[name] {
			return "builtin"
		}
		return "local_value"
	}
	if jsGlobals[name] {
		return "builtin"
	}
	return "member_on_value"
}

// jsIndex counts every JS/TS call site by the production call index (step 1D).
func (c *callClassifier) jsIndex() map[string]int {
	out := map[string]int{}
	for _, m := range c.js.modules {
		walkKinds(m.tree.RootNode(), jsCallKinds, func(n *sitter.Node) {
			r := c.js.callResolution(m, n)
			out[r.Kind.String()+":"+r.Receiver+r.Reason]++
		})
	}
	return out
}
