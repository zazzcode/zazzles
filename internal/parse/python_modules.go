package parse

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	python "github.com/tree-sitter/tree-sitter-python/bindings/go"
	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/guidelines"
	"github.com/zazzcode/zazzles/internal/lang"
	"github.com/zazzcode/zazzles/internal/walk"
)

type pythonImport struct {
	module, name string
	node         *sitter.Node
}
type pythonModule struct {
	commentsReady bool
	comments      []sourceComment
	file          string
	src           []byte
	hash          string
	tree          *sitter.Tree
	imports       map[string]pythonImport
	vars, funcs   map[string]*sitter.Node
}
type pythonSet struct {
	root          string
	parser        *sitter.Parser
	modules       map[string]*pythonModule
	files         []string
	gaps          []analysis.Gap
	text          *moduleSet
	writes        map[string][]pythonWrite
	staticInvalid map[string]bool
	// tampered caches command-API shadowing and monkey-patch facts.
	tampered map[string]bool
	// dynamicMembers records setattr(module, name, value) registrations.
	dynamicMembers map[string]map[string]*pythonStaticValue
}

func newPythonSet(root string) (*pythonSet, error) {
	manifest, err := walk.Walk(root, walk.Options{})
	if err != nil {
		return nil, err
	}
	p, err := openParser(python.Language())
	if err != nil {
		return nil, err
	}
	s := &pythonSet{root: root, parser: p, modules: map[string]*pythonModule{}, writes: map[string][]pythonWrite{}, text: &moduleSet{root: root, textSources: map[string]analysis.Evidence{}}}
	for _, f := range manifest.Files {
		if f.Language == lang.Python {
			s.files = append(s.files, f.Path)
		}
	}
	for _, file := range s.files {
		src, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(file)))
		if err != nil {
			s.close()
			return nil, err
		}
		if len(src) > 2<<20 {
			s.gaps = append(s.gaps, analysis.Gap{Kind: "work_limit", Detail: "Python source exceeds 2 MiB", At: analysis.Span{File: file, StartLine: 1}})
			continue
		}
		tree := p.Parse(src, nil)
		if tree == nil {
			continue
		}
		m := &pythonModule{file: file, src: src, hash: fmt.Sprintf("%x", sha256.Sum256(src)), tree: tree, imports: map[string]pythonImport{}, vars: map[string]*sitter.Node{}, funcs: map[string]*sitter.Node{}}
		s.modules[file] = m
		if tree.RootNode().HasError() {
			s.gaps = append(s.gaps, analysis.Gap{Kind: "parse_error", Detail: "Python syntax errors; module omitted", At: spanOf(file, tree.RootNode())})
			continue
		}
		m.declarations(tree.RootNode(), true)
	}
	s.indexStaticMutations()
	return s, nil
}
func (s *pythonSet) close() {
	for _, m := range s.modules {
		m.tree.Close()
	}
	s.parser.Close()
}
func (m *pythonModule) evidence(kind string, n *sitter.Node) analysis.Evidence {
	if n == nil {
		return analysis.Evidence{Kind: kind, SHA256: m.hash, Span: analysis.Span{File: m.file}}
	}
	if !m.commentsReady {
		m.comments = sourceComments(m.tree.RootNode(), m.src, true)
		m.commentsReady = true
	}
	modelText := ""
	if kind != "file" {
		modelText = modelSource(m.src, n.StartByte(), n.EndByte(), m.comments)
	}
	return analysis.Evidence{ModelText: modelText, Kind: kind, Text: n.Utf8Text(m.src), Span: spanOf(m.file, n), SHA256: m.hash}
}
func pyWalk(n *sitter.Node, fn func(*sitter.Node)) {
	if n == nil {
		return
	}
	fn(n)
	for i := uint(0); i < n.NamedChildCount(); i++ {
		pyWalk(n.NamedChild(i), fn)
	}
}
func pyText(m *pythonModule, n *sitter.Node) string {
	if n == nil {
		return ""
	}
	return n.Utf8Text(m.src)
}
func pyField(n *sitter.Node, key string) *sitter.Node {
	if n == nil {
		return nil
	}
	return n.ChildByFieldName(key)
}
func pyArgs(n *sitter.Node) []*sitter.Node {
	a := pyField(n, "arguments")
	var out []*sitter.Node
	if a != nil {
		for i := uint(0); i < a.NamedChildCount(); i++ {
			c := a.NamedChild(i)
			if c.Kind() != "keyword_argument" {
				out = append(out, c)
			}
		}
	}
	return out
}
func pyKeywordIn(m *pythonModule, n *sitter.Node, key string) *sitter.Node {
	a := pyField(n, "arguments")
	if a != nil {
		for i := uint(0); i < a.NamedChildCount(); i++ {
			c := a.NamedChild(i)
			if c.Kind() == "keyword_argument" && pyText(m, c.ChildByFieldName("name")) == key {
				return c.ChildByFieldName("value")
			}
		}
	}
	return nil
}
func pyLiteral(m *pythonModule, n *sitter.Node) (string, bool) {
	if n == nil || n.Kind() != "string" {
		return "", false
	}
	for i := uint(0); i < n.NamedChildCount(); i++ {
		if n.NamedChild(i).Kind() == "interpolation" {
			return "", false
		}
	}
	text := pyText(m, n)
	pos := strings.IndexAny(text, "\"'")
	if pos < 0 {
		return "", false
	}
	prefix := strings.ToLower(text[:pos])
	if strings.Contains(prefix, "f") {
		return "", false
	}
	text = text[pos:]
	q := text[:1]
	if strings.HasPrefix(text, strings.Repeat(q, 3)) {
		q = strings.Repeat(q, 3)
	}
	if len(text) < 2*len(q) {
		return "", false
	}
	return text[len(q) : len(text)-len(q)], true
}
func (m *pythonModule) declarations(n *sitter.Node, top bool) {
	if n == nil {
		return
	}
	switch n.Kind() {
	case "import_statement", "import_from_statement":
		from := pyText(m, n.ChildByFieldName("module_name"))
		for i := uint(0); i < n.NamedChildCount(); i++ {
			c := n.NamedChild(i)
			if from != "" && c.Id() == n.ChildByFieldName("module_name").Id() {
				continue
			}
			if c.Kind() != "dotted_name" && c.Kind() != "aliased_import" {
				continue
			}
			name := pyText(m, c)
			alias := name
			if c.Kind() == "aliased_import" {
				name = pyText(m, c.ChildByFieldName("name"))
				alias = pyText(m, c.ChildByFieldName("alias"))
			}
			if from == "" {
				mod := name
				if c.Kind() != "aliased_import" {
					alias = strings.Split(name, ".")[0]
					mod = alias
				}
				m.imports[alias] = pythonImport{mod, "", n}
			} else {
				m.imports[alias] = pythonImport{from, name, n}
			}
		}
		return
	case "function_definition":
		if top {
			m.funcs[pyText(m, n.ChildByFieldName("name"))] = n
		}
		return
	case "assignment":
		if top {
			left := n.ChildByFieldName("left")
			if left != nil && left.Kind() == "identifier" {
				m.vars[pyText(m, left)] = n.ChildByFieldName("right")
			}
		}
		return
	case "class_definition":
		if top {
			m.vars[pyText(m, n.ChildByFieldName("name"))] = n
		}
		return
	}
	for i := uint(0); i < n.NamedChildCount(); i++ {
		m.declarations(n.NamedChild(i), top)
	}
}
func (s *pythonSet) importModule(m *pythonModule, module string) *pythonModule {
	base := ""
	if strings.HasPrefix(module, ".") {
		dots := len(module) - len(strings.TrimLeft(module, "."))
		base = filepath.Dir(m.file)
		for i := 1; i < dots; i++ {
			base = filepath.Dir(base)
		}
		module = strings.TrimLeft(module, ".")
	}
	path := filepath.ToSlash(filepath.Join(base, strings.ReplaceAll(module, ".", "/")))
	for _, p := range []string{path + ".py", path + "/__init__.py", "src/" + path + ".py", "src/" + path + "/__init__.py"} {
		if found := s.modules[p]; found != nil {
			return found
		}
	}
	return nil
}
func (s *pythonSet) resolve(m *pythonModule, name string, depth int) (*pythonModule, string) {
	if depth > 8 {
		return nil, ""
	}
	parts := strings.Split(name, ".")
	imp, ok := m.imports[parts[0]]
	if !ok {
		return m, name
	}
	if imp.name != "" {
		path := imp.module
		if !strings.HasSuffix(path, ".") {
			path += "."
		}
		path += imp.name
		if target := s.importModule(m, path); target != nil {
			return s.resolve(target, strings.Join(parts[1:], "."), depth+1)
		}
	}
	if target := s.importModule(m, imp.module); target != nil {
		rest := imp.name
		if len(parts) > 1 {
			if rest != "" {
				rest += "."
			}
			rest += strings.Join(parts[1:], ".")
		}
		return s.resolve(target, rest, depth+1)
	}
	return m, name
}
func (s *pythonSet) qualified(m *pythonModule, name string) string {
	target, key := s.resolve(m, name, 0)
	if target == nil {
		return ""
	}
	parts := strings.Split(key, ".")
	if target.funcs[parts[0]] != nil || target.vars[parts[0]] != nil {
		return ""
	}
	if imp, ok := target.imports[parts[0]]; ok {
		q := imp.module
		if imp.name != "" {
			q += "." + imp.name
		}
		if len(parts) > 1 {
			q += "." + strings.Join(parts[1:], ".")
		}
		return q
	}
	return ""
}
func (s *pythonSet) report(entry string, checks []analysis.Check) (*analysis.AnalysisReport, error) {
	if entry != "" && s.modules[entry] == nil {
		return nil, fmt.Errorf("entry must be a selected JS/TS/Python file relative to target root: %s", entry)
	}
	routes := s.routeEntries()
	dynamic := s.dynamicRouteEntries()
	routes = append(routes, dynamic...)
	resolvedSites := map[string]bool{}
	for _, r := range dynamic {
		resolvedSites[fmt.Sprintf("%s:%d", r.route.Registration.File, r.route.Registration.StartByte)] = true
	}
	gaps := s.gaps[:0]
	for _, g := range s.gaps {
		if (g.Kind == "dynamic_path" || g.Kind == "python_registration_unresolved") && resolvedSites[fmt.Sprintf("%s:%d", g.At.File, g.At.StartByte)] {
			continue
		}
		gaps = append(gaps, g)
	}
	s.gaps = gaps
	out := &analysis.AnalysisReport{SchemaVersion: analysis.ReportSchemaVersion, Root: s.root, Entries: []analysis.EntryPoint{}, Uses: []analysis.CandidateUse{}, Gaps: append([]analysis.Gap{}, s.gaps...), Files: []analysis.Evidence{}, Limitations: []string{
		"Python supports static Flask/Blueprint, RESTX Resource and FastAPI routes plus bounded source-derived Flask/FastAPI generation; runtime registry mutation, unsupported decorators and response overrides remain gaps",
		"Python helper expansion is bounded to depth 3 and 24 calls per route; loops, comprehensions, mutation, exceptions and external dispatch are conservative",
		"Jinja output requires a verified Flask template binding; unresolved configuration, includes/macros and stored origins remain Review; no runtime execution or SCA",
	}}
	for _, r := range routes {
		if entry == "" || r.module.file == entry {
			s.analyze(out, r)
		}
	}
	if err := s.browserTemplates(out); err != nil {
		return nil, err
	}
	s.linkStorage(out)
	assembleXSSClaims(out)
	if len(checks) > 0 {
		s.attachChecks(out, checks)
	}
	for _, file := range s.files {
		if m := s.modules[file]; m != nil {
			e := m.evidence("file", m.tree.RootNode())
			e.Text = ""
			out.Files = append(out.Files, e)
		}
	}
	keys := []string{}
	for k := range s.text.textSources {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		e := s.text.textSources[k]
		e.Kind = "file"
		e.Text = ""
		out.Files = append(out.Files, e)
	}
	for _, r := range guidelines.ForPaths(s.files) {
		out.AnalysisGuidelines = append(out.AnalysisGuidelines, analysis.GuidelinesRef{ID: r.ID, Version: r.Version, Languages: r.Languages})
	}
	if err := finalizeEntries(out); err != nil {
		return nil, err
	}
	return out, nil
}
