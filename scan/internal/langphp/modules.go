// Package langphp is the PHP language adapter. It analyzes server-mapped PHP
// files through bounded value, control and include flow, and builds on the
// language core API exported by internal/parse (core_api.go); it never reaches
// into JS/TS flow internals. Run produces the PHP report and Routes the PHP
// part of the route inventory. Only internal/pipeline calls them.
package langphp

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	php "github.com/tree-sitter/tree-sitter-php/bindings/go"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/guidelines"
	"github.com/zazzcode/zazzles/scan/internal/lang"
	"github.com/zazzcode/zazzles/scan/internal/parse"
)

// phpModule is one parsed PHP file. Plain PHP has no router: every file is a
// potential HTTP entry, and files compose through include/require.
type phpModule struct {
	commentsReady bool
	// inlineHTML holds the byte spans of inline HTML (text) regions in
	// source order, indexed lazily for output-context classification.
	inlineHTMLReady bool
	inlineHTML      [][2]uint
	comments        []parse.SourceComment
	file            string
	src             []byte
	hash            string
	tree            *sitter.Tree
	funcs           map[string]*sitter.Node
	classes         map[string]*sitter.Node
	// constants maps define(name, literal) declarations in this file.
	constants map[string]string
}

// phpSet owns the parsed PHP modules of one scan root.
type phpSet struct {
	witnessPrograms map[string]*phpWitnessProgram
	resolutions     map[string]phpCallResolution
	project         *phpProjectInputs
	composers       map[string]*symfonyProject
	symfony         []*symfonyProject
	builtinEffects  map[string]bool
	sqlHazard       *bool
	summaries       map[string]*parse.ClosedCallable
	root            string
	parser          *sitter.Parser
	modules         map[string]*phpModule
	files           []string
	gaps            []analysis.Gap
	// inputs indexes acquisition per invocation context, never by span alone.
	inputs map[string]map[analysis.Evidence]phpInputSource
	// writes links SQL storage keys to their writing values (stored XSS).
	writes map[string][]phpWrite
	// sessionWrites links php-session:<key> containers to writing values.
	sessionWrites map[string][]phpWrite
	// storedOnly lists, per SQL use ID, the storage keys of a claim whose only
	// content is stored; session writers from later entries resolve it.
	storedOnly map[string][]string
	// classes indexes class-like declarations by fully qualified name (W3).
	classes *phpClassIndex
	// objects numbers created objects.
	objects int
	// functions indexes function declarations and `use function` imports.
	functions *phpFunctionBindings
	// magicClasses caches the deserialization magic-method class evidence.
	magicClasses      []analysis.Evidence
	magicClassesReady bool
	twig              twigInventory
	doctrine          doctrineStorage
	responses         map[int]symfonyResponseState
	// securityConfig and census cache the security.yaml reader and the
	// security-field census per Symfony project.
	securityConfig map[*symfonyProject]*symfonySecurity
	census         map[*symfonyProject]*phpSecurityCensus
	// authzChanges collects stored writes while entries are walked.
	authzChanges []authzChange
	// account is the account adapter's state.
	account *phpAccountState
	// configFiles and deployFiles are the allow-listed framework and
	// deployment files. unreadFiles are allow-listed paths the walk did not
	// open, and truncatedLists names a list that passed its file limit.
	configFiles, deployFiles, unreadFiles, truncatedLists []string
	// textFiles, deployViews, sourceSettings and trustCache hold what the
	// configuration checks read, so each file is read and parsed once.
	textFiles      map[string]textFile
	deployViews    map[string]*deployView
	sourceSettings map[string]*phpSourceSettings
	trustCache     map[string]*addressTrustFacts
}

type phpWrite struct {
	value    phpValue
	entry    string
	evidence analysis.Evidence
}

// Run analyzes the inventory's PHP files. A full scan of an inventory with
// no PHP files returns nil, nil and opens no grammar; a PHP entry always runs
// so that an unselected entry keeps its error.
func Run(inv parse.Inventory, entry string, checks []analysis.Check) (*analysis.AnalysisReport, error) {
	if entry == "" && !inv.HasLanguage(lang.PHP) {
		return nil, nil
	}
	ph, err := openPHPSet(inv)
	if err != nil {
		return nil, err
	}
	defer ph.close()
	return ph.report(entry, checks)
}

func openPHPSet(inv parse.Inventory) (*phpSet, error) {
	root := inv.Root
	p, err := parse.OpenParser(php.LanguagePHP())
	if err != nil {
		return nil, err
	}
	s := &phpSet{root: root, parser: p, modules: map[string]*phpModule{}, writes: map[string][]phpWrite{}, sessionWrites: map[string][]phpWrite{}, storedOnly: map[string][]string{}}
	s.configFiles = append([]string{}, inv.Config...)
	s.deployFiles = append([]string{}, inv.Deploy...)
	s.unreadFiles = append([]string{}, inv.Unread...)
	s.truncatedLists = append([]string{}, inv.Truncated...)
	s.loadSymfonyProjects(inv.Config)
	s.twig = newTwigInventory(inv.Templates, root)
	s.doctrine = newDoctrineStorage()
	s.responses = map[int]symfonyResponseState{}
	for _, f := range inv.Files {
		if f.Language == lang.PHP && !s.symfonyCacheFile(f.Path) {
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
			s.gaps = append(s.gaps, analysis.Gap{Kind: "work_limit", Detail: "PHP source exceeds 2 MiB", At: analysis.Span{File: file, StartLine: 1}})
			continue
		}
		tree := p.Parse(src, nil)
		if tree == nil {
			continue
		}
		m := &phpModule{file: file, src: src, hash: fmt.Sprintf("%x", sha256.Sum256(src)), tree: tree, funcs: map[string]*sitter.Node{}, classes: map[string]*sitter.Node{}, constants: map[string]string{}}
		s.modules[file] = m
		if tree.RootNode().HasError() {
			// The module is still walked error-tolerantly (PHP executes the
			// valid code regions of a mostly inline-HTML file), but its
			// declarations are not indexed and its results may be partial.
			s.gaps = append(s.gaps, analysis.Gap{Kind: "parse_error", Detail: "PHP syntax errors; module analyzed error-tolerantly and may be incomplete", At: parse.Span(file, tree.RootNode())})
			continue
		}
		m.declarations(tree.RootNode())
	}
	return s, nil
}

func (s *phpSet) close() {
	for _, m := range s.modules {
		m.tree.Close()
	}
	s.parser.Close()
}

func (m *phpModule) evidence(kind string, n *sitter.Node) analysis.Evidence {
	if n == nil {
		return analysis.Evidence{Kind: kind, SHA256: m.hash, Span: analysis.Span{File: m.file}}
	}
	if !m.commentsReady {
		m.comments = parse.SourceComments(m.tree.RootNode(), m.src, false)
		m.commentsReady = true
	}
	modelText := ""
	if kind != "file" {
		modelText = parse.ModelSource(m.src, n.StartByte(), n.EndByte(), m.comments)
	}
	return analysis.Evidence{ModelText: modelText, Kind: kind, Text: n.Utf8Text(m.src), Span: parse.Span(m.file, n), SHA256: m.hash}
}

// inlineHTMLBefore returns the inline HTML that precedes byte pos in this
// module, which decides the output context of an echo embedded in a page
// (`value="<?php echo $x ?>"` is an attribute, not HTML text).
func (m *phpModule) inlineHTMLBefore(pos uint) string {
	if !m.inlineHTMLReady {
		m.inlineHTMLReady = true
		phpWalk(m.tree.RootNode(), func(n *sitter.Node) {
			if n.Kind() == "text" {
				m.inlineHTML = append(m.inlineHTML, [2]uint{n.StartByte(), n.EndByte()})
			}
		})
	}
	var b strings.Builder
	for _, span := range m.inlineHTML {
		if span[1] > pos {
			break
		}
		b.Write(m.src[span[0]:span[1]])
	}
	return b.String()
}

// phpShortEcho reports an expression statement opened by the `<?=` short
// echo tag, which outputs its expression exactly like echo.
func phpShortEcho(m *phpModule, stmt *sitter.Node) bool {
	prev := stmt.PrevSibling()
	if prev != nil && prev.Kind() == "text_interpolation" && prev.ChildCount() > 0 {
		prev = prev.Child(prev.ChildCount() - 1)
	}
	return prev != nil && prev.Kind() == "php_tag" && strings.TrimSpace(phpText(m, prev)) == "<?="
}

func phpWalk(n *sitter.Node, fn func(*sitter.Node)) {
	if n == nil {
		return
	}
	fn(n)
	for i := uint(0); i < n.ChildCount(); i++ {
		if c := n.Child(i); c != nil && c.IsNamed() {
			phpWalk(c, fn)
		}
	}
}

func phpText(m *phpModule, n *sitter.Node) string {
	if n == nil {
		return ""
	}
	return n.Utf8Text(m.src)
}

func phpField(n *sitter.Node, key string) *sitter.Node {
	if n == nil {
		return nil
	}
	return n.ChildByFieldName(key)
}

// phpVarName returns the bare variable name of a variable_name node
// ("$id" → "id"). The grammar attaches no field to the inner name token.
func phpVarName(m *phpModule, n *sitter.Node) string {
	if n == nil || n.Kind() != "variable_name" {
		return ""
	}
	return strings.TrimPrefix(phpText(m, n), "$")
}

// phpArgs flattens a call's arguments, unwrapping argument nodes.
func phpArgs(n *sitter.Node) []*sitter.Node {
	a := phpField(n, "arguments")
	var out []*sitter.Node
	if a != nil {
		for i := uint(0); i < a.NamedChildCount(); i++ {
			c := a.NamedChild(i)
			if c.Kind() == "argument" {
				if v := c.NamedChild(0); v != nil {
					out = append(out, v)
					continue
				}
			}
			out = append(out, c)
		}
	}
	return out
}

// phpStringLiteral unquotes a plain string node (no interpolation). Both
// single-quoted strings and double-quoted encapsed strings without
// interpolation carry literal text.
func phpStringLiteral(m *phpModule, n *sitter.Node) (string, bool) {
	if n == nil {
		return "", false
	}
	if n.Kind() == "encapsed_string" {
		var out []byte
		for i := uint(0); i < n.ChildCount(); i++ {
			c := n.Child(i)
			if c == nil {
				continue
			}
			if c.Kind() == "string_content" {
				out = append(out, c.Utf8Text(m.src)...)
				continue
			}
			if c.IsNamed() {
				return "", false // interpolation
			}
		}
		return string(out), true
	}
	if n.Kind() != "string" {
		return "", false
	}
	text := phpText(m, n)
	if len(text) < 2 {
		return "", false
	}
	q := text[:1]
	if q != "'" && q != "\"" {
		return "", false
	}
	return text[1 : len(text)-1], true
}

// declarations indexes top-level functions, classes and define() constants.
func (m *phpModule) declarations(n *sitter.Node) {
	if n == nil {
		return
	}
	for i := uint(0); i < n.NamedChildCount(); i++ {
		c := n.NamedChild(i)
		switch c.Kind() {
		case "function_definition":
			m.funcs[phpText(m, phpField(c, "name"))] = c
		case "class_declaration":
			m.classes[phpText(m, phpField(c, "name"))] = c
		case "expression_statement":
			call := firstChildOfKind(c, "function_call_expression")
			if call == nil || phpText(m, phpField(call, "function")) != "define" {
				continue
			}
			args := phpArgs(call)
			if len(args) != 2 {
				continue
			}
			name, ok := phpStringLiteral(m, args[0])
			if !ok {
				continue
			}
			if value, ok := phpStringLiteral(m, args[1]); ok {
				m.constants[name] = value
			}
		}
	}
}

func firstChildOfKind(n *sitter.Node, kind string) *sitter.Node {
	if n == nil {
		return nil
	}
	for i := uint(0); i < n.ChildCount(); i++ {
		if c := n.Child(i); c != nil && c.Kind() == kind {
			return c
		}
	}
	return nil
}

// constant resolves a bare identifier to a define() literal. PHP constants are
// global; the declaring module is searched first, then all modules in order.
func (s *phpSet) constant(m *phpModule, name string) (string, bool) {
	if v, ok := m.constants[name]; ok {
		return v, true
	}
	files := append([]string{}, s.files...)
	sort.Strings(files)
	for _, file := range files {
		if other := s.modules[file]; other != nil {
			if v, ok := other.constants[name]; ok {
				return v, true
			}
		}
	}
	return "", false
}

func (s *phpSet) report(entry string, checks []analysis.Check) (*analysis.AnalysisReport, error) {
	if entry != "" && s.modules[entry] == nil {
		return nil, fmt.Errorf("entry must be a selected JS/TS/Python/PHP file relative to target root: %s", entry)
	}
	out := &analysis.AnalysisReport{SchemaVersion: analysis.ReportSchemaVersion, Root: s.root, Entries: []analysis.EntryPoint{}, Uses: []analysis.CandidateUse{}, Gaps: append([]analysis.Gap{}, s.gaps...), Files: []analysis.Evidence{}, Limitations: []string{
		"PHP supports server-mapped file entries with literal and finite-alternative include composition; unresolvable dynamic includes, loops, mutation and whole-program class hierarchies remain gaps",
		fmt.Sprintf("PHP helper expansion is bounded to depth %d and %d calls per entry; framework adapters and template engines are not modeled", phpHelperDepthLimit, phpHelperWorkLimit),
		"PHP SQL text, command strings, output rendering and file operands are candidate findings, not confirmed vulnerabilities",
	}}
	before := len(s.gaps)
	if len(s.symfony) > 0 {
		out.Limitations = append(out.Limitations, "Symfony route discovery covers source-backed attributes, annotations and YAML registrations")
		for _, project := range s.symfony {
			for _, route := range project.routes(s) {
				if entry != "" && route.sourceFile() != entry {
					continue
				}
				for _, method := range route.httpMethods() {
					s.analyzeSymfonyEntry(out, project, route, method)
				}
			}
		}
	}
	for _, file := range s.files {
		m := s.modules[file]
		if m == nil {
			continue
		}
		if !s.fileMapped(file) || entry != "" && file != entry {
			continue
		}
		s.analyzeEntry(out, m)
	}
	// Class-resolution gaps found while walking entries are report coverage.
	out.Gaps = append(out.Gaps, s.gaps[before:]...)
	s.finalizeSymfonyResponses(out)
	s.linkDoctrineStorage(out)
	s.linkStorage(out)
	s.linkStoredOnlySessions(out)
	parse.AssembleXSSClaims(out)
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
	for _, file := range s.twig.text.Files() {
		e, _ := s.twig.text.Get(file)
		e.Kind, e.Text = "file", ""
		out.Files = append(out.Files, e)
	}
	for _, r := range guidelines.ForPaths(s.files) {
		out.AnalysisGuidelines = append(out.AnalysisGuidelines, analysis.GuidelinesRef{ID: r.ID, Version: r.Version, Languages: r.Languages})
	}
	s.assemblePHPInputs(out)
	s.finishAuthorization(out)
	s.finishAccount(out)
	s.finishConfiguration(out)
	if err := parse.FinalizeEntries(out); err != nil {
		return nil, err
	}
	s.linkServerSideRequests(out)
	return out, nil
}

// constant resolves a bare identifier: magic __DIR__/__FILE__, then a
// define() executed in this flow, then a top-level define() of the current
// module, then the first module (by path) that defines it.
func (f *phpFlow) constant(name string) (string, bool) {
	switch name {
	case "__DIR__":
		return "/" + path.Dir(f.module.file), true
	case "__FILE__":
		return "/" + f.module.file, true
	}
	if v, ok := f.constants[name]; ok {
		return v, true
	}
	return f.set.constant(f.module, name)
}

// defineConstant records define(name, literal); the first definition wins.
func (f *phpFlow) defineConstant(name, value string) {
	if f.constants == nil {
		f.constants = map[string]string{}
	}
	if _, ok := f.constants[name]; !ok {
		f.constants[name] = value
	}
}

// adoptConstants carries definitions made in a branch or helper back to f.
func (f *phpFlow) adoptConstants(defined map[string]string) {
	for _, name := range sortedStrings(defined) {
		f.defineConstant(name, defined[name])
	}
}

func sortedStrings(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
