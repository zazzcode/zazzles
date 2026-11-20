package langjs

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/parse"
)

type importBinding struct {
	module, name string
	declaration  *sitter.Node
}
type sourceModule struct {
	shadowQueries        map[shadowQuery]bool
	interpreterMutations map[string]bool
	// recovered names the byte-preserving grammar workarounds that parsed this module.
	recovered []string
	// awaitedCalls are generic calls whose `await` was blanked for parsing.
	awaitedCalls map[uint]bool
	// commandNames holds CommonJS destructured child_process members. They are
	// kept apart from imports so no other analyzer's module resolution changes.
	commandNames map[string]importBinding
	// fsNames holds CommonJS destructured Node fs members, kept apart from imports
	// for the same reason.
	fsNames        map[string]importBinding
	commentsReady  bool
	comments       []parse.SourceComment
	browserGlobals map[string]analysis.Evidence
	file           string
	src            []byte
	hash           string
	tree           *sitter.Tree
	funcs          map[string]*sitter.Node
	exports        map[string]*sitter.Node
	imports        map[string]importBinding
	express        map[string]bool
	receivers      map[string]bool
	// bindings is the lazily built write index; see binding_index.go.
	bindings *bindingIndex
	// calls caches call-site resolutions by node; see call_index.go.
	calls map[uintptr]callResolution
	// refsUnstable names module bindings with a use that is not a plain read;
	// see callable_summary.go.
	refsUnstable map[string]bool
}

type moduleSet struct {
	pollutionWrites map[uintptr][]pollutionWrite
	witnessPlans    map[string]*jsWitnessPlan
	prismaSchemas   map[string]map[string]map[string]string
	browserStates   map[string]*browserEvents
	tsConfigs       map[string]*tsConfig
	next            *nextState
	nextConfigs     map[string]*nextConfigFacts
	nextMiddlewares map[string]*nextMiddleware
	nodeHTTP        map[string]*nodeHTTPContext
	graphqlRecords  int
	grpcRecords     int
	grpcProtos      map[string]grpcProtoResult
	storageWrites   map[string][]storageWrite
	tableModels     map[string]string
	restResources   []restResource
	signedTokens    []signedToken
	angularUnits    []*angularUnit
	producers       []jsonProducer
	// ownAPI holds server-side helper calls that return the JSON body of a
	// fetch to a route of this repository, keyed by the call's span.
	ownAPI         map[string]ownAPICall
	modelEvidence  map[string][]analysis.Evidence
	mountedOrigins map[string]bool
	text           *parse.TextSources
	packageFiles   map[string]*packageFile
	contextLimits  []analysis.Gap
	contextFields  []string
	root           string
	parsers        *parsers
	modules        map[string]*sourceModule
	allowed        map[string]bool
	// summaries caches L4 callable summaries by callable key; see callable_summary.go.
	summaries map[string]*callableSummary
	// summaryNoLoad is set while summaries are built: a summary never loads a
	// module, so it cannot change which files a scan reports.
	summaryNoLoad bool
}

func (s *moduleSet) close() {
	for _, m := range s.modules {
		m.tree.Close()
	}
	if s.parsers != nil {
		s.parsers.close()
	}
}

func (s *moduleSet) load(file string) (*sourceModule, error) {
	file = filepath.ToSlash(filepath.Clean(file))
	if m := s.modules[file]; m != nil {
		return m, nil
	}
	if s.summaryNoLoad {
		return nil, fmt.Errorf("module not loaded while building summaries: %s", file)
	}
	if !s.allowed[file] {
		return nil, fmt.Errorf("module outside selected target sources: %s", file)
	}
	src, err := os.ReadFile(filepath.Join(s.root, filepath.FromSlash(file)))
	if err != nil {
		return nil, err
	}
	if len(src) > 2<<20 {
		return nil, fmt.Errorf("source exceeds 2 MiB limit: %s", file)
	}
	// A set built for an inventory with no JS/TS files opens no grammar; the
	// first module it ever loads opens them. Every other parser use runs inside
	// a flow over a loaded module, so it always finds them open.
	if s.parsers == nil {
		ps, err := newParsers()
		if err != nil {
			return nil, err
		}
		s.parsers = ps
	}
	parseSource := src
	parser := s.parsers.forPath(file)
	if filepath.Ext(file) == ".vue" {
		parseSource = vueScriptSource(src)
		parser = s.parsers.forPath("component.ts")
	}
	tree, recovered := parseRecovered(parser, parseSource)
	if tree == nil {
		return nil, fmt.Errorf("no syntax tree: %s", file)
	}
	var awaited map[uint]bool
	if len(recovered) == 0 && s.nextProjectFor(file) != nil && (strings.HasSuffix(file, ".ts") || strings.HasSuffix(file, ".tsx")) {
		tree, awaited = reparseTypedAwaits(parser, tree, parseSource)
	}
	m := &sourceModule{awaitedCalls: awaited, recovered: recovered, file: file, src: src, hash: fmt.Sprintf("%x", sha256.Sum256(src)), tree: tree,
		funcs: map[string]*sitter.Node{}, exports: map[string]*sitter.Node{}, imports: map[string]importBinding{}, express: map[string]bool{}, receivers: map[string]bool{}, commandNames: map[string]importBinding{}, fsNames: map[string]importBinding{}}
	s.modules[file] = m
	top := tree.RootNode()
	for i := uint(0); i < top.NamedChildCount(); i++ {
		n := top.NamedChild(i)
		if n.Kind() == "import_statement" {
			m.readImport(n)
			continue
		}
		m.readCommonJSExport(n)
		exported := n.Kind() == "export_statement"
		if exported {
			if v := n.ChildByFieldName("value"); v != nil && isFunction(v) {
				m.exports["default"] = v // export default () => ...
			}
			n = n.ChildByFieldName("declaration")
			if n == nil {
				continue
			}
		}
		if n.Kind() == "function_declaration" {
			if name := n.ChildByFieldName("name"); name != nil {
				m.funcs[name.Utf8Text(src)] = n
				if exported {
					m.exports[name.Utf8Text(src)] = n
				}
			}
		}
		if n.Kind() == "lexical_declaration" || n.Kind() == "variable_declaration" {
			for j := uint(0); j < n.NamedChildCount(); j++ {
				d := n.NamedChild(j)
				name := d.ChildByFieldName("name")
				v := d.ChildByFieldName("value")
				if name != nil && v != nil && name.Kind() == "object_pattern" {
					m.readRequireDestructuring(name, v, d)
					m.readDefaultDestructuring(name, v, d)
					m.readCommandDestructuring(name, v, d)
					m.readFSDestructuring(name, v, d)
				}
				if name == nil || v == nil || name.Kind() != "identifier" {
					continue
				}
				key := name.Utf8Text(src)
				m.readRequire(key, v, d)
				if isFunction(v) {
					m.funcs[key] = v
					if exported {
						m.exports[key] = v
					}
				}
				if v.Kind() == "call_expression" {
					fn := v.ChildByFieldName("function")
					if fn != nil && expressConstructor(m, fn) && !bindingReassigned(m, key) {
						m.receivers[key] = true
					}
				}
			}
		}
	}
	return m, nil
}

func (m *sourceModule) readImport(n *sitter.Node) {
	path := n.ChildByFieldName("source")
	module, ok := stringLiteral(path, m.src)
	if !ok {
		return
	}
	for i := uint(0); i < n.NamedChildCount(); i++ {
		clause := n.NamedChild(i)
		if clause.Kind() != "import_clause" {
			continue
		}
		for j := uint(0); j < clause.NamedChildCount(); j++ {
			c := clause.NamedChild(j)
			switch c.Kind() {
			case "identifier":
				m.imports[c.Utf8Text(m.src)] = importBinding{module, "default", n}
				if module == "express" {
					m.express[c.Utf8Text(m.src)] = true
				}
			case "namespace_import":
				if c.NamedChildCount() > 0 {
					m.imports[c.NamedChild(0).Utf8Text(m.src)] = importBinding{module, "*", n}
					if module == "express" {
						m.express[c.NamedChild(0).Utf8Text(m.src)] = true
					}
				}
			case "named_imports":
				for k := uint(0); k < c.NamedChildCount(); k++ {
					spec := c.NamedChild(k)
					name := spec.ChildByFieldName("name")
					alias := spec.ChildByFieldName("alias")
					if name == nil {
						continue
					}
					if alias == nil {
						alias = name
					}
					m.imports[alias.Utf8Text(m.src)] = importBinding{module, name.Utf8Text(m.src), n}
				}
			}
		}
	}
}

func (s *moduleSet) resolve(m *sourceModule, name string) (*sourceModule, *sitter.Node) {
	parts := strings.Split(name, ".")
	if len(parts) == 3 {
		if imp, ok := m.imports[parts[0]]; ok && imp.name == "*" {
			if target := s.importModule(m, imp.module); target != nil && exportedName(target, parts[1]) {
				obj := topVariable(target, parts[1])
				if obj != nil && obj.Kind() == "object" && !exportMemberAssigned(target, parts[1], parts[2]) {
					if method := objectMethod(obj, parts[2], target.src); method != nil {
						return target, method
					}
				}
			}
			if target := s.importModule(m, imp.module); target != nil {
				if obj := target.exports[parts[1]]; obj != nil && obj.Kind() == "object" && !exportMemberAssigned(target, parts[1], parts[2]) {
					if method := objectMethod(obj, parts[2], target.src); method != nil {
						return target, method
					}
				}
			}
		}
	}
	if parts := strings.Split(name, "."); len(parts) == 2 {
		if imp, ok := m.imports[parts[0]]; ok && imp.name == "default" {
			if target := s.importModule(m, imp.module); target != nil {
				if fn := exportedMember(target, parts[1]); fn != nil {
					return target, fn
				}
			}
		}
		if imp, ok := m.imports[parts[0]]; ok && imp.name == "*" {
			if target := s.importModule(m, imp.module); target != nil {
				if exported := target.exports[parts[1]]; exported != nil {
					return target, exported
				}
				if obj := target.exports["default"]; obj != nil && obj.Kind() == "object" {
					return target, property(obj, parts[1], target.src)
				}
			}
		}
	}

	if n := m.funcs[name]; n != nil {
		return m, n
	}
	imp, ok := m.imports[name]
	if !ok {
		return nil, nil
	}
	for _, p := range s.moduleCandidates(m, imp.module) {
		if !s.allowed[p] {
			continue
		}
		target, err := s.load(p)
		if err != nil {
			return nil, nil
		}
		key := imp.name
		if key == "*" {
			key = "default"
		}
		if member, ok := strings.CutPrefix(key, "default."); ok {
			return target, exportedMember(target, member)
		}
		if target.exports[key] == nil && key != "default" {
			// require destructuring of a CommonJS module.exports object.
			if fn := exportedMember(target, key); fn != nil {
				return target, fn
			}
		}
		return target, target.exports[key]
	}
	return nil, nil
}

func (s *moduleSet) importModule(m *sourceModule, path string) *sourceModule {
	for _, p := range s.moduleCandidates(m, path) {
		if s.allowed[p] {
			target, err := s.load(p)
			if err == nil {
				return target
			}
			return nil
		}
	}
	return nil
}

// objectMethod returns the callable an object literal holds under key
// (close-findings-gaps D-29): a shorthand method, or a function or arrow
// function value. A spread (which may replace any property), a duplicate
// key, a computed key or an accessor never names a handler statically.
func objectMethod(obj *sitter.Node, key string, src []byte) *sitter.Node {
	var found *sitter.Node
	for i := uint(0); i < obj.NamedChildCount(); i++ {
		p := obj.NamedChild(i)
		var name, value *sitter.Node
		switch p.Kind() {
		case "spread_element":
			return nil
		case "pair":
			name, value = p.ChildByFieldName("key"), p.ChildByFieldName("value")
			if value != nil && !isFunction(value) {
				value = nil
			}
		case "method_definition":
			name, value = p.ChildByFieldName("name"), p
			for j := uint(0); j < p.ChildCount(); j++ {
				if c := p.Child(j); c != nil && !c.IsNamed() && (c.Kind() == "get" || c.Kind() == "set" || c.Kind() == "*") {
					value = nil // accessors and generators are not request handlers
				}
			}
		case "shorthand_property_identifier":
			if p.Utf8Text(src) == key {
				return nil // a reference to another binding, not resolved here
			}
			continue
		default:
			continue
		}
		if name == nil || name.Kind() == "computed_property_name" || strings.Trim(name.Utf8Text(src), `"'`) != key {
			continue
		}
		if found != nil {
			return nil
		}
		found = value
		if found == nil {
			return nil
		}
	}
	return found
}

// exportMemberAssigned reports an assignment anywhere in the module to the
// exported object's member (exports.obj.key = ...) or a second assignment of
// the export itself: the literal no longer names the handler.
func exportMemberAssigned(m *sourceModule, obj, key string) bool {
	member := map[string]bool{"exports." + obj + "." + key: true, "module.exports." + obj + "." + key: true}
	whole := map[string]bool{"exports." + obj: true, "module.exports." + obj: true}
	wholeWrites := 0
	assigned := false
	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		if assigned {
			return
		}
		if n.Kind() == "assignment_expression" || n.Kind() == "augmented_assignment_expression" {
			if left := n.ChildByFieldName("left"); left != nil {
				text := strings.Join(strings.Fields(left.Utf8Text(m.src)), "")
				if member[text] {
					assigned = true
					return
				}
				if whole[text] {
					wholeWrites++
				}
			}
		}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			visit(n.NamedChild(i))
		}
	}
	visit(m.tree.RootNode())
	return assigned || wholeWrites > 1
}
