package langjs

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
	"github.com/zazzcode/zazzles/scan/internal/parse"
)

// Package origin: which database client package a value derives from.
//
// The scanner does not list the methods of a driver, the ways a client is
// created, cached or passed, or the names an application gives its handles. It
// follows definitions backwards from the receiver or callee of a call: names to
// what is assigned to them, members to the value they are read from, calls to
// what the called function returns or, for a method of a derived value, to that
// value, parameters to the arguments of the calls, and imports to the package.
// The result is a may-fact: one definition path from the package import to the
// value exists. What the call does is the decision model's question; the path
// is its evidence.

// storePackage is the query language a database client package speaks.
type storePackage struct {
	kind     string // candidate kind of a call on a value from the package
	contract string
}

// storePackages maps a package to its query language. A new driver of a known
// language is one entry; nothing else in the scanner names it.
var storePackages = map[string]storePackage{
	"mongodb": {"nosql_query_candidate", analysispacks.MongoDBDocumentContract},
}

const (
	maxOriginWork  = 1500
	maxOriginSteps = 14
	maxOriginDepth = 14
)

// originTrace is one backwards search from a receiver.
type originTrace struct {
	set   *moduleSet
	work  int
	seen  map[string]bool
	stack []analysis.Evidence
	pkg   string
	path  []analysis.Evidence
}

// originRef is a value expression in a module, with the property path wanted of it.
type originRef struct {
	m      *sourceModule
	n      *sitter.Node
	fields []string
}

// originDef is one definition of a name: a value, a parameter or an import.
type originDef struct {
	ref   originRef
	at    *sitter.Node // the statement that binds the name, as evidence
	param *sitter.Node // the function whose parameter the name is
	index int
	imp   *importBinding
}

// namesStorePackage reports source text that names a database package as a
// module path. It is a cheap filter, not evidence: the search still has to
// reach the import.
func namesStorePackage(src []byte) bool {
	for pkg := range storePackages {
		if bytes.Contains(src, []byte("'"+pkg+"'")) || bytes.Contains(src, []byte("\""+pkg+"\"")) || bytes.Contains(src, []byte("`"+pkg+"`")) {
			return true
		}
	}
	return false
}

// findStorePackages sets storeActive when any JavaScript or TypeScript file of
// the target names a database package: the import may be in a file that is
// loaded only when a handler reaches it.
func (s *moduleSet) findStorePackages() {
	for file := range s.allowed {
		if s.storeActive {
			return
		}
		if m := s.modules[file]; m != nil {
			s.storeActive = namesStorePackage(m.src)
		} else if src, err := os.ReadFile(filepath.Join(s.root, filepath.FromSlash(file))); err == nil {
			s.storeActive = namesStorePackage(src)
		}
	}
}

// storeOrigin returns the database package a call's callee derives from, with
// the definition path as binding evidence. The path ends at the call.
func (s *moduleSet) storeOrigin(m *sourceModule, call *sitter.Node) (string, []analysis.Evidence) {
	if call == nil || call.Kind() != "call_expression" {
		return "", nil
	}
	fn := unwrapTS(call.ChildByFieldName("function"))
	if fn == nil || !s.storeActive {
		return "", nil
	}
	t := &originTrace{set: s, seen: map[string]bool{}}
	if !t.derive(m, fn, nil) {
		return "", nil
	}
	return t.pkg, append(t.path, m.evidence("sink_binding", call))
}

func (t *originTrace) push(m *sourceModule, n *sitter.Node) int {
	mark := len(t.stack)
	if n == nil {
		return mark
	}
	e := m.evidence("sink_binding", n)
	for _, old := range t.stack {
		if old.Span == e.Span {
			return mark
		}
	}
	t.stack = append(t.stack, e)
	return mark
}

// pushDefinition records the statement that gives n its place in the path: the
// declaration, assignment, return or class field it is written in.
func (t *originTrace) pushDefinition(m *sourceModule, n *sitter.Node) int {
	mark := len(t.stack)
	for p := n; p != nil; p = p.Parent() {
		switch p.Kind() {
		case "variable_declarator", "assignment_expression", "augmented_assignment_expression", "return_statement", "field_definition", "public_field_definition":
			t.push(m, p)
			return mark
		case "statement_block", "program", "class_body":
			return mark
		}
	}
	return mark
}

func (t *originTrace) found(pkg string) bool {
	t.pkg = pkg
	// The import comes first and the receiver last; the search ran backwards.
	for i := len(t.stack) - 1; i >= 0 && len(t.path) < maxOriginSteps; i-- {
		t.path = append(t.path, t.stack[i])
	}
	return true
}

func prepend(key string, fields []string) []string {
	return append([]string{key}, fields...)
}

func memberKey(n *sitter.Node, src []byte) (string, bool) {
	if n.Kind() == "member_expression" {
		if p := n.ChildByFieldName("property"); p != nil {
			return p.Utf8Text(src), true
		}
		return "", false
	}
	if key, ok := stringLiteral(n.ChildByFieldName("index"), src); ok {
		return key, true
	}
	return "", false
}

// derive reports whether the value at fields of expression n may come from a
// database package.
func (t *originTrace) derive(m *sourceModule, n *sitter.Node, fields []string) bool {
	n = unwrapTS(n)
	if n == nil || m == nil {
		return false
	}
	t.work++
	if t.work > maxOriginWork || len(fields) > maxOriginDepth {
		return false
	}
	key := m.file + ":" + strconv.Itoa(int(n.StartByte())) + ":" + strconv.Itoa(int(n.EndByte())) + ":" + strings.Join(fields, ".")
	if t.seen[key] {
		return false
	}
	t.seen[key] = true
	switch n.Kind() {
	case "await_expression", "spread_element":
		if n.NamedChildCount() == 1 {
			return t.derive(m, n.NamedChild(0), fields)
		}
	case "identifier", "shorthand_property_identifier":
		return t.name(m, n, fields)
	case "member_expression", "subscript_expression":
		obj := unwrapTS(n.ChildByFieldName("object"))
		if obj == nil {
			return false
		}
		key, ok := memberKey(n, m.src)
		if !ok {
			return t.derive(m, obj, nil)
		}
		if obj.Kind() == "this" {
			for _, r := range classMembers(m, enclosingClass(n), key) {
				mark := t.pushDefinition(r.m, r.n)
				if t.derive(r.m, r.n, fields) {
					return true
				}
				t.stack = t.stack[:mark]
			}
			return false
		}
		if obj.Kind() == "identifier" && globalObjectName(obj.Utf8Text(m.src)) && len(t.set.nameDefs(m, obj)) == 0 {
			return t.global(key, fields)
		}
		return t.derive(m, obj, prepend(key, fields))
	case "call_expression":
		return t.call(m, n, fields)
	case "new_expression":
		ctor := n.ChildByFieldName("constructor")
		if len(fields) > 0 {
			// A property of an instance of the application's own class.
			for _, c := range t.set.resolveRefs(m, ctor, nil, 0) {
				for _, r := range classMembers(c.m, instanceBody(c.n), fields[0]) {
					mark := t.pushDefinition(r.m, r.n)
					if t.derive(r.m, r.n, fields[1:]) {
						return true
					}
					t.stack = t.stack[:mark]
				}
			}
		}
		return t.derive(m, ctor, nil)
	case "object":
		for i := uint(0); i < n.NamedChildCount(); i++ {
			p := n.NamedChild(i)
			switch p.Kind() {
			case "spread_element":
				if t.derive(m, p, fields) {
					return true
				}
			case "pair":
				k, v := p.ChildByFieldName("key"), p.ChildByFieldName("value")
				if k == nil || v == nil {
					continue
				}
				if len(fields) == 0 {
					if t.derive(m, v, nil) {
						return true
					}
				} else if strings.Trim(k.Utf8Text(m.src), `"'`) == fields[0] && t.derive(m, v, fields[1:]) {
					return true
				}
			case "shorthand_property_identifier":
				if len(fields) == 0 {
					if t.derive(m, p, nil) {
						return true
					}
				} else if p.Utf8Text(m.src) == fields[0] && t.derive(m, p, fields[1:]) {
					return true
				}
			}
		}
	case "array":
		for i := uint(0); i < n.NamedChildCount(); i++ {
			if t.derive(m, n.NamedChild(i), nil) {
				return true
			}
		}
	case "ternary_expression":
		return t.derive(m, n.ChildByFieldName("consequence"), fields) || t.derive(m, n.ChildByFieldName("alternative"), fields)
	case "binary_expression":
		if op := n.ChildByFieldName("operator"); op != nil {
			switch op.Utf8Text(m.src) {
			case "||", "??", "&&":
				return t.derive(m, n.ChildByFieldName("left"), fields) || t.derive(m, n.ChildByFieldName("right"), fields)
			}
		}
	case "assignment_expression", "augmented_assignment_expression":
		return t.derive(m, n.ChildByFieldName("right"), fields) || t.derive(m, n.ChildByFieldName("left"), fields)
	case "sequence_expression":
		if c := n.NamedChildCount(); c > 0 {
			return t.derive(m, n.NamedChild(c-1), fields)
		}
	}
	return false
}

func globalObjectName(name string) bool {
	return name == "globalThis" || name == "global"
}

// call is the value a call gives.
func (t *originTrace) call(m *sourceModule, n *sitter.Node, fields []string) bool {
	fn := unwrapTS(n.ChildByFieldName("function"))
	if fn == nil {
		return false
	}
	if path, ok := moduleLoad(m, n); ok {
		mark := t.push(m, n)
		defer func() { t.stack = t.stack[:mark] }()
		return t.module(m, path, "*", fields)
	}
	// A function of the repository gives what it returns.
	if fns := t.set.functionsOf(m, fn); len(fns) > 0 {
		for _, f := range fns {
			mark := t.pushDefinition(f.m, f.n)
			if t.returns(f.m, f.n, fields) {
				return true
			}
			t.stack = t.stack[:mark]
		}
		return false
	}
	if fn.Kind() == "member_expression" {
		obj, prop := fn.ChildByFieldName("object"), fn.ChildByFieldName("property")
		if obj != nil && prop != nil {
			switch prop.Utf8Text(m.src) {
			case "catch", "finally", "bind":
				// The same promise value, or the same function with its receiver fixed.
				return t.derive(m, obj, fields)
			}
		}
	}
	// A method or function of a derived value gives a derived value.
	return t.derive(m, fn, nil)
}

// moduleLoad is require('path') or import('path') with a literal path.
func moduleLoad(m *sourceModule, call *sitter.Node) (string, bool) {
	fn, args := call.ChildByFieldName("function"), call.ChildByFieldName("arguments")
	if fn == nil || args == nil || args.NamedChildCount() != 1 {
		return "", false
	}
	if fn.Kind() != "import" && (fn.Kind() != "identifier" || fn.Utf8Text(m.src) != "require" || topLevelBinding(m, "require")) {
		return "", false
	}
	return stringLiteral(args.NamedChild(0), m.src)
}

// module is the value of an export of a module path: a database package, or a
// module of the repository.
func (t *originTrace) module(m *sourceModule, path, name string, fields []string) bool {
	if _, ok := storePackages[path]; ok {
		return t.found(path)
	}
	for _, r := range t.set.importRefs(m, path, name, fields) {
		mark := t.pushDefinition(r.m, r.n)
		if t.derive(r.m, r.n, r.fields) {
			return true
		}
		t.stack = t.stack[:mark]
	}
	return false
}

// returns is what a function returns.
func (t *originTrace) returns(m *sourceModule, fn *sitter.Node, fields []string) bool {
	body := fn.ChildByFieldName("body")
	if body == nil {
		return false
	}
	if body.Kind() != "statement_block" {
		return t.derive(m, body, fields)
	}
	found := false
	var walk func(*sitter.Node)
	walk = func(n *sitter.Node) {
		if found || (n != body && scopeFunction(n)) {
			return
		}
		if n.Kind() == "return_statement" && n.NamedChildCount() == 1 {
			mark := t.push(m, n)
			if found = t.derive(m, n.NamedChild(0), fields); !found {
				t.stack = t.stack[:mark]
			}
			return
		}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			walk(n.NamedChild(i))
		}
	}
	walk(body)
	return found
}

func scopeFunction(n *sitter.Node) bool {
	switch n.Kind() {
	case "function_declaration", "function_expression", "function", "arrow_function", "method_definition", "generator_function", "generator_function_declaration", "class_body":
		return true
	}
	return false
}

// name follows an identifier to its definitions.
func (t *originTrace) name(m *sourceModule, id *sitter.Node, fields []string) bool {
	for _, d := range t.set.nameDefs(m, id) {
		mark := t.push(m, d.at)
		ok := false
		switch {
		case d.imp != nil:
			ok = t.module(m, d.imp.module, d.imp.name, fields)
		case d.param != nil:
			ok = t.argument(m, d.param, d.index, append(append([]string{}, d.ref.fields...), fields...))
		default:
			ok = t.derive(d.ref.m, d.ref.n, append(append([]string{}, d.ref.fields...), fields...))
		}
		if ok {
			return true
		}
		t.stack = t.stack[:mark]
	}
	return false
}

// global follows a property of the global object to every assignment of it.
func (t *originTrace) global(key string, fields []string) bool {
	for _, file := range t.set.moduleFiles() {
		m := t.set.modules[file]
		for _, a := range m.originIndex().assignments {
			left := a.ChildByFieldName("left")
			if left == nil || left.Kind() != "member_expression" {
				continue
			}
			obj, prop := left.ChildByFieldName("object"), left.ChildByFieldName("property")
			if obj == nil || prop == nil || obj.Kind() != "identifier" || !globalObjectName(obj.Utf8Text(m.src)) || prop.Utf8Text(m.src) != key {
				continue
			}
			mark := t.push(m, a)
			if t.derive(m, a.ChildByFieldName("right"), fields) {
				return true
			}
			t.stack = t.stack[:mark]
		}
	}
	return false
}

// argument follows parameter index of fn to the arguments it receives: at the
// calls of the function, or, for a callback, from the value whose method takes it.
func (t *originTrace) argument(m *sourceModule, fn *sitter.Node, index int, fields []string) bool {
	parent := fn.Parent()
	if parent != nil && parent.Kind() == "arguments" {
		call := parent.Parent()
		if call == nil || call.Kind() != "call_expression" {
			return false
		}
		callee := unwrapTS(call.ChildByFieldName("function"))
		position := -1
		for i := uint(0); i < parent.NamedChildCount(); i++ {
			if parent.NamedChild(i).Id() == fn.Id() {
				position = int(i)
			}
		}
		if callee == nil || position < 0 {
			return false
		}
		if isFunction(callee) {
			return false
		}
		if targets := t.set.functionsOf(m, callee); len(targets) > 0 {
			// A function of the repository calls its parameter with some arguments.
			for _, g := range targets {
				params := parameterPatterns(g.n)
				if position >= len(params) || params[position] == nil || params[position].Kind() != "identifier" {
					continue
				}
				name := params[position].Utf8Text(g.m.src)
				ok := false
				walkCalls(g.n.ChildByFieldName("body"), func(inner *sitter.Node) {
					f, args := inner.ChildByFieldName("function"), inner.ChildByFieldName("arguments")
					if ok || f == nil || args == nil || f.Kind() != "identifier" || f.Utf8Text(g.m.src) != name || uint(index) >= args.NamedChildCount() {
						return
					}
					ok = t.derive(g.m, args.NamedChild(uint(index)), fields)
				})
				if ok {
					return true
				}
			}
			return false
		}
		if callee.Kind() == "member_expression" {
			// A callback of a method of a derived value receives a derived value.
			return t.derive(m, callee.ChildByFieldName("object"), nil)
		}
		return false
	}
	if parent != nil && parent.Kind() == "call_expression" {
		// A function called where it is written receives the arguments written there.
		if args := parent.ChildByFieldName("arguments"); args != nil && uint(index) < args.NamedChildCount() {
			return t.derive(m, args.NamedChild(uint(index)), fields)
		}
		return false
	}
	name, constructor := callableName(m, fn)
	if name == "" {
		return false
	}
	plainFunction := fn.Kind() != "method_definition"
	for _, file := range t.set.moduleFiles() {
		cm := t.set.modules[file]
		sites := cm.originIndex().calls[name]
		// A module that imports the function under another name calls it by that name.
		for _, local := range sortedImportNames(cm) {
			if local == name || len(cm.originIndex().calls[local]) == 0 {
				continue
			}
			first := cm.originIndex().calls[local][0]
			callee := first.ChildByFieldName("function")
			if first.Kind() == "new_expression" {
				callee = first.ChildByFieldName("constructor")
			}
			if callee = unwrapTS(callee); callee == nil || callee.Kind() != "identifier" {
				continue
			}
			for _, f := range t.set.functionsOf(cm, callee) {
				if f.m == m && f.n.Id() == fn.Id() {
					sites = append(sites, cm.originIndex().calls[local]...)
				}
			}
		}
		for _, site := range sites {
			// A class is constructed; a function may be called or constructed.
			if constructor != (site.Kind() == "new_expression") && !(plainFunction && !constructor) {
				continue
			}
			callee := unwrapTS(site.ChildByFieldName("function"))
			if site.Kind() == "new_expression" {
				callee = unwrapTS(site.ChildByFieldName("constructor"))
			}
			args := site.ChildByFieldName("arguments")
			if callee == nil || args == nil || uint(index) >= args.NamedChildCount() {
				continue
			}
			if callee.Kind() == "identifier" && site.Kind() != "new_expression" {
				// A plain name must resolve to this function; a method is matched by name.
				match := false
				for _, f := range t.set.functionsOf(cm, callee) {
					match = match || (f.m == m && f.n.Id() == fn.Id())
				}
				if !match {
					continue
				}
			}
			mark := t.push(cm, site)
			if t.derive(cm, args.NamedChild(uint(index)), fields) {
				return true
			}
			t.stack = t.stack[:mark]
		}
	}
	return false
}

// callableName is the name a function is called by, and whether it is a class
// constructor, which is called by the name of its class.
func callableName(m *sourceModule, fn *sitter.Node) (string, bool) {
	if fn.Kind() == "method_definition" {
		name := fn.ChildByFieldName("name")
		if name == nil {
			return "", false
		}
		if name.Utf8Text(m.src) != "constructor" {
			return name.Utf8Text(m.src), false
		}
		if body := fn.Parent(); body != nil && body.Parent() != nil {
			class := body.Parent()
			if id := class.ChildByFieldName("name"); id != nil {
				return id.Utf8Text(m.src), true
			}
			if d := class.Parent(); d != nil && d.Kind() == "variable_declarator" {
				if id := d.ChildByFieldName("name"); id != nil {
					return id.Utf8Text(m.src), true
				}
			}
		}
		return "", false
	}
	if id := fn.ChildByFieldName("name"); id != nil && fn.Kind() != "arrow_function" {
		return id.Utf8Text(m.src), false
	}
	parent := fn.Parent()
	if parent == nil {
		return "", false
	}
	switch parent.Kind() {
	case "variable_declarator":
		if id := parent.ChildByFieldName("name"); id != nil && id.Kind() == "identifier" {
			return id.Utf8Text(m.src), false
		}
	case "pair":
		if k := parent.ChildByFieldName("key"); k != nil {
			return strings.Trim(k.Utf8Text(m.src), `"'`), false
		}
	case "assignment_expression":
		if left := parent.ChildByFieldName("left"); left != nil {
			if left.Kind() == "identifier" {
				return left.Utf8Text(m.src), false
			}
			if p := left.ChildByFieldName("property"); p != nil {
				return p.Utf8Text(m.src), false
			}
		}
	}
	return "", false
}

// originIndex holds the assignments, calls and constructions of a module.
type originIndex struct {
	assignments []*sitter.Node
	// calls maps the last name of a callee to its call and new expressions.
	calls map[string][]*sitter.Node
}

func (m *sourceModule) originIndex() *originIndex {
	if m.origins != nil {
		return m.origins
	}
	idx := &originIndex{calls: map[string][]*sitter.Node{}}
	var walk func(*sitter.Node)
	walk = func(n *sitter.Node) {
		switch n.Kind() {
		case "assignment_expression", "augmented_assignment_expression":
			idx.assignments = append(idx.assignments, n)
		case "call_expression", "new_expression":
			callee := n.ChildByFieldName("function")
			if n.Kind() == "new_expression" {
				callee = n.ChildByFieldName("constructor")
			}
			callee = unwrapTS(callee)
			if callee != nil && callee.Kind() == "member_expression" {
				callee = callee.ChildByFieldName("property")
			}
			if callee != nil && (callee.Kind() == "identifier" || callee.Kind() == "property_identifier") {
				name := callee.Utf8Text(m.src)
				idx.calls[name] = append(idx.calls[name], n)
			}
		}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			walk(n.NamedChild(i))
		}
	}
	walk(m.tree.RootNode())
	m.origins = idx
	return idx
}

// moduleFiles lists the loaded modules in a fixed order.
func (s *moduleSet) moduleFiles() []string {
	files := make([]string, 0, len(s.modules))
	for file := range s.modules {
		files = append(files, file)
	}
	sort.Strings(files)
	return files
}

// parameterPatterns lists a function's parameters: the identifier or pattern of each.
func parameterPatterns(fn *sitter.Node) []*sitter.Node {
	params := fn.ChildByFieldName("parameters")
	if params == nil {
		if p := fn.ChildByFieldName("parameter"); p != nil {
			return []*sitter.Node{p}
		}
		return nil
	}
	var out []*sitter.Node
	for i := uint(0); i < params.NamedChildCount(); i++ {
		p := params.NamedChild(i)
		if p.Kind() == "comment" {
			continue
		}
		if p.Kind() == "required_parameter" || p.Kind() == "optional_parameter" {
			p = p.ChildByFieldName("pattern")
		}
		if p != nil && p.Kind() == "assignment_pattern" {
			p = p.ChildByFieldName("left")
		}
		out = append(out, p)
	}
	return out
}

// patternPath finds name in a binding pattern and returns the property path it
// is bound from. An array element or a rest element has no path.
func patternPath(p *sitter.Node, name string, src []byte) ([]string, bool) {
	if p == nil {
		return nil, false
	}
	switch p.Kind() {
	case "identifier", "shorthand_property_identifier_pattern":
		return nil, p.Utf8Text(src) == name
	case "assignment_pattern":
		return patternPath(p.ChildByFieldName("left"), name, src)
	case "object_assignment_pattern":
		return patternPath(p.ChildByFieldName("left"), name, src)
	case "pair_pattern":
		k := p.ChildByFieldName("key")
		if path, ok := patternPath(p.ChildByFieldName("value"), name, src); ok && k != nil {
			return prepend(strings.Trim(k.Utf8Text(src), `"'`), path), true
		}
		return nil, false
	case "object_pattern":
		for i := uint(0); i < p.NamedChildCount(); i++ {
			c := p.NamedChild(i)
			if c.Kind() == "shorthand_property_identifier_pattern" && c.Utf8Text(src) == name {
				return []string{name}, true
			}
			if path, ok := patternPath(c, name, src); ok {
				return path, true
			}
		}
	case "array_pattern", "rest_pattern":
		for i := uint(0); i < p.NamedChildCount(); i++ {
			if _, ok := patternPath(p.NamedChild(i), name, src); ok {
				return nil, true
			}
		}
	}
	return nil, false
}

// nameDefs lists the definitions of the name an identifier reads: the binding
// of the nearest enclosing scope, and every assignment to it in that scope.
func (s *moduleSet) nameDefs(m *sourceModule, id *sitter.Node) []originDef {
	name := id.Utf8Text(m.src)
	var defs []originDef
	declarators := func(decl *sitter.Node) {
		if decl == nil || (decl.Kind() != "lexical_declaration" && decl.Kind() != "variable_declaration") {
			return
		}
		for i := uint(0); i < decl.NamedChildCount(); i++ {
			d := decl.NamedChild(i)
			if d.Kind() != "variable_declarator" {
				continue
			}
			if path, ok := patternPath(d.ChildByFieldName("name"), name, m.src); ok {
				defs = append(defs, originDef{ref: originRef{m, d.ChildByFieldName("value"), path}, at: d})
			}
		}
	}
	statement := func(c *sitter.Node) {
		if c.Kind() == "export_statement" {
			if d := c.ChildByFieldName("declaration"); d != nil {
				c = d
			}
		}
		switch c.Kind() {
		case "lexical_declaration", "variable_declaration":
			declarators(c)
		case "function_declaration", "class_declaration", "generator_function_declaration":
			if n := c.ChildByFieldName("name"); n != nil && n.Utf8Text(m.src) == name {
				defs = append(defs, originDef{ref: originRef{m: m, n: c}})
			}
		}
	}
	var scope *sitter.Node
	for p := id.Parent(); p != nil && scope == nil; p = p.Parent() {
		switch p.Kind() {
		case "statement_block", "program", "switch_case", "switch_default":
			for i := uint(0); i < p.NamedChildCount(); i++ {
				statement(p.NamedChild(i))
			}
		case "for_statement":
			declarators(p.ChildByFieldName("initializer"))
		case "for_in_statement":
			if left := p.ChildByFieldName("left"); left != nil {
				if _, ok := patternPath(left, name, m.src); ok {
					// An element of what is iterated.
					defs = append(defs, originDef{ref: originRef{m: m, n: p.ChildByFieldName("right")}, at: p.ChildByFieldName("right")})
				}
			}
		case "catch_clause":
			if param := p.ChildByFieldName("parameter"); param != nil {
				if _, ok := patternPath(param, name, m.src); ok {
					return nil
				}
			}
		}
		if scopeFunction(p) && p.Kind() != "class_body" {
			for i, param := range parameterPatterns(p) {
				if path, ok := patternPath(param, name, m.src); ok {
					return []originDef{{ref: originRef{m: m, fields: path}, param: p, index: i}}
				}
			}
			if len(defs) == 0 {
				// A var declared in a nested block of this function.
				var walk func(*sitter.Node)
				walk = func(n *sitter.Node) {
					if n != p && scopeFunction(n) {
						return
					}
					if n.Kind() == "variable_declaration" {
						declarators(n)
					}
					for i := uint(0); i < n.NamedChildCount(); i++ {
						walk(n.NamedChild(i))
					}
				}
				walk(p)
			}
		}
		if len(defs) > 0 || p.Kind() == "program" {
			scope = p
		}
	}
	if scope == nil {
		return nil
	}
	if len(defs) == 0 {
		if imp, ok := m.imports[name]; ok {
			return []originDef{{imp: &imp, at: imp.declaration}}
		}
		if imp, ok := importEquals(m, name); ok {
			return []originDef{{imp: &imp, at: imp.declaration}}
		}
		return nil
	}
	for _, a := range m.originIndex().assignments {
		left := a.ChildByFieldName("left")
		if left == nil || left.Kind() != "identifier" || left.Utf8Text(m.src) != name || a.StartByte() < scope.StartByte() || a.EndByte() > scope.EndByte() {
			continue
		}
		defs = append(defs, originDef{ref: originRef{m: m, n: a.ChildByFieldName("right")}, at: a})
	}
	return defs
}

// importEquals reads TypeScript's `import name = require('module')`.
func importEquals(m *sourceModule, name string) (importBinding, bool) {
	root := m.tree.RootNode()
	for i := uint(0); i < root.NamedChildCount(); i++ {
		n := root.NamedChild(i)
		if n.Kind() != "import_statement" {
			continue
		}
		for j := uint(0); j < n.NamedChildCount(); j++ {
			clause := n.NamedChild(j)
			if clause.Kind() != "import_require_clause" || clause.NamedChildCount() < 2 || clause.NamedChild(0).Utf8Text(m.src) != name {
				continue
			}
			if path, ok := stringLiteral(clause.ChildByFieldName("source"), m.src); ok {
				return importBinding{path, "*", n}, true
			}
		}
	}
	return importBinding{}, false
}

// enclosingClass is the body that defines the instance `this` names at n: the
// class body, or the body of the nearest function that is not an arrow function,
// which is a constructor function when it assigns to this.
func enclosingClass(n *sitter.Node) *sitter.Node {
	for p := n.Parent(); p != nil; p = p.Parent() {
		switch p.Kind() {
		case "class_body":
			return p
		case "function_declaration", "function_expression", "function":
			return p.ChildByFieldName("body")
		}
	}
	return nil
}

// instanceBody is the body that defines the instances a constructor makes: a
// class body, or the body of a constructor function.
func instanceBody(ctor *sitter.Node) *sitter.Node {
	switch ctor.Kind() {
	case "class_declaration", "class", "function_declaration", "function_expression", "function":
		return ctor.ChildByFieldName("body")
	}
	return nil
}

// classMembers lists what a class gives the member key of its instances: a
// method, a field value, and every assignment to this.key in the class.
func classMembers(m *sourceModule, body *sitter.Node, key string) []originRef {
	if body == nil {
		return nil
	}
	var out []originRef
	for i := uint(0); i < body.NamedChildCount(); i++ {
		c := body.NamedChild(i)
		name := c.ChildByFieldName("name")
		if name == nil {
			name = c.ChildByFieldName("property")
		}
		if name == nil || name.Utf8Text(m.src) != key {
			continue
		}
		switch c.Kind() {
		case "method_definition":
			out = append(out, originRef{m: m, n: c})
		case "field_definition", "public_field_definition":
			if v := c.ChildByFieldName("value"); v != nil {
				out = append(out, originRef{m: m, n: v})
			}
		}
	}
	var walk func(*sitter.Node)
	walk = func(n *sitter.Node) {
		if n.Kind() == "assignment_expression" || n.Kind() == "augmented_assignment_expression" {
			if left := n.ChildByFieldName("left"); left != nil && left.Kind() == "member_expression" {
				obj, prop := left.ChildByFieldName("object"), left.ChildByFieldName("property")
				if obj != nil && prop != nil && obj.Kind() == "this" && prop.Utf8Text(m.src) == key {
					out = append(out, originRef{m: m, n: n.ChildByFieldName("right")})
				}
			}
		}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			walk(n.NamedChild(i))
		}
	}
	walk(body)
	return out
}

// importRefs lists the values an import of name from a module path of the
// repository refers to. name is an export, "default", "default.member" or "*",
// which takes the export from fields.
func (s *moduleSet) importRefs(m *sourceModule, path, name string, fields []string) []originRef {
	target := s.importModule(m, path)
	if target == nil {
		return nil
	}
	if member, ok := strings.CutPrefix(name, "default."); ok {
		name, fields = "default", prepend(member, fields)
	}
	if name == "*" {
		if len(fields) == 0 {
			// The module itself as a value: what a CommonJS module assigns to
			// module.exports, or its default export.
			name = "default"
		} else {
			name, fields = fields[0], fields[1:]
		}
	}
	refs := s.exportRefs(target, name, 0)
	if len(refs) == 0 && name == "default" && len(fields) > 0 {
		// A default import of a module with named exports reads them as members.
		refs, fields = s.exportRefs(target, fields[0], 0), fields[1:]
	}
	out := make([]originRef, 0, len(refs))
	for _, r := range refs {
		out = append(out, originRef{r.m, r.n, append(append([]string{}, r.fields...), fields...)})
	}
	return out
}

// exportRefs lists the values a module exports under name.
func (s *moduleSet) exportRefs(target *sourceModule, name string, depth int) []originRef {
	if depth > 4 {
		return nil
	}
	var out []originRef
	root := target.tree.RootNode()
	for i := uint(0); i < root.NamedChildCount(); i++ {
		n := root.NamedChild(i)
		switch n.Kind() {
		case "export_statement":
			byDefault := false
			var clause *sitter.Node
			for j := uint(0); j < n.ChildCount(); j++ {
				byDefault = byDefault || n.Child(j).Kind() == "default"
				if n.Child(j).Kind() == "export_clause" {
					clause = n.Child(j)
				}
			}
			decl, value := n.ChildByFieldName("declaration"), n.ChildByFieldName("value")
			source, hasSource := stringLiteral(n.ChildByFieldName("source"), target.src)
			switch {
			case byDefault:
				if name != "default" {
					continue
				}
				if value != nil {
					out = append(out, originRef{m: target, n: value})
				} else if decl != nil {
					out = append(out, originRef{m: target, n: decl})
				}
			case decl != nil && (decl.Kind() == "lexical_declaration" || decl.Kind() == "variable_declaration"):
				for j := uint(0); j < decl.NamedChildCount(); j++ {
					d := decl.NamedChild(j)
					if path, ok := patternPath(d.ChildByFieldName("name"), name, target.src); ok {
						out = append(out, originRef{target, d.ChildByFieldName("value"), path})
					}
				}
			case decl != nil:
				if id := decl.ChildByFieldName("name"); id != nil && id.Utf8Text(target.src) == name {
					out = append(out, originRef{m: target, n: decl})
				}
			case clause != nil:
				for j := uint(0); j < clause.NamedChildCount(); j++ {
					spec := clause.NamedChild(j)
					id, alias := spec.ChildByFieldName("name"), spec.ChildByFieldName("alias")
					visible := alias
					if visible == nil {
						visible = id
					}
					if id == nil || visible.Utf8Text(target.src) != name {
						continue
					}
					if hasSource {
						if next := s.importModule(target, source); next != nil {
							out = append(out, s.exportRefs(next, id.Utf8Text(target.src), depth+1)...)
						}
					} else {
						out = append(out, originRef{m: target, n: id})
					}
				}
			case hasSource:
				// export * from './module'
				if next := s.importModule(target, source); next != nil {
					out = append(out, s.exportRefs(next, name, depth+1)...)
				}
			}
		case "expression_statement":
			if n.NamedChildCount() != 1 || n.NamedChild(0).Kind() != "assignment_expression" {
				continue
			}
			left, right := n.NamedChild(0).ChildByFieldName("left"), n.NamedChild(0).ChildByFieldName("right")
			if left == nil || right == nil {
				continue
			}
			text := strings.Join(strings.Fields(left.Utf8Text(target.src)), "")
			switch {
			case text == "module.exports" && name == "default":
				out = append(out, originRef{m: target, n: right})
			case text == "module.exports":
				out = append(out, originRef{target, right, []string{name}})
			case text == "exports."+name || text == "module.exports."+name:
				out = append(out, originRef{m: target, n: right})
			}
		}
	}
	return out
}

// resolveRefs follows names, members and imports of the repository to the
// values they are defined as: functions, classes, objects and other expressions.
// It does not follow a parameter to its arguments.
func (s *moduleSet) resolveRefs(m *sourceModule, n *sitter.Node, fields []string, depth int) []originRef {
	n = unwrapTS(n)
	if n == nil || m == nil || depth > maxOriginDepth {
		return nil
	}
	var out []originRef
	follow := func(refs []originRef) {
		for _, r := range refs {
			out = append(out, s.resolveRefs(r.m, r.n, r.fields, depth+1)...)
		}
	}
	switch n.Kind() {
	case "await_expression":
		if n.NamedChildCount() == 1 {
			return s.resolveRefs(m, n.NamedChild(0), fields, depth+1)
		}
	case "identifier", "shorthand_property_identifier":
		for _, d := range s.nameDefs(m, n) {
			switch {
			case d.imp != nil:
				follow(s.importRefs(m, d.imp.module, d.imp.name, fields))
			case d.param == nil && d.ref.n != nil && d.ref.n.Id() != n.Id():
				follow([]originRef{{d.ref.m, d.ref.n, append(append([]string{}, d.ref.fields...), fields...)}})
			}
		}
		return out
	case "member_expression", "subscript_expression":
		obj := unwrapTS(n.ChildByFieldName("object"))
		key, ok := memberKey(n, m.src)
		if obj == nil || !ok {
			return nil
		}
		if obj.Kind() == "this" {
			for _, r := range classMembers(m, enclosingClass(n), key) {
				follow([]originRef{{r.m, r.n, fields}})
			}
			return out
		}
		return s.resolveRefs(m, obj, prepend(key, fields), depth+1)
	case "call_expression":
		if path, ok := moduleLoad(m, n); ok {
			follow(s.importRefs(m, path, "*", fields))
			return out
		}
	case "new_expression":
		if len(fields) > 0 {
			for _, c := range s.resolveRefs(m, n.ChildByFieldName("constructor"), nil, depth+1) {
				for _, r := range classMembers(c.m, instanceBody(c.n), fields[0]) {
					follow([]originRef{{r.m, r.n, fields[1:]}})
				}
			}
			return out
		}
	case "object":
		if len(fields) > 0 {
			for i := uint(0); i < n.NamedChildCount(); i++ {
				p := n.NamedChild(i)
				switch p.Kind() {
				case "pair":
					if k, v := p.ChildByFieldName("key"), p.ChildByFieldName("value"); k != nil && v != nil && strings.Trim(k.Utf8Text(m.src), `"'`) == fields[0] {
						follow([]originRef{{m, v, fields[1:]}})
					}
				case "shorthand_property_identifier":
					if p.Utf8Text(m.src) == fields[0] {
						follow([]originRef{{m, p, fields[1:]}})
					}
				case "method_definition":
					if k := p.ChildByFieldName("name"); k != nil && k.Utf8Text(m.src) == fields[0] && len(fields) == 1 {
						out = append(out, originRef{m: m, n: p})
					}
				}
			}
			return out
		}
	}
	if len(fields) > 0 {
		return nil
	}
	return []originRef{{m: m, n: n}}
}

// functionsOf lists the functions of the repository a callee expression names.
func (s *moduleSet) functionsOf(m *sourceModule, callee *sitter.Node) []originRef {
	var out []originRef
	for _, r := range s.resolveRefs(m, callee, nil, 0) {
		if r.n.Kind() == "function_declaration" || r.n.Kind() == "method_definition" || r.n.Kind() == "generator_function_declaration" || isFunction(r.n) {
			out = append(out, r)
		}
	}
	return out
}

// storeBinding is the binding evidence and contract of a recorded call whose
// callee derives from a database package.
func (s *moduleSet) storeBinding(use analysis.CandidateUse) ([]analysis.Evidence, string) {
	m := s.modules[use.Sink.Span.File]
	if m == nil {
		return nil, ""
	}
	call := parse.NodeAt(m.tree.RootNode(), use.Sink.Span.StartByte, use.Sink.Span.EndByte)
	pkg, path := s.storeOrigin(m, call)
	if pkg == "" || storePackages[pkg].kind != use.Kind {
		return nil, ""
	}
	return path, storePackages[pkg].contract
}

// storeCall records a call on a value from a database package that receives
// request data. It is additive: the call is then handled exactly as before, so
// the candidates, gaps and identities of every other family are unchanged, and
// no request field is marked as consumed.
func (f *flow) storeCall(n, args *sitter.Node, values []value) {
	if f.client != nil || f.set == nil || !f.set.storeActive {
		return
	}
	if !requestDeps(values) {
		f.storeAliasCall(n)
		f.storeClosureCall(n, args)
		return
	}
	f.recordStore(n, args, values)
}

// recordStore records the call when its callee derives from a database package.
func (f *flow) recordStore(n, args *sitter.Node, values []value) {
	pkg, _ := f.set.storeOrigin(f.module, n)
	if pkg == "" {
		return
	}
	kind := storePackages[pkg].kind
	v := value{}
	for _, a := range values {
		v = combine(v, a)
	}
	gaps := append(append([]analysis.Gap{}, f.gaps...), v.gaps...)
	text := ""
	if args != nil {
		text = ownArgumentText(args, f.module.src)
	}
	if strings.Contains(text, "$where") {
		gaps = append(gaps, f.gap("query_text_interpolated", "a value is built into a NoSQL $where string", n))
	} else {
		gaps = append(gaps, f.gap("query_document_unvalidated", "request-controlled value enters a query, update, or insert document without a modeled type constraint", n))
	}
	gaps = append(gaps, f.gap("sink_binding_unverified", "candidate API shape; library binding/argument roles require review", n))
	f.uses = append(f.uses, analysis.CandidateUse{ID: fmt.Sprintf("use:%s:%s:%d", f.invocation.ID, f.module.file, n.StartByte()), EntryID: f.entry.ID, InvocationContextID: f.invocation.ID, Kind: kind, Sink: f.module.evidence(kind, n), Dependencies: v.deps, Context: append([]analysis.Evidence{}, f.context...), Gaps: gaps, Assessment: analysis.Assessment{Status: "not_run"}})
}

// storeHardBlockers are the limits that still fix the outcome of a database
// package operation: the entry chain is not established, or the walk was cut.
var storeHardBlockers = map[string]bool{
	"unresolved_wrapper": true, "unresolved_handler": true, "unresolved_factory": true,
	"applicable_middleware_unresolved": true, "middleware_mount_unresolved": true,
	"work_limit": true, "dependency_limit": true, "gap_limit": true, "transfer_limit": true,
}

// judgeStoreLimits leaves the scanner's own reading limits of a database
// package operation to the decision model. The model has the source and four
// coverage questions for exactly this: whether the source, the library, the
// guards and the path are established. Each limit moves from the blockers to
// the coverage the model reads, and is listed as judged, so the policy never
// answers protected on it.
func judgeStoreLimits(c *analysis.Completeness) {
	if c == nil {
		return
	}
	var hard []analysis.Gap
	for _, g := range c.Blockers {
		if storeHardBlockers[g.Kind] {
			hard = append(hard, g)
			continue
		}
		c.Coverage = append(c.Coverage, g)
		c.Judged = append(c.Judged, g)
	}
	c.Blockers = hard
}
