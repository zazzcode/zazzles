package parse

import (
	"path"
	"regexp"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
)

// prismaRawMethods are Prisma Client methods whose first argument is SQL text.
var prismaRawMethods = map[string]bool{"$queryRawUnsafe": true, "$executeRawUnsafe": true}

// sqlLibraryCall classifies a call against the Prisma raw and better-sqlite3
// contracts. The receiver must be a verified client binding; method names alone
// never qualify. Tagged-template $queryRaw is parameterized and is not returned.
func (s *moduleSet) sqlLibraryCall(m *sourceModule, call *sitter.Node) (contract, method string, binding []analysis.Evidence, ok bool) {
	fn := call.ChildByFieldName("function")
	args := call.ChildByFieldName("arguments")
	if fn == nil || fn.Kind() != "member_expression" || args == nil || args.Kind() != "arguments" {
		return "", "", nil, false
	}
	obj, prop := fn.ChildByFieldName("object"), fn.ChildByFieldName("property")
	if obj == nil || prop == nil || obj.Kind() != "identifier" {
		return "", "", nil, false
	}
	method = prop.Utf8Text(m.src)
	name := obj.Utf8Text(m.src)
	if prismaRawMethods[method] {
		if shadowed(call, name, m.src) {
			return "", "", nil, false
		}
		if b := s.prismaClient(m, name, 0); len(b) > 0 {
			return analysispacks.PrismaRawContract, method, append(b, m.evidence("sink_binding", call)), true
		}
		return "", "", nil, false
	}
	if b := s.pgliteCall(m, call, name, method); len(b) > 0 {
		return analysispacks.PGliteContract, method, append(b, m.evidence("sink_binding", call)), true
	}
	switch method {
	case "exec", "prepare", "pragma":
		if b := s.betterSQLite(m, call, name); len(b) > 0 {
			return analysispacks.BetterSQLite3Contract, method, append(b, m.evidence("sink_binding", call)), true
		}
	}
	return "", "", nil, false
}

// prismaClient verifies that name is a Prisma Client: constructed from a
// PrismaClient import (`@prisma/client` or the schema generator output), as
// `new PrismaClient()` or the `global.prisma ?? new PrismaClient()` singleton,
// in this module or through one named import hop.
func (s *moduleSet) prismaClient(m *sourceModule, name string, depth int) []analysis.Evidence {
	if depth > 2 {
		return nil
	}
	if imp, ok := m.imports[name]; ok && topVariable(m, name) == nil {
		if imp.name == "*" || imp.name == "default" {
			// `import prisma from "@/lib/prisma"` with `export default prisma`.
			if target := s.importModule(m, imp.module); target != nil && imp.name == "default" {
				if v := defaultExport(target); v != nil {
					if b := s.prismaConstruction(target, v); len(b) > 0 {
						return append([]analysis.Evidence{m.evidence("sink_binding", imp.declaration)}, b...)
					}
				}
			}
			return nil
		}
		target := s.importModule(m, imp.module)
		if target == nil || !exportedName(target, imp.name) || bindingReassigned(target, imp.name) {
			return nil
		}
		b := s.prismaClient(target, imp.name, depth+1)
		if len(b) == 0 {
			return nil
		}
		return append([]analysis.Evidence{m.evidence("sink_binding", imp.declaration)}, b...)
	}
	v := topVariable(m, name)
	if v == nil {
		return nil
	}
	return s.prismaConstruction(m, v)
}

func (s *moduleSet) prismaConstruction(m *sourceModule, v *sitter.Node) []analysis.Evidence {
	v = unwrapTS(v)
	if v == nil {
		return nil
	}
	if v.Kind() == "binary_expression" {
		if op := v.ChildByFieldName("operator"); op != nil && op.Utf8Text(m.src) == "??" {
			if right := unwrapTS(v.ChildByFieldName("right")); right != nil && right.Kind() == "new_expression" {
				v = right
			}
		}
	}
	if v.Kind() != "new_expression" {
		return nil
	}
	ctor := v.ChildByFieldName("constructor")
	if ctor == nil || ctor.Kind() != "identifier" {
		return nil
	}
	imp, ok := m.imports[ctor.Utf8Text(m.src)]
	if !ok || imp.name != "PrismaClient" {
		return nil
	}
	out := []analysis.Evidence{m.evidence("sink_binding", imp.declaration)}
	assignment := v
	for p := v.Parent(); p != nil; p = p.Parent() {
		if p.Kind() == "variable_declarator" {
			assignment = p
			break
		}
	}
	out = append(out, m.evidence("sink_binding", assignment))
	if imp.module == "@prisma/client" {
		return out
	}
	// A custom generator output: the import must resolve into the schema's
	// `output` directory. The generated client itself is usually not checked in.
	schema, output := s.prismaGeneratorOutput(m.file)
	if output == "" {
		return nil
	}
	spec := imp.module
	var resolved string
	if strings.HasPrefix(spec, ".") {
		resolved = path.Clean(path.Join(path.Dir(m.file), spec))
	} else if bases := s.aliasBases(m.file, spec); len(bases) > 0 {
		resolved = bases[0]
	}
	resolved = strings.TrimSuffix(strings.TrimSuffix(resolved, "/client"), "/index")
	if resolved != output {
		return nil
	}
	return append(out, schema)
}

var prismaGenerator = regexp.MustCompile(`(?s)generator\s+\w+\s*\{([^}]*)\}`)
var prismaOutput = regexp.MustCompile(`output\s*=\s*"([^"]+)"`)
var prismaProvider = regexp.MustCompile(`provider\s*=\s*"(prisma-client(?:-js)?)"`)

// prismaGeneratorOutput reads the nearest prisma/schema.prisma and returns its
// evidence and the client generator's output directory (scan-root relative).
func (s *moduleSet) prismaGeneratorOutput(file string) (analysis.Evidence, string) {
	for _, dir := range ancestorDirs(file) {
		schemaFile := joinDir(dir, "prisma/schema.prisma")
		e, ok := s.readBounded(schemaFile, 2<<20)
		if !ok {
			continue
		}
		for _, g := range prismaGenerator.FindAllStringSubmatch(e.Text, -1) {
			if !prismaProvider.MatchString(g[1]) {
				continue
			}
			out := prismaOutput.FindStringSubmatch(g[1])
			if out == nil {
				continue
			}
			e.Kind = "sink_binding"
			resolved := cleanRel(path.Join(path.Dir(schemaFile), out[1]))
			return e, resolved
		}
		return analysis.Evidence{}, ""
	}
	return analysis.Evidence{}, ""
}

// betterSQLite verifies `const db = new Database(...)` where Database is the
// default import of better-sqlite3, in the enclosing function or module.
func (s *moduleSet) betterSQLite(m *sourceModule, call *sitter.Node, name string) []analysis.Evidence {
	var ctor *sitter.Node
	count := 0
	scope := m.tree.RootNode()
	for p := call.Parent(); p != nil; p = p.Parent() {
		if isFunction(p) || p.Kind() == "function_declaration" {
			if d := declarationIn(p, name, m.src); d != nil {
				scope = p
				break
			}
		}
	}
	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		if n.Kind() == "variable_declarator" {
			if id := n.ChildByFieldName("name"); id != nil && id.Utf8Text(m.src) == name {
				count++
				ctor = unwrapTS(n.ChildByFieldName("value"))
			}
		}
		if n.Kind() == "assignment_expression" {
			if l := n.ChildByFieldName("left"); l != nil && l.Utf8Text(m.src) == name {
				count += 2
			}
		}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			visit(n.NamedChild(i))
		}
	}
	visit(scope)
	if count != 1 || ctor == nil || ctor.Kind() != "new_expression" {
		return nil
	}
	c := ctor.ChildByFieldName("constructor")
	if c == nil || c.Kind() != "identifier" {
		return nil
	}
	imp, ok := m.imports[c.Utf8Text(m.src)]
	if !ok || imp.module != "better-sqlite3" || (imp.name != "default" && imp.name != "*") {
		return nil
	}
	return []analysis.Evidence{m.evidence("sink_binding", imp.declaration), m.evidence("sink_binding", ctor.Parent())}
}

func declarationIn(fn *sitter.Node, name string, src []byte) *sitter.Node {
	var found *sitter.Node
	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		if found != nil {
			return
		}
		if n.Kind() == "variable_declarator" {
			if id := n.ChildByFieldName("name"); id != nil && id.Utf8Text(src) == name {
				found = n
				return
			}
		}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			visit(n.NamedChild(i))
		}
	}
	visit(fn)
	return found
}

// sqlLibraryBinding returns the verified binding and contract of a SQL use.
func (s *moduleSet) sqlLibraryBinding(use analysis.CandidateUse) ([]analysis.Evidence, string) {
	m := s.modules[use.Sink.Span.File]
	if m == nil {
		return nil, ""
	}
	call := nodeAt(m.tree.RootNode(), use.Sink.Span.StartByte, use.Sink.Span.EndByte)
	if call == nil || call.Kind() != "call_expression" {
		return nil, ""
	}
	contract, _, binding, ok := s.sqlLibraryCall(m, call)
	if !ok {
		return nil, ""
	}
	return binding, contract
}

// sqlStatementFact names the statement-count behavior of a better-sqlite3 call.
func (s *moduleSet) sqlStatementFact(use analysis.CandidateUse) string {
	m := s.modules[use.Sink.Span.File]
	if m == nil {
		return ""
	}
	call := nodeAt(m.tree.RootNode(), use.Sink.Span.StartByte, use.Sink.Span.EndByte)
	if call == nil {
		return ""
	}
	contract, method, _, ok := s.sqlLibraryCall(m, call)
	if !ok || (contract != analysispacks.BetterSQLite3Contract && contract != analysispacks.PGliteContract) {
		return ""
	}
	if method == "prepare" || (contract == analysispacks.PGliteContract && method == "query") {
		return "sql_single_statement"
	}
	return "sql_multi_statement"
}

var prismaFilterMethods = map[string]bool{"findUnique": true, "findUniqueOrThrow": true, "findFirst": true, "findFirstOrThrow": true, "findMany": true, "count": true, "update": true, "updateMany": true, "delete": true, "deleteMany": true, "upsert": true, "aggregate": true, "groupBy": true}

// prismaFilterCall verifies `client.<model>.<method>({ where: ... })` on a
// verified Prisma Client and returns the where object.
func (s *moduleSet) prismaFilterCall(m *sourceModule, call *sitter.Node) (*sitter.Node, []analysis.Evidence, bool) {
	fn := call.ChildByFieldName("function")
	args := call.ChildByFieldName("arguments")
	if fn == nil || fn.Kind() != "member_expression" || args == nil || args.Kind() != "arguments" || args.NamedChildCount() == 0 {
		return nil, nil, false
	}
	prop := fn.ChildByFieldName("property")
	model := fn.ChildByFieldName("object")
	if prop == nil || model == nil || !prismaFilterMethods[prop.Utf8Text(m.src)] || model.Kind() != "member_expression" {
		return nil, nil, false
	}
	client := model.ChildByFieldName("object")
	if client == nil || client.Kind() != "identifier" || shadowed(call, client.Utf8Text(m.src), m.src) {
		return nil, nil, false
	}
	opts := unwrapTS(args.NamedChild(0))
	if opts == nil || opts.Kind() != "object" {
		return nil, nil, false
	}
	where := property(opts, "where", m.src)
	if where == nil {
		return nil, nil, false
	}
	binding := s.prismaClient(m, client.Utf8Text(m.src), 0)
	if len(binding) == 0 {
		return nil, nil, false
	}
	return where, append(binding, m.evidence("sink_binding", call)), true
}

// unvalidatedBody reports a dependency on raw JSON request body data that no
// schema helper parsed: the only shape that can carry a Prisma filter object.
func (s *moduleSet) unvalidatedBody(v value) bool {
	for _, d := range v.deps {
		o, ok := s.webOriginFor(d.Source)
		if !ok || o.origin != "http.body" || o.initialType == "array" {
			continue
		}
		validated := false
		for _, t := range d.Transfers {
			validated = validated || t.Kind == "validated_parse"
		}
		if !validated {
			return true
		}
	}
	return false
}

// prismaFilterBinding returns the verified binding of a Prisma filter use.
func (s *moduleSet) prismaFilterBinding(use analysis.CandidateUse) []analysis.Evidence {
	m := s.modules[use.Sink.Span.File]
	if m == nil {
		return nil
	}
	call := nodeAt(m.tree.RootNode(), use.Sink.Span.StartByte, use.Sink.Span.EndByte)
	if call == nil || call.Kind() != "call_expression" {
		return nil
	}
	_, binding, ok := s.prismaFilterCall(m, call)
	if !ok {
		return nil
	}
	return binding
}
