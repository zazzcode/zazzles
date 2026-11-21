package langphp

import (
	"strconv"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
)

// phpFunctionBindings records, once per source set, every declaration that
// takes an unqualified function name away from the PHP builtin.
type phpFunctionBindings struct {
	// declared holds the lower-cased namespace and name of each function declaration.
	declared map[string]bool
	// imported holds the file, namespace scope and alias of each `use function` clause.
	imported map[string]bool
}

func phpFunctionKey(namespace, name string) string {
	return strings.ToLower(namespace + "\x00" + name)
}

func phpImportKey(file string, scopeStart uint, alias string) string {
	return file + "\x00" + strconv.FormatUint(uint64(scopeStart), 10) + "\x00" + strings.ToLower(alias)
}

// functionBindings builds the function index on first use.
func (s *phpSet) functionBindings() *phpFunctionBindings {
	if s.functions != nil {
		return s.functions
	}
	x := s.classIndex()
	b := &phpFunctionBindings{declared: map[string]bool{}, imported: map[string]bool{}}
	for _, file := range s.files {
		m := s.modules[file]
		if m == nil {
			continue
		}
		phpWalk(m.tree.RootNode(), func(n *sitter.Node) {
			switch n.Kind() {
			case "function_definition":
				b.declared[phpFunctionKey(x.scopeAt(m, n.StartByte()).namespace, phpText(m, phpField(n, "name")))] = true
			case "namespace_use_declaration":
				start := x.scopeAt(m, n.StartByte()).start
				for alias := range phpFunctionImports(m, n) {
					b.imported[phpImportKey(file, start, alias)] = true
				}
			}
		})
	}
	s.functions = b
	return b
}

// phpDeserializationBuiltin reports whether an unqualified or fully qualified
// callee names the PHP builtin: no function of that name is declared in the
// call's namespace and none is imported into its namespace scope.
func (s *phpSet) phpDeserializationBuiltin(m *phpModule, callee *sitter.Node) bool {
	name := phpText(m, callee)
	if strings.HasPrefix(name, `\`) {
		return !strings.Contains(strings.TrimPrefix(name, `\`), `\`)
	}
	if callee.Kind() != "name" {
		return false
	}
	scope := s.classIndex().scopeAt(m, callee.StartByte())
	b := s.functionBindings()
	return !b.declared[phpFunctionKey(scope.namespace, name)] && !b.imported[phpImportKey(m.file, scope.start, name)]
}

// phpFunctionImports returns the lower-cased aliases one use declaration
// imports as functions.
func phpFunctionImports(m *phpModule, declaration *sitter.Node) map[string]string {
	names := map[string]string{}
	group := phpField(declaration, "body")
	parent := declaration
	if group != nil {
		parent = group
	}
	for i := uint(0); i < parent.NamedChildCount(); i++ {
		clause := parent.NamedChild(i)
		if clause.Kind() != "namespace_use_clause" {
			continue
		}
		kind := phpField(clause, "type")
		if kind == nil {
			kind = phpField(declaration, "type")
		}
		if kind == nil || kind.Kind() != "function" {
			continue
		}
		phpUseClause(m, clause, "", names)
	}
	return names
}

func (f *phpFlow) phpSymfonyYAML(scope *sitter.Node) bool {
	if scope == nil || scope.Kind() != "name" && scope.Kind() != "qualified_name" {
		return false
	}
	x := f.set.classIndex()
	class := x.qualify(f.module, phpText(f.module, scope), scope.StartByte())
	return strings.EqualFold(class, symfonyYAMLClass) && len(x.byName[strings.ToLower(class)]) == 0
}
