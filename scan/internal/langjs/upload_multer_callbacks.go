package langjs

import (
	"regexp"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

// uploadCallback is a multer option callback (req, file, cb): the destination
// and filename options of diskStorage and the fileFilter option share this
// signature. derived holds, per client-supplied file field, the local names
// whose value is computed from that field.
type uploadCallback struct {
	fn         *sitter.Node
	file, done string
	derived    map[string]map[string]bool
}

var uploadClientFields = []string{"originalname", "mimetype"}

// uploadCallbackOf resolves an option value to a function this module
// defines: the function itself, or a name bound once to one.
func uploadCallbackOf(m *sourceModule, n *sitter.Node) *uploadCallback {
	n = unwrapTS(n)
	if n == nil {
		return nil
	}
	if n.Kind() == "identifier" {
		name := n.Utf8Text(m.src)
		if shadowed(n, name, m.src) || bindingReassigned(m, name) {
			return nil
		}
		if n = unwrapTS(topVariable(m, name)); n == nil {
			n = m.funcs[name]
		}
	}
	if n == nil || !isFunction(n) && n.Kind() != "function_declaration" {
		return nil
	}
	params := plainParameters(n, m.src)
	if len(params) != 3 || n.ChildByFieldName("body") == nil {
		return nil
	}
	cb := &uploadCallback{fn: n, file: params[1], done: params[2], derived: map[string]map[string]bool{}}
	for _, field := range uploadClientFields {
		cb.derived[field] = map[string]bool{}
	}
	for changed := true; changed; {
		changed = false
		cb.walk(func(c *sitter.Node) {
			var target, value *sitter.Node
			switch c.Kind() {
			case "variable_declarator":
				target, value = c.ChildByFieldName("name"), c.ChildByFieldName("value")
			case "assignment_expression":
				target, value = c.ChildByFieldName("left"), c.ChildByFieldName("right")
			}
			if target == nil || value == nil {
				return
			}
			if target.Kind() == "object_pattern" && value.Kind() == "identifier" && value.Utf8Text(m.src) == cb.file {
				// const { originalname } = file
				for i := uint(0); i < target.NamedChildCount(); i++ {
					p := target.NamedChild(i)
					if set := cb.derived[p.Utf8Text(m.src)]; p.Kind() == "shorthand_property_identifier_pattern" && set != nil && !set[p.Utf8Text(m.src)] {
						set[p.Utf8Text(m.src)], changed = true, true
					}
				}
				return
			}
			if target.Kind() != "identifier" {
				return
			}
			for _, field := range uploadClientFields {
				if name := target.Utf8Text(m.src); !cb.derived[field][name] && cb.mentions(m, value, field) {
					cb.derived[field][name], changed = true, true
				}
			}
		})
	}
	return cb
}

func (cb *uploadCallback) walk(visit func(*sitter.Node)) {
	var walk func(*sitter.Node)
	walk = func(n *sitter.Node) {
		visit(n)
		for i := uint(0); i < n.NamedChildCount(); i++ {
			walk(n.NamedChild(i))
		}
	}
	walk(cb.fn.ChildByFieldName("body"))
}

// mentions reports whether n reads the client-supplied field of the file
// parameter, directly or through a local name computed from it.
func (cb *uploadCallback) mentions(m *sourceModule, n *sitter.Node, field string) bool {
	if n == nil {
		return false
	}
	switch n.Kind() {
	case "member_expression":
		obj, prop := n.ChildByFieldName("object"), n.ChildByFieldName("property")
		if obj != nil && prop != nil && obj.Kind() == "identifier" && obj.Utf8Text(m.src) == cb.file && prop.Utf8Text(m.src) == field {
			return true
		}
	case "identifier":
		return cb.derived[field][n.Utf8Text(m.src)]
	}
	for i := uint(0); i < n.NamedChildCount(); i++ {
		if cb.mentions(m, n.NamedChild(i), field) {
			return true
		}
	}
	return false
}

// firstRead returns the first read of file.<field> in the callback.
func (cb *uploadCallback) firstRead(m *sourceModule, field string) *sitter.Node {
	var found *sitter.Node
	cb.walk(func(n *sitter.Node) {
		if found != nil || n.Kind() != "member_expression" {
			return
		}
		obj, prop := n.ChildByFieldName("object"), n.ChildByFieldName("property")
		if obj != nil && prop != nil && obj.Kind() == "identifier" && obj.Utf8Text(m.src) == cb.file && prop.Utf8Text(m.src) == field {
			found = n
		}
	})
	return found
}

// results returns the second argument of each call of the callback's cb
// parameter: the directory, the stored name or the accept decision.
func (cb *uploadCallback) results(m *sourceModule) []*sitter.Node {
	var out []*sitter.Node
	cb.walk(func(n *sitter.Node) {
		if n.Kind() != "call_expression" {
			return
		}
		fn, args := n.ChildByFieldName("function"), n.ChildByFieldName("arguments")
		if fn == nil || args == nil || fn.Kind() != "identifier" || fn.Utf8Text(m.src) != cb.done {
			return
		}
		if r := jsArgument(args, 1); r != nil {
			out = append(out, r)
		}
	})
	return out
}

type uploadCondition struct {
	kind string
	at   analysis.Evidence
}

// conditions returns the tests in the callback that read a client-supplied
// file field: each if and conditional-expression test and, for a fileFilter,
// each computed accept decision. A test of the declared MIME type is a
// client_declared_type control. A test of the client name against a literal
// (a regular expression, a string or a list) is an extension_allow_list
// control; without a literal the test compares the name with nothing fixed.
func (cb *uploadCallback) conditions(m *sourceModule, filter bool) []uploadCondition {
	var tests []*sitter.Node
	cb.walk(func(n *sitter.Node) {
		if n.Kind() == "if_statement" || n.Kind() == "ternary_expression" {
			if c := n.ChildByFieldName("condition"); c != nil {
				tests = append(tests, c)
			}
		}
	})
	if filter {
		for _, r := range cb.results(m) {
			if k := unwrapTS(r).Kind(); k != "true" && k != "false" && k != "identifier" {
				tests = append(tests, r)
			}
		}
	}
	var out []uploadCondition
	for _, test := range tests {
		at := m.evidence("branch_precondition", test)
		if cb.mentions(m, test, "mimetype") {
			out = append(out, uploadCondition{analysis.UploadClientDeclaredType, at})
		}
		if cb.mentions(m, test, "originalname") && containsLiteral(test) {
			out = append(out, uploadCondition{analysis.UploadExtensionAllowList, at})
		}
	}
	return out
}

func containsLiteral(n *sitter.Node) bool {
	switch n.Kind() {
	case "regex", "string", "array":
		return true
	}
	for i := uint(0); i < n.NamedChildCount(); i++ {
		if containsLiteral(n.NamedChild(i)) {
			return true
		}
	}
	return false
}

var uploadExtension = regexp.MustCompile(`\.[A-Za-z0-9]{1,8}$`)

// storedName classifies the name a filename callback passes on, and the
// origin of its extension, which is the last piece of the name.
func (cb *uploadCallback) storedName(m *sourceModule, name *sitter.Node) (stored, extension string) {
	name = unwrapTS(name)
	client := cb.mentions(m, name, "originalname")
	switch {
	case !client && !cb.mentions(m, name, "mimetype"):
		stored = "server_generated"
	case cb.clientName(m, name):
		stored = "client"
	case pathCall(m, name, "basename") && name.ChildByFieldName("arguments").NamedChildCount() == 1 && cb.clientName(m, name.ChildByFieldName("arguments").NamedChild(0)):
		// path.basename keeps the last component, extension included.
		stored = "client_basename"
	default:
		stored = "mixed"
	}
	pieces := concatenated(name, m.src)
	tail := pieces[len(pieces)-1]
	if tail.Kind() == "string" || tail.Kind() == "string_fragment" {
		text := tail.Utf8Text(m.src)
		if tail.Kind() == "string" {
			text, _ = stringLiteral(tail, m.src)
		}
		if uploadExtension.MatchString(text) {
			return stored, "fixed"
		}
		return stored, "unknown"
	}
	value := tail
	if tail.Kind() == "identifier" {
		// A local name bound once in the callback stands for its value.
		if v := singleDeclaration(tail.Utf8Text(m.src), cb.fn, m.src); v != nil {
			value = unwrapTS(v)
		}
	}
	switch {
	case literalTableLookup(m, value):
		// The extension is one of the table's literal values, whatever key the
		// client sends.
		return stored, "allow_listed"
	case cb.mentions(m, tail, "originalname") || cb.mentions(m, tail, "mimetype"):
		return stored, "client"
	}
	return stored, "unknown"
}

func (cb *uploadCallback) clientName(m *sourceModule, n *sitter.Node) bool {
	n = unwrapTS(n)
	if n == nil || n.Kind() != "member_expression" {
		return false
	}
	obj, prop := n.ChildByFieldName("object"), n.ChildByFieldName("property")
	return obj != nil && prop != nil && obj.Kind() == "identifier" && obj.Utf8Text(m.src) == cb.file && prop.Utf8Text(m.src) == "originalname"
}

// concatenated returns the pieces of a + concatenation or a template string
// in source order; any other expression is its own single piece.
func concatenated(n *sitter.Node, src []byte) []*sitter.Node {
	n = unwrapTS(n)
	switch n.Kind() {
	case "binary_expression":
		if op := n.ChildByFieldName("operator"); op != nil && op.Utf8Text(src) == "+" {
			return append(concatenated(n.ChildByFieldName("left"), src), concatenated(n.ChildByFieldName("right"), src)...)
		}
	case "template_string":
		var out []*sitter.Node
		for i := uint(0); i < n.NamedChildCount(); i++ {
			c := n.NamedChild(i)
			if c.Kind() == "template_substitution" && c.NamedChildCount() == 1 {
				out = append(out, concatenated(c.NamedChild(0), src)...)
			} else {
				out = append(out, c)
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	return []*sitter.Node{n}
}

// literalTableLookup reports a subscript of a module constant bound to an
// object literal whose values are all string literals.
func literalTableLookup(m *sourceModule, n *sitter.Node) bool {
	if n == nil || n.Kind() != "subscript_expression" {
		return false
	}
	obj := n.ChildByFieldName("object")
	if obj == nil || obj.Kind() != "identifier" || shadowed(n, obj.Utf8Text(m.src), m.src) || bindingReassigned(m, obj.Utf8Text(m.src)) {
		return false
	}
	table := unwrapTS(topVariable(m, obj.Utf8Text(m.src)))
	if table == nil || table.Kind() != "object" || table.NamedChildCount() == 0 {
		return false
	}
	for i := uint(0); i < table.NamedChildCount(); i++ {
		p := table.NamedChild(i)
		if v := p.ChildByFieldName("value"); p.Kind() != "pair" || v == nil || v.Kind() != "string" {
			return false
		}
	}
	return true
}

// pathCall reports a call of member of Node's path module.
func pathCall(m *sourceModule, n *sitter.Node, member string) bool {
	return libraryCall(m, n, "path", member) || libraryCall(m, n, "node:path", member)
}
