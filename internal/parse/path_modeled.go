package parse

import (
	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
)

// pathModuleOps are the Node path operations modeled as transformations.
var pathModuleOps = map[string]bool{"join": true, "resolve": true, "normalize": true, "basename": true, "dirname": true, "extname": true, "relative": true, "isAbsolute": true}

func pathCoreModule(module string) bool {
	switch module {
	case "path", "node:path", "path/posix", "node:path/posix":
		return true
	}
	return false
}

// nodePathModuleOp returns the verified Node path operation of a call, if any.
func nodePathModuleOp(m *sourceModule, call *sitter.Node) (string, bool) {
	if call == nil || call.Kind() != "call_expression" {
		return "", false
	}
	fn := call.ChildByFieldName("function")
	if fn == nil {
		return "", false
	}
	switch fn.Kind() {
	case "identifier":
		name := fn.Utf8Text(m.src)
		imp, ok := m.imports[name]
		if !ok || !pathCoreModule(imp.module) || !pathModuleOps[imp.name] || shadowed(call, name, m.src) || bindingReassigned(m, name) {
			return "", false
		}
		return imp.name, true
	case "member_expression":
		obj, prop := fn.ChildByFieldName("object"), fn.ChildByFieldName("property")
		if obj == nil || prop == nil || !pathModuleOps[prop.Utf8Text(m.src)] {
			return "", false
		}
		op := prop.Utf8Text(m.src)
		if obj.Kind() == "member_expression" {
			// path.posix.join
			if p := obj.ChildByFieldName("property"); p == nil || p.Utf8Text(m.src) != "posix" {
				return "", false
			}
			obj = obj.ChildByFieldName("object")
			if obj == nil {
				return "", false
			}
		}
		switch obj.Kind() {
		case "identifier":
			name := obj.Utf8Text(m.src)
			imp, ok := m.imports[name]
			if !ok || !pathCoreModule(imp.module) || (imp.name != "*" && imp.name != "default") || shadowed(call, name, m.src) || bindingReassigned(m, name) {
				return "", false
			}
			return op, true
		case "call_expression":
			if p, member, ok := requireBinding(m, obj); ok && member == "*" && pathCoreModule(p) {
				return op, true
			}
		}
	}
	return "", false
}

// nodeDecodeCall reports an unshadowed global decode call.
func nodeDecodeCall(m *sourceModule, call *sitter.Node) bool {
	if call == nil || call.Kind() != "call_expression" {
		return false
	}
	fn := call.ChildByFieldName("function")
	if fn == nil || fn.Kind() != "identifier" {
		return false
	}
	switch fn.Utf8Text(m.src) {
	case "decodeURIComponent", "decodeURI", "unescape":
		name := fn.Utf8Text(m.src)
		if _, imported := m.imports[name]; imported || shadowed(call, name, m.src) || m.funcs[name] != nil || topVariable(m, name) != nil {
			return false
		}
		return true
	}
	return false
}

// nodeRealpathCall reports a verified fs realpath call.
func nodeRealpathCall(m *sourceModule, call *sitter.Node) bool {
	fn := call.ChildByFieldName("function")
	if fn == nil {
		return false
	}
	b, ok := fsMember(m, call, fn)
	return ok && (b.op == "realpathSync" || b.op == "realpath")
}

// constantPathValue reports an expression built only from literals, Node
// location globals and verified path operations over those: a trusted base.
func constantPathValue(m *sourceModule, n *sitter.Node, depth int) bool {
	if n == nil || depth > 6 {
		return false
	}
	switch n.Kind() {
	case "string", "number":
		return true
	case "template_string":
		for i := uint(0); i < n.NamedChildCount(); i++ {
			if c := n.NamedChild(i); c.Kind() == "template_substitution" {
				if c.NamedChildCount() == 0 || !constantPathValue(m, c.NamedChild(0), depth+1) {
					return false
				}
			}
		}
		return true
	case "parenthesized_expression", "as_expression", "non_null_expression":
		return n.NamedChildCount() > 0 && constantPathValue(m, n.NamedChild(0), depth+1)
	case "binary_expression":
		l, r := n.ChildByFieldName("left"), n.ChildByFieldName("right")
		return constantPathValue(m, l, depth+1) && constantPathValue(m, r, depth+1)
	case "identifier":
		name := n.Utf8Text(m.src)
		if name == "__dirname" || name == "__filename" {
			return !shadowed(n, name, m.src) && topVariable(m, name) == nil && m.funcs[name] == nil
		}
		if shadowed(n, name, m.src) || bindingReassigned(m, name) {
			return false
		}
		if v := topVariable(m, name); v != nil {
			return constantPathValue(m, v, depth+1)
		}
		return false
	case "member_expression":
		text := n.Utf8Text(m.src)
		return text == "path.sep" || text == "import.meta.dirname" || text == "import.meta.filename"
	case "call_expression":
		fn := n.ChildByFieldName("function")
		if fn != nil && fn.Utf8Text(m.src) == "process.cwd" {
			return true
		}
		if _, ok := nodePathModuleOp(m, n); !ok {
			return false
		}
		args := n.ChildByFieldName("arguments")
		for i := uint(0); args != nil && i < args.NamedChildCount(); i++ {
			if c := args.NamedChild(i); c.Kind() != "comment" && !constantPathValue(m, c, depth+1) {
				return false
			}
		}
		return true
	case "array", "object":
		return false
	}
	return false
}

// constantCollection reports an array, Set or object literal made only of string
// literals: a finite set of trusted constant identities.
func constantCollection(m *sourceModule, name string) bool {
	if shadowedAnywhere(m, name) || bindingReassigned(m, name) {
		return false
	}
	v := topVariable(m, name)
	if v == nil {
		return false
	}
	if v.Kind() == "new_expression" {
		ctor, args := v.ChildByFieldName("constructor"), v.ChildByFieldName("arguments")
		if ctor == nil || ctor.Utf8Text(m.src) != "Set" || args == nil || args.NamedChildCount() != 1 {
			return false
		}
		v = args.NamedChild(0)
	}
	switch v.Kind() {
	case "array":
		for i := uint(0); i < v.NamedChildCount(); i++ {
			if c := v.NamedChild(i); c.Kind() != "string" && c.Kind() != "comment" {
				return false
			}
		}
		return v.NamedChildCount() > 0
	case "object":
		count := 0
		for i := uint(0); i < v.NamedChildCount(); i++ {
			c := v.NamedChild(i)
			if c.Kind() == "comment" {
				continue
			}
			key := c.ChildByFieldName("key")
			if c.Kind() != "pair" || key == nil || (key.Kind() != "string" && key.Kind() != "property_identifier") {
				return false
			}
			count++
		}
		return count > 0
	}
	return false
}

// shadowedAnywhere reports a local declaration of name anywhere in the module
// other than at top level: a conservative check that a module constant is not
// rebound by a nested scope.
func shadowedAnywhere(m *sourceModule, name string) bool {
	found := false
	var walk func(*sitter.Node, bool)
	walk = func(n *sitter.Node, top bool) {
		if found {
			return
		}
		if n.Kind() == "variable_declarator" && !top {
			if id := n.ChildByFieldName("name"); id != nil && id.Kind() == "identifier" && id.Utf8Text(m.src) == name {
				found = true
				return
			}
		}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			walk(n.NamedChild(i), top && (n.Kind() == "program" || n.Kind() == "lexical_declaration" || n.Kind() == "variable_declaration" || n.Kind() == "export_statement"))
		}
	}
	walk(m.tree.RootNode(), true)
	return found
}

// coreModuleReference reports an identifier or member (`fs.promises`, `path.sep`)
// that names a verified Node fs or path module binding. Referring to a module is
// not a value dependency.
func coreModuleReference(m *sourceModule, n *sitter.Node) bool {
	switch n.Kind() {
	case "identifier":
		name := n.Utf8Text(m.src)
		imp, ok := m.imports[name]
		if !ok || shadowed(n, name, m.src) || bindingReassigned(m, name) {
			return false
		}
		core, _ := fsCoreModule(imp.module)
		return core || pathCoreModule(imp.module)
	case "member_expression":
		obj, prop := n.ChildByFieldName("object"), n.ChildByFieldName("property")
		if obj == nil || prop == nil {
			return false
		}
		switch prop.Utf8Text(m.src) {
		case "promises", "sep", "posix":
			return coreModuleReference(m, obj)
		}
	}
	return false
}

// responseMethods are the Express-style methods that emit a response.
var responseMethods = map[string]bool{"send": true, "json": true, "end": true, "write": true, "render": true, "sendFile": true, "download": true, "redirect": true, "jsonp": true, "sendStatus": true}

// responseEmission reports a call of a response method on a parameter of an
// enclosing function: the consumer of a result, never a path operand.
func responseEmission(m *sourceModule, call *sitter.Node) bool {
	fn := call.ChildByFieldName("function")
	if fn == nil || fn.Kind() != "member_expression" {
		return false
	}
	obj, prop := fn.ChildByFieldName("object"), fn.ChildByFieldName("property")
	if obj == nil || prop == nil || obj.Kind() != "identifier" || !responseMethods[prop.Utf8Text(m.src)] {
		return false
	}
	name := obj.Utf8Text(m.src)
	for p := call.Parent(); p != nil; p = p.Parent() {
		params := p.ChildByFieldName("parameters")
		for i := uint(0); params != nil && i < params.NamedChildCount(); i++ {
			param := params.NamedChild(i)
			if param.Kind() == "required_parameter" || param.Kind() == "optional_parameter" {
				param = param.ChildByFieldName("pattern")
			}
			if param != nil && param.Kind() == "identifier" && param.Utf8Text(m.src) == name {
				return true
			}
		}
	}
	return false
}

// pathModeledGap reports a gap that does not concern the path operand: a verified
// module reference, a modeled path/decode/realpath call or the call that consumes
// the file result (a separate response claim).
func (s *moduleSet) pathModeledGap(u *analysis.CandidateUse, g analysis.Gap) bool {
	switch g.Kind {
	case "unknown_value", "unknown_call_result", "unknown_transfer", "input_helper_unresolved":
	default:
		return false
	}
	m := s.modules[g.At.File]
	if m == nil {
		return false
	}
	n := nodeAt(m.tree.RootNode(), g.At.StartByte, g.At.EndByte)
	if n == nil {
		return false
	}
	if coreModuleReference(m, n) {
		return true
	}
	if g.Kind == "input_helper_unresolved" && n.Kind() == "call_expression" && g.At.File == u.Sink.Span.File && g.At.StartByte <= u.Sink.Span.StartByte && g.At.EndByte >= u.Sink.Span.EndByte && g.At != u.Sink.Span {
		return true
	}
	if n.Kind() == "call_expression" {
		if _, ok := nodePathModuleOp(m, n); ok || nodeDecodeCall(m, n) || nodeRealpathCall(m, n) {
			return true
		}
		if g.Kind == "input_helper_unresolved" && responseEmission(m, n) {
			return true
		}
	}
	return false
}

// pathGapCovered decides whether a discovery gap leaves the path claim intact.
// A gap on a modeled path transformation, a module reference, a constant trusted
// base or the consumer of the file result is covered; every other gap on the
// operand path stays a blocker.
func (s *moduleSet) pathGapCovered(u *analysis.CandidateUse, g analysis.Gap, controlComplete bool, complete, transforms []analysis.Evidence, extra map[string][]analysis.Evidence) bool {
	if s.pathModeledGap(u, g) {
		if m := s.modules[g.At.File]; m != nil {
			if n := nodeAt(m.tree.RootNode(), g.At.StartByte, g.At.EndByte); n != nil && n.Kind() == "call_expression" && s.touchesAnyDependency(g, *u) {
				extra["transformation"] = append(extra["transformation"], m.evidence("transformation", n))
			}
		}
		return true
	}
	switch g.Kind {
	case "unknown_value", "unknown_call_result", "unknown_transfer":
		if m := s.modules[g.At.File]; m != nil && s.touchesAnyDependency(g, *u) {
			if n := nodeAt(m.tree.RootNode(), g.At.StartByte, g.At.EndByte); n != nil && constantPathValue(m, n, 0) {
				extra["constant_base"] = append(extra["constant_base"], m.evidence("constant_base", n))
				return true
			}
		}
	}
	return s.commandGapCovered(u, g, controlComplete, complete, transforms, extra)
}
