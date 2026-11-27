package langpy

import (
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/parse"
)

// SQL text built by a join, returned by a helper or held in another module
// (specification 21 follow-up). Only the shape of the code is read: a str method
// that joins parts, a function or method defined in the scanned source, a name
// imported from another scanned file. What cannot be read stays a hole.

// sqlTextWork bounds the reading of one text argument and records the
// definitions the reading followed, so the record can carry their source.
type sqlTextWork struct {
	budget int
	refs   []sqlRef
}

type sqlRef struct {
	module *pythonModule
	node   *sitter.Node
}

const sqlListLimit = 64

func sqlAllHole(p []parse.SQLTextPiece) bool {
	for _, x := range p {
		if !x.Hole {
			return false
		}
	}
	return true
}

// sqlIn returns a copy of the flow that reads nodes of module m.
func (f *pythonFlow) sqlIn(m *pythonModule) *pythonFlow {
	c := *f
	c.module = m
	return &c
}

func (f *pythonFlow) sqlRef(m *pythonModule, n *sitter.Node) {
	if f.sqlWork == nil || n == nil {
		return
	}
	if p := n.Parent(); p != nil && p.Kind() == "assignment" {
		n = p
	}
	f.sqlWork.refs = append(f.sqlWork.refs, sqlRef{m, n})
}

// sqlJoinPieces reads sep.join(parts): the pieces of each element in order with
// the separator's pieces between them. A parts argument that is not a list or
// tuple written out, or a list variable built in the same scope, is one hole.
func (f *pythonFlow) sqlJoinPieces(n, fnn *sitter.Node, hops int) ([]parse.SQLTextPiece, bool, bool) {
	if fnn == nil || fnn.Kind() != "attribute" || pyText(f.module, fnn.ChildByFieldName("attribute")) != "join" {
		return nil, false, false
	}
	args := n.ChildByFieldName("arguments")
	if args == nil || args.NamedChildCount() != 1 || args.NamedChild(0).Kind() == "keyword_argument" {
		return nil, false, false
	}
	sep, dynamic := f.sqlPieces(fnn.ChildByFieldName("object"), hops)
	elems := f.sqlListElements(args.NamedChild(0), hops, 0)
	var pieces []parse.SQLTextPiece
	for i, e := range elems {
		if i > 0 {
			pieces = append(pieces, sep...)
		}
		if e == nil {
			pieces = append(pieces, parse.SQLTextPiece{Hole: true})
			dynamic = true
			continue
		}
		p, d := f.sqlPieces(e, hops)
		pieces = append(pieces, p...)
		dynamic = dynamic || d
	}
	return pieces, dynamic, true
}

// sqlListElements returns the elements of a list expression; a nil element is a
// part the scanner cannot read.
func (f *pythonFlow) sqlListElements(n *sitter.Node, hops, level int) []*sitter.Node {
	n = sqlTextUnwrap(n)
	if n == nil {
		return []*sitter.Node{nil}
	}
	switch n.Kind() {
	case "list", "tuple", "set":
		var out []*sitter.Node
		for i := uint(0); i < n.NamedChildCount(); i++ {
			c := n.NamedChild(i)
			switch {
			case c.Kind() == "comment":
			case len(out) >= sqlListLimit:
				return append(out, nil)
			case strings.Contains(c.Kind(), "splat"):
				out = append(out, nil)
			default:
				out = append(out, c)
			}
		}
		return out
	case "identifier":
		if hops >= 2 || level >= 2 {
			return []*sitter.Node{nil}
		}
		return f.sqlListVariable(n, hops, level)
	}
	return []*sitter.Node{nil}
}

// sqlListVariable follows a list variable to its last literal assignment in a
// scope and the append, extend, insert and += that follow it before the use.
func (f *pythonFlow) sqlListVariable(id *sitter.Node, hops, level int) []*sitter.Node {
	name := pyText(f.module, id)
	for scope := sqlScopeOf(id); scope != nil; scope = sqlScopeOf(scope) {
		module := scope.Kind() == "module"
		key := sqlAssignKey{scope.Id(), "\x00list:" + name}
		all, cached := f.sqlAssign[key]
		if !cached {
			all = f.sqlCollectListSteps(scope, name)
			f.sqlAssign[key] = all
		}
		var steps []sqlAssignStep
		for _, s := range all {
			if module || s.end <= id.StartByte() {
				steps = append(steps, s)
			}
		}
		last := -1
		for i, s := range steps {
			if s.op == "set" {
				last = i
			}
		}
		if last >= 0 {
			var out []*sitter.Node
			for _, s := range steps[last:] {
				switch s.op {
				case "set", "add", "extend":
					out = append(out, f.sqlListElements(s.value, hops, level+1)...)
				case "append":
					out = append(out, s.value)
				default:
					out = append(out, nil)
				}
				if len(out) > sqlListLimit {
					return append(out[:sqlListLimit], nil)
				}
			}
			return out
		}
		if scope.Kind() == "function_definition" && sqlParamNamed(f.module, scope, name) {
			break
		}
	}
	return []*sitter.Node{nil}
}

// sqlCollectListSteps lists, in source order, what is done to the list variable
// name directly in scope (not in nested functions, classes or lambdas).
func (f *pythonFlow) sqlCollectListSteps(scope *sitter.Node, name string) []sqlAssignStep {
	m := f.module
	var steps []sqlAssignStep
	count := 0
	var walk func(x *sitter.Node)
	walk = func(x *sitter.Node) {
		if x == nil || count > 4000 {
			return
		}
		count++
		switch x.Kind() {
		case "function_definition", "class_definition", "lambda":
			if x.Id() != scope.Id() {
				return
			}
		case "assignment":
			l := x.ChildByFieldName("left")
			if l != nil && l.Kind() == "identifier" && pyText(m, l) == name {
				if r := x.ChildByFieldName("right"); r != nil {
					steps = append(steps, sqlAssignStep{value: r, end: x.EndByte(), op: "set"})
				}
			}
		case "augmented_assignment":
			l := x.ChildByFieldName("left")
			if l != nil && l.Kind() == "identifier" && pyText(m, l) == name && pyText(m, x.ChildByFieldName("operator")) == "+=" {
				if r := x.ChildByFieldName("right"); r != nil {
					steps = append(steps, sqlAssignStep{value: r, end: x.EndByte(), op: "add"})
				}
			}
		case "call":
			fn := x.ChildByFieldName("function")
			if fn != nil && fn.Kind() == "attribute" {
				if o := fn.ChildByFieldName("object"); o != nil && o.Kind() == "identifier" && pyText(m, o) == name {
					op := pyText(m, fn.ChildByFieldName("attribute"))
					args := x.ChildByFieldName("arguments")
					switch {
					case (op == "append" || op == "extend") && args != nil && args.NamedChildCount() == 1:
						steps = append(steps, sqlAssignStep{value: args.NamedChild(0), end: x.EndByte(), op: op})
					case op == "insert":
						steps = append(steps, sqlAssignStep{end: x.EndByte(), op: op})
					}
				}
			}
		}
		for i := uint(0); i < x.NamedChildCount(); i++ {
			walk(x.NamedChild(i))
		}
	}
	walk(scope)
	return steps
}

// sqlParamNamed reports a parameter of the function with the given name.
func sqlParamNamed(m *pythonModule, fn *sitter.Node, name string) bool {
	params := fn.ChildByFieldName("parameters")
	for i := uint(0); params != nil && i < params.NamedChildCount(); i++ {
		p := params.NamedChild(i)
		id := p
		if p.Kind() != "identifier" {
			id = p.ChildByFieldName("name")
			if id == nil && p.NamedChildCount() > 0 {
				id = p.NamedChild(0)
			}
		}
		if id != nil && id.Kind() == "identifier" && pyText(m, id) == name {
			return true
		}
	}
	return false
}

// sqlReturnsOf lists the return expressions of a function (nil for a bare
// return), not those of nested functions, classes or lambdas.
func (f *pythonFlow) sqlReturnsOf(fn *sitter.Node) []*sitter.Node {
	if f.sqlReturns == nil {
		f.sqlReturns = map[uintptr][]*sitter.Node{}
	}
	if r, ok := f.sqlReturns[fn.Id()]; ok {
		return r
	}
	var out []*sitter.Node
	count := 0
	var walk func(x *sitter.Node)
	walk = func(x *sitter.Node) {
		if x == nil || count > 4000 {
			return
		}
		count++
		switch x.Kind() {
		case "function_definition", "class_definition", "lambda":
			if x.Id() != fn.Id() {
				return
			}
		case "return_statement":
			var e *sitter.Node
			for i := uint(0); i < x.NamedChildCount(); i++ {
				if c := x.NamedChild(i); c.Kind() != "comment" {
					e = c
					break
				}
			}
			out = append(out, e)
			return
		}
		for i := uint(0); i < x.NamedChildCount(); i++ {
			walk(x.NamedChild(i))
		}
	}
	walk(fn)
	f.sqlReturns[fn.Id()] = out
	return out
}

// sqlHelperPieces follows a call of a function or method defined in the scanned
// source into its return expressions, one helper level. The helper's parameters
// are holes. The pieces of the first return that is SQL statement text are
// used; a helper with one return that is not statement text gives that return
// (it may be a clause of a larger statement); otherwise the call is not read.
func (f *pythonFlow) sqlHelperPieces(n *sitter.Node, hops int) ([]parse.SQLTextPiece, bool, bool) {
	if f.sqlDepth >= 1 {
		return nil, false, false
	}
	mod, fn := f.sqlHelperDef(n)
	if fn == nil {
		return nil, false, false
	}
	rets := f.sqlReturnsOf(fn)
	if len(rets) == 0 {
		return nil, false, false
	}
	c := f.sqlIn(mod)
	c.sqlDepth = f.sqlDepth + 1
	for _, r := range rets {
		if r == nil {
			continue
		}
		p, d := c.sqlReturnPieces(r)
		if parse.SQLStatementText(p).Matched || (len(rets) == 1 && !sqlAllHole(p)) {
			f.sqlRef(mod, fn)
			return p, d, true
		}
	}
	return nil, false, false
}

// sqlReturnPieces reads a returned expression. A method call that is not a
// builder is taken for an operation the helper performs, not for text.
func (f *pythonFlow) sqlReturnPieces(r *sitter.Node) ([]parse.SQLTextPiece, bool) {
	if r.Kind() == "call" && !f.sqlBuilderCall(r) {
		if fnn := r.ChildByFieldName("function"); fnn != nil && fnn.Kind() == "attribute" {
			return []parse.SQLTextPiece{{Hole: true}}, true
		}
	}
	return f.sqlPieces(r, 0)
}

// sqlHelperDef finds the function a call names in the scanned source: a function
// defined in an enclosing function, a function of this or an imported module, a
// method reached by self or by its class.
func (f *pythonFlow) sqlHelperDef(n *sitter.Node) (*pythonModule, *sitter.Node) {
	fnn := n.ChildByFieldName("function")
	if fnn == nil {
		return nil, nil
	}
	switch fnn.Kind() {
	case "identifier":
		name := pyText(f.module, fnn)
		for scope := sqlScopeOf(n); scope != nil; scope = sqlScopeOf(scope) {
			if scope.Kind() != "function_definition" {
				continue
			}
			if def := sqlChildDef(f.module, pyBody(scope), name); def != nil {
				return f.module, def
			}
			if sqlParamNamed(f.module, scope, name) {
				return nil, nil
			}
		}
		if f.sqlDepth == 0 {
			if _, shadow := f.env[name]; shadow {
				return nil, nil
			}
		}
		target, key := f.set.resolve(f.module, name, 0)
		if target != nil && !strings.Contains(key, ".") && target.funcs[key] != nil && !f.set.staticInvalid[f.module.file+":"+name] && !f.set.staticInvalid[target.file+":"+key] {
			return target, target.funcs[key]
		}
	case "attribute":
		obj := fnn.ChildByFieldName("object")
		attr := pyText(f.module, fnn.ChildByFieldName("attribute"))
		if obj == nil || obj.Kind() != "identifier" {
			return nil, nil
		}
		if cls := f.sqlSelfClass(n, obj); cls != nil {
			return f.module, sqlChildDef(f.module, cls.ChildByFieldName("body"), attr)
		}
		for scope := sqlScopeOf(n); scope != nil; scope = sqlScopeOf(scope) {
			if scope.Kind() == "function_definition" && sqlParamNamed(f.module, scope, pyText(f.module, obj)) {
				return nil, nil
			}
		}
		target, key := f.set.resolve(f.module, pyText(f.module, fnn), 0)
		if target == nil {
			return nil, nil
		}
		parts := strings.Split(key, ".")
		switch {
		case len(parts) == 1 && target.funcs[key] != nil:
			return target, target.funcs[key]
		case len(parts) == 2:
			if cls := target.vars[parts[0]]; cls != nil && cls.Kind() == "class_definition" {
				return target, sqlChildDef(target, cls.ChildByFieldName("body"), parts[1])
			}
		}
	}
	return nil, nil
}

// sqlChildDef finds a function defined directly in a block (decorated or not).
func sqlChildDef(m *pythonModule, block *sitter.Node, name string) *sitter.Node {
	if block == nil {
		return nil
	}
	for i := uint(0); i < block.NamedChildCount(); i++ {
		c := block.NamedChild(i)
		if c.Kind() == "decorated_definition" {
			c = c.ChildByFieldName("definition")
		}
		if c != nil && c.Kind() == "function_definition" && pyText(m, c.ChildByFieldName("name")) == name {
			return c
		}
	}
	return nil
}

// sqlSelfClass returns the class of the method that holds n when obj is the
// first parameter of that method (self or cls by position, not by name).
func (f *pythonFlow) sqlSelfClass(n, obj *sitter.Node) *sitter.Node {
	var fn *sitter.Node
	for p := n.Parent(); p != nil; p = p.Parent() {
		if p.Kind() == "function_definition" {
			fn = p
			break
		}
	}
	if fn == nil {
		return nil
	}
	params := fn.ChildByFieldName("parameters")
	if params == nil || params.NamedChildCount() == 0 || params.NamedChild(0).Kind() != "identifier" || pyText(f.module, params.NamedChild(0)) != pyText(f.module, obj) {
		return nil
	}
	p := fn.Parent()
	if p != nil && p.Kind() == "decorated_definition" {
		p = p.Parent()
	}
	if p != nil && p.Kind() == "block" {
		p = p.Parent()
	}
	if p != nil && p.Kind() == "class_definition" {
		return p
	}
	return nil
}

// sqlImportedPieces follows a name imported from another scanned module.
func (f *pythonFlow) sqlImportedPieces(name string, hops int) ([]parse.SQLTextPiece, bool, bool) {
	if hops >= 2 || f.module.imports[name].node == nil {
		return nil, false, false
	}
	target, key := f.set.resolve(f.module, name, 0)
	if target == nil || target == f.module {
		return nil, false, false
	}
	return f.sqlModuleValue(target, key, hops)
}

// sqlModuleValue reads a module-level variable, or an attribute of a module
// level class, of the module target.
func (f *pythonFlow) sqlModuleValue(target *pythonModule, key string, hops int) ([]parse.SQLTextPiece, bool, bool) {
	parts := strings.Split(key, ".")
	switch len(parts) {
	case 1:
		v := target.vars[key]
		if v == nil || v.Kind() == "class_definition" {
			return nil, false, false
		}
		c := f.sqlIn(target)
		p, d := c.sqlPieces(v, hops+1)
		if !sqlAllHole(p) {
			f.sqlRef(target, v)
		}
		return p, d, true
	case 2:
		if cls := target.vars[parts[0]]; cls != nil && cls.Kind() == "class_definition" {
			return f.sqlClassAttr(target, cls, parts[1], hops)
		}
	}
	return nil, false, false
}

// sqlClassAttr reads a class attribute assigned in the body of the class.
func (f *pythonFlow) sqlClassAttr(m *pythonModule, cls *sitter.Node, attr string, hops int) ([]parse.SQLTextPiece, bool, bool) {
	body := cls.ChildByFieldName("body")
	for i := uint(0); body != nil && i < body.NamedChildCount(); i++ {
		s := body.NamedChild(i)
		if s.Kind() != "expression_statement" || s.NamedChildCount() != 1 || s.NamedChild(0).Kind() != "assignment" {
			continue
		}
		a := s.NamedChild(0)
		if l := a.ChildByFieldName("left"); l != nil && l.Kind() == "identifier" && pyText(m, l) == attr {
			r := a.ChildByFieldName("right")
			if r == nil {
				return nil, false, false
			}
			c := f.sqlIn(m)
			p, d := c.sqlPieces(r, hops+1)
			if !sqlAllHole(p) {
				f.sqlRef(m, r)
			}
			return p, d, true
		}
	}
	return nil, false, false
}

// sqlAttributePieces reads Name.attr and module.name for a class attribute or a
// constant of an imported module, and self.attr for a class attribute.
func (f *pythonFlow) sqlAttributePieces(n *sitter.Node, hops int) ([]parse.SQLTextPiece, bool) {
	hole := []parse.SQLTextPiece{{Hole: true}}
	obj := n.ChildByFieldName("object")
	if obj == nil || obj.Kind() != "identifier" {
		return hole, true
	}
	if cls := f.sqlSelfClass(n, obj); cls != nil {
		if p, d, ok := f.sqlClassAttr(f.module, cls, pyText(f.module, n.ChildByFieldName("attribute")), hops); ok {
			return p, d
		}
		return hole, true
	}
	root := pyText(f.module, obj)
	for scope := sqlScopeOf(n); scope != nil; scope = sqlScopeOf(scope) {
		if scope.Kind() == "function_definition" && sqlParamNamed(f.module, scope, root) {
			return hole, true
		}
	}
	target, key := f.set.resolve(f.module, pyText(f.module, n), 0)
	if target == nil {
		return hole, true
	}
	if p, d, ok := f.sqlModuleValue(target, key, hops); ok {
		return p, d
	}
	return hole, true
}

// sqlTextDefinitions returns the source of the definitions the reading of the
// text followed, when no context evidence of the record holds it: a
// referenced_definition for another place of the same file, a source excerpt for
// another file. The judge reads no file.
func (f *pythonFlow) sqlTextDefinitions(u *analysis.CandidateUse) []analysis.Evidence {
	if f.sqlWork == nil {
		return nil
	}
	var out []analysis.Evidence
	covered := func(sp analysis.Span) bool {
		for _, list := range [][]analysis.Evidence{u.Context, out} {
			for _, e := range list {
				switch e.Kind {
				case "handler", "invoked_callable", "helper_definition", "selected_callable", "validation_schema", "validation_control", "condition_helper", "referenced_definition", parse.SQLTextSourceExcerptKind:
					if e.Span.File == sp.File && e.Span.StartByte <= sp.StartByte && e.Span.EndByte >= sp.EndByte {
						return true
					}
				}
			}
		}
		return false
	}
	for _, r := range f.sqlWork.refs {
		sp := parse.Span(r.module.file, r.node)
		if covered(sp) {
			continue
		}
		if r.module.file == f.module.file {
			out = append(out, f.module.evidence("referenced_definition", r.node))
		} else if e, ok := parse.SQLTextExcerptEvidence(r.module.src, sp); ok {
			out = append(out, e)
		}
	}
	f.sqlWork = nil
	return out
}
