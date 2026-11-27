package langphp

import (
	"regexp"
	"sort"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/parse"
)

// Text the hook follows beyond one expression (specification 21, follow-up): a
// join of a list, text returned by a function or method of the scanned source,
// a constant (define, const, class constant) and a heredoc. Everything is
// syntax: a part that cannot be read as literal text is a hole.

const (
	// sqlTextHelperHops is the number of function or method bodies followed from
	// the text argument; the identifier hops inside a body are bounded by the
	// expression depth.
	sqlTextHelperHops = 1
	// sqlTextSyntaxWork bounds the expressions read for one text argument.
	sqlTextSyntaxWork = 400
	// sqlTextListMax bounds the elements of a joined list.
	sqlTextListMax = 64
	// sqlTextReturnMax bounds the return expressions read in one function.
	sqlTextReturnMax = 8
)

// sqlTextDef is a definition (function, method or constant declaration) the
// text of an argument was read from.
type sqlTextDef struct {
	module *phpModule
	node   *sitter.Node
}

// sqlTextRead is the per-argument state of one syntax read.
type sqlTextRead struct {
	hops int
	work int
	defs []sqlTextDef
}

func (f *phpFlow) sqlTextRootRead(m *phpModule, n *sitter.Node, before uint) ([]parse.SQLTextPiece, []sqlTextDef) {
	st := f.set.sqlTextStateInit()
	prev := st.read
	st.read = &sqlTextRead{}
	defer func() { st.read = prev }()
	pieces := f.sqlTextSyntax(m, n, before, 0)
	return pieces, st.read.defs
}

func (st *sqlTextState) addDef(m *phpModule, n *sitter.Node) {
	if st.read == nil || n == nil {
		return
	}
	for _, d := range st.read.defs {
		if d.module == m && d.node.StartByte() == n.StartByte() && d.node.EndByte() == n.EndByte() {
			return
		}
	}
	st.read.defs = append(st.read.defs, sqlTextDef{module: m, node: n})
}

var sqlTextFormatRe = regexp.MustCompile(`%%|%(?:\d+\$)?[-+ 0]*(?:'.)?\d*(?:\.\d+)?[bcdeEfFgGosuxX]`)

// sqlTextFormatPieces turns the literal pieces of a printf format into text
// with a hole for each conversion.
func sqlTextFormatPieces(in []parse.SQLTextPiece) []parse.SQLTextPiece {
	var out []parse.SQLTextPiece
	for _, p := range in {
		if p.Hole {
			out = append(out, p)
			continue
		}
		last := 0
		for _, loc := range sqlTextFormatRe.FindAllStringIndex(p.Text, -1) {
			if loc[0] > last {
				out = append(out, parse.SQLTextPiece{Text: p.Text[last:loc[0]]})
			}
			if p.Text[loc[0]:loc[1]] == "%%" {
				out = append(out, parse.SQLTextPiece{Text: "%"})
			} else {
				out = append(out, parse.SQLTextPiece{Hole: true})
			}
			last = loc[1]
		}
		if last < len(p.Text) {
			out = append(out, parse.SQLTextPiece{Text: p.Text[last:]})
		}
	}
	return out
}

// sqlTextInterpolated reads the parts of an interpolated string or heredoc body.
func (f *phpFlow) sqlTextInterpolated(m *phpModule, n *sitter.Node, before uint, depth int) []parse.SQLTextPiece {
	var out []parse.SQLTextPiece
	for i := uint(0); i < n.ChildCount(); i++ {
		c := n.Child(i)
		if c == nil {
			continue
		}
		if c.Kind() == "string_content" {
			out = append(out, parse.SQLTextPiece{Text: c.Utf8Text(m.src)})
		} else if c.IsNamed() {
			if c.Kind() == "variable_name" {
				out = append(out, f.sqlTextSyntax(m, c, before, depth+1)...)
			} else {
				out = append(out, parse.SQLTextPiece{Hole: true})
			}
		}
	}
	return out
}

func sqlTextHeredocBody(n *sitter.Node) *sitter.Node {
	for i := uint(0); i < n.NamedChildCount(); i++ {
		if c := n.NamedChild(i); c.Kind() == "heredoc_body" || c.Kind() == "nowdoc_body" {
			return c
		}
	}
	return nil
}

// sqlTextBuiltinName returns the lower-cased unqualified name of a function
// call that is the language's own (not defined in the module).
func sqlTextBuiltinName(m *phpModule, n *sitter.Node) string {
	fn := phpField(n, "function")
	if fn == nil || (fn.Kind() != "name" && fn.Kind() != "qualified_name") {
		return ""
	}
	name := strings.TrimPrefix(phpText(m, fn), "\\")
	if _, local := m.funcs[name]; local {
		return ""
	}
	return strings.ToLower(name)
}

// sqlTextJoin reads implode(sep, list) and join(sep, list).
func (f *phpFlow) sqlTextJoin(m *phpModule, n *sitter.Node, before uint, depth int) []parse.SQLTextPiece {
	hole := []parse.SQLTextPiece{{Hole: true}}
	args := phpArgs(n)
	var sep []parse.SQLTextPiece
	var list *sitter.Node
	switch len(args) {
	case 1:
		list = args[0]
	case 2:
		sep = f.sqlTextSyntax(m, args[0], before, depth+1)
		list = args[1]
	default:
		return hole
	}
	elems, ok := f.sqlTextList(m, list, before, depth+1)
	if !ok {
		return hole
	}
	var out []parse.SQLTextPiece
	for i, e := range elems {
		if i > 0 {
			out = append(out, sep...)
		}
		out = append(out, e...)
	}
	return out
}

// sqlTextListEvent is a write to a list variable.
type sqlTextListEvent struct {
	end    uint
	kind   string // set, append, unknown
	values []*sitter.Node
	right  *sitter.Node
}

func (f *phpFlow) sqlTextListEvents(m *phpModule, scope *sitter.Node, name string) []sqlTextListEvent {
	var out []sqlTextListEvent
	isVar := func(n *sitter.Node) bool { return n != nil && n.Kind() == "variable_name" && phpText(m, n) == name }
	var walk func(n *sitter.Node)
	walk = func(n *sitter.Node) {
		switch n.Kind() {
		case "function_definition", "method_declaration", "anonymous_function", "arrow_function":
			if n.StartByte() != scope.StartByte() || n.EndByte() != scope.EndByte() {
				return
			}
		case "assignment_expression":
			l, r := phpField(n, "left"), phpField(n, "right")
			switch {
			case isVar(l):
				if r != nil && r.Kind() == "array_creation_expression" {
					out = append(out, sqlTextListEvent{end: n.EndByte(), kind: "set", right: r})
				} else {
					out = append(out, sqlTextListEvent{end: n.EndByte(), kind: "unknown"})
				}
			case l != nil && l.Kind() == "subscript_expression" && isVar(l.NamedChild(0)) && r != nil:
				out = append(out, sqlTextListEvent{end: n.EndByte(), kind: "append", values: []*sitter.Node{r}})
			}
		case "augmented_assignment_expression", "reference_assignment_expression":
			if isVar(phpField(n, "left")) {
				out = append(out, sqlTextListEvent{end: n.EndByte(), kind: "unknown"})
			}
		case "function_call_expression":
			if strings.EqualFold(strings.TrimPrefix(phpText(m, phpField(n, "function")), "\\"), "array_push") {
				if args := phpArgs(n); len(args) > 1 && isVar(args[0]) {
					out = append(out, sqlTextListEvent{end: n.EndByte(), kind: "append", values: args[1:]})
				}
			}
		}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			if c := n.NamedChild(i); c != nil {
				walk(c)
			}
		}
	}
	walk(scope)
	sort.SliceStable(out, func(i, j int) bool { return out[i].end < out[j].end })
	return out
}

// sqlTextArrayElements reads the elements of an array literal; a spread is a
// hole element.
func (f *phpFlow) sqlTextArrayElements(m *phpModule, lit *sitter.Node, before uint, depth int) [][]parse.SQLTextPiece {
	var out [][]parse.SQLTextPiece
	for i := uint(0); i < lit.NamedChildCount(); i++ {
		el := lit.NamedChild(i)
		if el.Kind() != "array_element_initializer" || el.NamedChildCount() == 0 {
			continue
		}
		v := el.NamedChild(el.NamedChildCount() - 1)
		if v.Kind() == "variadic_unpacking" {
			out = append(out, []parse.SQLTextPiece{{Hole: true}})
			continue
		}
		out = append(out, f.sqlTextSyntax(m, v, before, depth+1))
	}
	return out
}

// sqlTextList reads the elements of a list: an array literal, or a variable
// assigned an array literal and extended with `$v[] = x` or array_push in its
// scope before the use. ok is false when the list cannot be followed.
func (f *phpFlow) sqlTextList(m *phpModule, n *sitter.Node, before uint, depth int) ([][]parse.SQLTextPiece, bool) {
	if n == nil || depth > 8 {
		return nil, false
	}
	var elems [][]parse.SQLTextPiece
	switch n.Kind() {
	case "parenthesized_expression":
		return f.sqlTextList(m, n.NamedChild(0), before, depth+1)
	case "array_creation_expression":
		elems = f.sqlTextArrayElements(m, n, before, depth)
	case "variable_name":
		scope := sqlTextScopeNode(n)
		if scope == nil {
			return nil, false
		}
		known := false
		for _, ev := range f.sqlTextListEvents(m, scope, phpText(m, n)) {
			if ev.end > before {
				continue
			}
			switch ev.kind {
			case "set":
				elems, known = f.sqlTextArrayElements(m, ev.right, ev.end, depth), true
			case "append":
				if !known {
					return nil, false
				}
				for _, v := range ev.values {
					elems = append(elems, f.sqlTextSyntax(m, v, ev.end, depth+1))
				}
			default:
				return nil, false
			}
			if len(elems) > sqlTextListMax {
				return nil, false
			}
		}
		if !known {
			return nil, false
		}
	default:
		return nil, false
	}
	if len(elems) > sqlTextListMax {
		return nil, false
	}
	return elems, true
}

// sqlTextReturns lists the return expressions of a function body, not those of
// nested functions or classes.
func sqlTextReturns(fn *sitter.Node) []*sitter.Node {
	var out []*sitter.Node
	var walk func(n *sitter.Node)
	walk = func(n *sitter.Node) {
		switch n.Kind() {
		case "function_definition", "method_declaration", "anonymous_function", "arrow_function", "class_declaration":
			return
		case "return_statement":
			if n.NamedChildCount() > 0 && len(out) < sqlTextReturnMax {
				out = append(out, n.NamedChild(0))
			}
			return
		}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			if c := n.NamedChild(i); c != nil {
				walk(c)
			}
		}
	}
	if body := phpField(fn, "body"); body != nil {
		walk(body)
	}
	return out
}

func (f *phpFlow) sqlTextEnclosingClass(m *phpModule, n *sitter.Node) *phpClassDecl {
	for p := n.Parent(); p != nil; p = p.Parent() {
		switch p.Kind() {
		case "class_declaration", "trait_declaration", "interface_declaration", "enum_declaration":
			d, _ := f.set.classIndex().resolve(m, phpText(m, phpField(p, "name")), p.StartByte())
			if d != nil && d.module == m && d.node.StartByte() == p.StartByte() {
				return d
			}
			return nil
		}
	}
	return nil
}

// sqlTextScopeClass resolves the class a written scope (self, static, parent or
// a name) means at a node.
func (f *phpFlow) sqlTextScopeClass(m *phpModule, scope *sitter.Node, at *sitter.Node) *phpClassDecl {
	if scope == nil {
		return nil
	}
	name := phpText(m, scope)
	switch strings.ToLower(name) {
	case "self", "static":
		return f.sqlTextEnclosingClass(m, at)
	case "parent":
		if d := f.sqlTextEnclosingClass(m, at); d != nil {
			p, _ := f.set.classIndex().parentOf(d)
			return p
		}
		return nil
	}
	if scope.Kind() != "name" && scope.Kind() != "qualified_name" {
		return nil
	}
	d, _ := f.set.classIndex().resolve(m, name, scope.StartByte())
	return d
}

// sqlTextCallable finds the function or method a call means in the scanned
// source: a function by name, a method of $this or of an object the flow tracks,
// a static method of a class.
func (f *phpFlow) sqlTextCallable(m *phpModule, n *sitter.Node) (*phpModule, *sitter.Node) {
	switch n.Kind() {
	case "function_call_expression":
		fn := phpField(n, "function")
		if fn == nil || (fn.Kind() != "name" && fn.Kind() != "qualified_name") {
			return nil, nil
		}
		name := strings.TrimPrefix(phpText(m, fn), "\\")
		if i := strings.LastIndex(name, "\\"); i >= 0 {
			name = name[i+1:]
		}
		if def, ok := m.funcs[name]; ok {
			return m, def
		}
		var fm *phpModule
		var found *sitter.Node
		files := append([]string{}, f.set.files...)
		sort.Strings(files)
		for _, file := range files {
			other := f.set.modules[file]
			if other == nil || other == m {
				continue
			}
			if def, ok := other.funcs[name]; ok {
				if found != nil {
					return nil, nil
				}
				fm, found = other, def
			}
		}
		return fm, found
	case "member_call_expression":
		obj := phpField(n, "object")
		if obj == nil || obj.Kind() != "variable_name" {
			return nil, nil
		}
		var decl *phpClassDecl
		if phpVarName(m, obj) == "this" {
			decl = f.sqlTextEnclosingClass(m, n)
		} else if m == f.module {
			if v, ok := f.env[phpVarName(m, obj)]; ok {
				decl = v.classDecl
			}
		}
		if decl == nil {
			return nil, nil
		}
		_, fn, mod, _ := f.set.classIndex().method(decl, phpText(m, phpField(n, "name")))
		return mod, fn
	case "scoped_call_expression":
		decl := f.sqlTextScopeClass(m, phpField(n, "scope"), n)
		if decl == nil {
			return nil, nil
		}
		_, fn, mod, _ := f.set.classIndex().method(decl, phpText(m, phpField(n, "name")))
		return mod, fn
	}
	return nil, nil
}

// sqlTextHelper reads the text a function or method of the scanned source
// returns, with its parameters as holes. With several returns the first that is
// SQL statement text is taken: the statement test passes when any return passes.
func (f *phpFlow) sqlTextHelper(m *phpModule, n *sitter.Node, depth int) []parse.SQLTextPiece {
	hole := []parse.SQLTextPiece{{Hole: true}}
	st := f.set.sqlTextStateInit()
	if st.read == nil || st.read.hops >= sqlTextHelperHops {
		return hole
	}
	hm, fn := f.sqlTextCallable(m, n)
	if fn == nil {
		return hole
	}
	rets := sqlTextReturns(fn)
	if len(rets) == 0 {
		return hole
	}
	st.read.hops++
	defer func() { st.read.hops-- }()
	st.addDef(hm, fn)
	var first []parse.SQLTextPiece
	for i, r := range rets {
		p := f.sqlTextSyntax(hm, r, r.StartByte(), depth+1)
		if sqlTextPiecesMatch(p) {
			return p
		}
		if i == 0 {
			first = p
		}
	}
	return first
}

// sqlTextConstRef is a top-level `const NAME = value`.
type sqlTextConstRef struct {
	module *phpModule
	decl   *sitter.Node
	value  *sitter.Node
}

func sqlTextConstElements(m *phpModule, decl *sitter.Node, fn func(name string, value *sitter.Node)) {
	for i := uint(0); i < decl.NamedChildCount(); i++ {
		el := decl.NamedChild(i)
		if el.Kind() == "const_element" && el.NamedChildCount() >= 2 {
			fn(phpText(m, el.NamedChild(0)), el.NamedChild(el.NamedChildCount()-1))
		}
	}
}

func (f *phpFlow) sqlTextGlobalConst(m *phpModule, name string) (sqlTextConstRef, bool) {
	st := f.set.sqlTextStateInit()
	if st.consts == nil {
		st.consts = map[string][]sqlTextConstRef{}
		files := append([]string{}, f.set.files...)
		sort.Strings(files)
		for _, file := range files {
			mod := f.set.modules[file]
			if mod == nil || mod.tree == nil {
				continue
			}
			root := mod.tree.RootNode()
			for i := uint(0); i < root.NamedChildCount(); i++ {
				if c := root.NamedChild(i); c.Kind() == "const_declaration" {
					sqlTextConstElements(mod, c, func(n string, v *sitter.Node) {
						st.consts[n] = append(st.consts[n], sqlTextConstRef{module: mod, decl: c, value: v})
					})
				}
			}
		}
	}
	refs := st.consts[name]
	for _, r := range refs {
		if r.module == m {
			return r, true
		}
	}
	if len(refs) > 0 {
		return refs[0], true
	}
	return sqlTextConstRef{}, false
}

// sqlTextConstant reads a bare constant: define() with a literal, or const.
func (f *phpFlow) sqlTextConstant(m *phpModule, n *sitter.Node, depth int) []parse.SQLTextPiece {
	hole := []parse.SQLTextPiece{{Hole: true}}
	name := phpText(m, n)
	if m == f.module {
		if v, ok := f.constants[name]; ok {
			return parse.SQLTextLiteral(v)
		}
	}
	if v, ok := m.constants[name]; ok {
		return parse.SQLTextLiteral(v)
	}
	if ref, ok := f.sqlTextGlobalConst(m, name); ok {
		f.set.sqlTextStateInit().addDef(ref.module, ref.decl)
		return f.sqlTextSyntax(ref.module, ref.value, ref.value.EndByte(), depth+1)
	}
	if v, ok := f.set.constant(m, name); ok {
		return parse.SQLTextLiteral(v)
	}
	return hole
}

// sqlTextClassConstant reads Class::NAME, self::NAME and parent::NAME through
// the class, its in-repository parents and its traits' own declarations.
func (f *phpFlow) sqlTextClassConstant(m *phpModule, n *sitter.Node, depth int) []parse.SQLTextPiece {
	hole := []parse.SQLTextPiece{{Hole: true}}
	if n.NamedChildCount() != 2 {
		return hole
	}
	name := phpText(m, n.NamedChild(1))
	if strings.EqualFold(name, "class") {
		return hole
	}
	d := f.sqlTextScopeClass(m, n.NamedChild(0), n)
	idx := f.set.classIndex()
	for i := 0; d != nil && i <= phpClassDepth; i++ {
		body := phpField(d.node, "body")
		for j := uint(0); body != nil && j < body.NamedChildCount(); j++ {
			decl := body.NamedChild(j)
			if decl.Kind() != "const_declaration" {
				continue
			}
			var value *sitter.Node
			sqlTextConstElements(d.module, decl, func(n string, v *sitter.Node) {
				if n == name && value == nil {
					value = v
				}
			})
			if value != nil {
				f.set.sqlTextStateInit().addDef(d.module, decl)
				return f.sqlTextSyntax(d.module, value, value.EndByte(), depth+1)
			}
		}
		d, _ = idx.parentOf(d)
	}
	return hole
}

// sqlTextExcerptDefs attaches, for every definition the text was read from that
// no sent context evidence holds, a referenced_definition (same file as the
// sink) or a source excerpt (another file).
func (f *phpFlow) sqlTextDefinitionEvidence(u *analysis.CandidateUse, defs []sqlTextDef) {
	for _, d := range defs {
		sp := parse.Span(d.module.file, d.node)
		covered := false
		for _, e := range u.Context {
			if e.Span.File == sp.File && e.Span.StartByte <= sp.StartByte && e.Span.EndByte >= sp.EndByte && sqlTextJudgeKind(e.Kind) {
				covered = true
				break
			}
		}
		if covered {
			continue
		}
		if sp.File == u.Sink.Span.File {
			u.Context = append(u.Context, d.module.evidence("referenced_definition", d.node))
		} else if ev, ok := parse.SQLTextExcerptEvidence(d.module.src, sp); ok {
			u.Context = append(u.Context, ev)
		}
	}
}
