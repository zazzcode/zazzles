package langphp

import (
	"fmt"
	"sort"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
)

// Class, method and property binding (close-findings-gaps W3, D-8 to D-11).
// Every class-like declaration is indexed by the fully qualified name its file
// declares; a name in a module resolves through that module's namespace and
// use clauses. A name with exactly one declaration resolves; zero or several
// stay unresolved with the reason. Similarity (basename or short-name
// matching) is never a binding rule.

// phpClassDecl is one class, interface, trait or enum declaration.
type phpClassDecl struct {
	fqn    string
	kind   string // class, interface, trait, enum
	module *phpModule
	node   *sitter.Node
}

// phpNamespaceScope is the namespace and use clauses in effect from start
// to end in one module.
type phpNamespaceScope struct {
	start, end uint
	namespace  string
	// uses maps a lower-cased alias to the fully qualified class name.
	uses map[string]string
}

type phpClassIndex struct {
	byName map[string][]*phpClassDecl // lower-cased FQN
	scopes map[string][]phpNamespaceScope
}

// phpClassDepth bounds the extends/trait chain walked for a method (D-9).
const phpClassDepth = 4

// classIndex builds the set's class index once.
func (s *phpSet) classIndex() *phpClassIndex {
	if s.classes != nil {
		return s.classes
	}
	x := &phpClassIndex{byName: map[string][]*phpClassDecl{}, scopes: map[string][]phpNamespaceScope{}}
	for _, file := range s.files {
		m := s.modules[file]
		if m == nil || m.tree.RootNode().HasError() {
			continue
		}
		x.indexModule(m)
	}
	s.classes = x
	return x
}

func (x *phpClassIndex) indexModule(m *phpModule) {
	root := m.tree.RootNode()
	scope := phpNamespaceScope{start: 0, end: root.EndByte(), uses: map[string]string{}}
	var scopes []phpNamespaceScope
	flush := func(end uint) {
		scope.end = end
		scopes = append(scopes, scope)
	}
	var visit func(n *sitter.Node, sc *phpNamespaceScope)
	visit = func(parent *sitter.Node, sc *phpNamespaceScope) {
		for i := uint(0); i < parent.NamedChildCount(); i++ {
			c := parent.NamedChild(i)
			switch c.Kind() {
			case "namespace_definition":
				name := phpText(m, phpField(c, "name"))
				if body := phpField(c, "body"); body != nil {
					inner := phpNamespaceScope{start: c.StartByte(), end: c.EndByte(), namespace: name, uses: map[string]string{}}
					visit(body, &inner)
					scopes = append(scopes, inner)
					continue
				}
				// `namespace X;` starts a new scope that runs to the next one.
				flush(c.StartByte())
				scope = phpNamespaceScope{start: c.StartByte(), end: root.EndByte(), namespace: name, uses: map[string]string{}}
				sc = &scope
			case "namespace_use_declaration":
				phpUseClauses(m, c, sc.uses)
			case "class_declaration", "interface_declaration", "trait_declaration", "enum_declaration":
				name := phpText(m, phpField(c, "name"))
				if name == "" {
					continue
				}
				fqn := name
				if sc.namespace != "" {
					fqn = sc.namespace + `\` + name
				}
				kind := strings.TrimSuffix(c.Kind(), "_declaration")
				key := strings.ToLower(fqn)
				x.byName[key] = append(x.byName[key], &phpClassDecl{fqn: fqn, kind: kind, module: m, node: c})
			}
		}
	}
	visit(root, &scope)
	flush(root.EndByte())
	x.scopes[m.file] = scopes
}

// phpUseClauses records the class imports of one use declaration, including
// aliases and group use. Function and constant imports are not classes.
func phpUseClauses(m *phpModule, n *sitter.Node, out map[string]string) {
	text := strings.TrimSpace(phpText(m, n))
	if strings.HasPrefix(text, "use function") || strings.HasPrefix(text, "use const") {
		return
	}
	prefix := ""
	for i := uint(0); i < n.NamedChildCount(); i++ {
		c := n.NamedChild(i)
		switch c.Kind() {
		case "namespace_name":
			prefix = phpText(m, c)
		case "namespace_use_clause":
			phpUseClause(m, c, "", out)
		case "namespace_use_group":
			for j := uint(0); j < c.NamedChildCount(); j++ {
				if g := c.NamedChild(j); g.Kind() == "namespace_use_clause" {
					phpUseClause(m, g, prefix, out)
				}
			}
		}
	}
}

func phpUseClause(m *phpModule, c *sitter.Node, prefix string, out map[string]string) {
	alias := phpText(m, phpField(c, "alias"))
	var target string
	for i := uint(0); i < c.NamedChildCount(); i++ {
		k := c.NamedChild(i)
		if (k.Kind() == "qualified_name" || k.Kind() == "name") && phpField(c, "alias") != k {
			target = phpText(m, k)
			break
		}
	}
	target = strings.TrimPrefix(target, `\`)
	if target == "" {
		return
	}
	if prefix != "" {
		target = strings.TrimPrefix(prefix, `\`) + `\` + target
	}
	if alias == "" {
		alias = target[strings.LastIndex(target, `\`)+1:]
	}
	out[strings.ToLower(alias)] = target
}

func (x *phpClassIndex) scopeAt(m *phpModule, at uint) phpNamespaceScope {
	for _, s := range x.scopes[m.file] {
		if at >= s.start && at < s.end {
			return s
		}
	}
	return phpNamespaceScope{uses: map[string]string{}}
}

// qualify returns the fully qualified class name a written name means at a
// position of a module (PHP name resolution rules for classes).
func (x *phpClassIndex) qualify(m *phpModule, name string, at uint) string {
	name = strings.TrimSpace(name)
	if strings.HasPrefix(name, `\`) {
		return strings.TrimPrefix(name, `\`)
	}
	sc := x.scopeAt(m, at)
	if strings.HasPrefix(strings.ToLower(name), `namespace\`) {
		rest := name[len(`namespace\`):]
		if sc.namespace == "" {
			return rest
		}
		return sc.namespace + `\` + rest
	}
	first, rest, qualified := strings.Cut(name, `\`)
	if target, ok := sc.uses[strings.ToLower(first)]; ok {
		if qualified {
			return target + `\` + rest
		}
		return target
	}
	if sc.namespace == "" {
		return name
	}
	return sc.namespace + `\` + name
}

// resolve returns the one declaration a written class name means, or the
// reason it does not resolve.
func (x *phpClassIndex) resolve(m *phpModule, name string, at uint) (*phpClassDecl, string) {
	fqn := x.qualify(m, name, at)
	decls := x.byName[strings.ToLower(fqn)]
	switch len(decls) {
	case 1:
		return decls[0], ""
	case 0:
		return nil, "no declaration of " + fqn + " in the scanned files"
	}
	files := []string{}
	for _, d := range decls {
		files = append(files, d.module.file)
	}
	sort.Strings(files)
	return nil, fqn + " is declared more than once (" + strings.Join(files, ", ") + ")"
}

// parentOf returns the in-repository parent of a class, the written parent
// name when it does not resolve, or neither when the class extends nothing.
func (x *phpClassIndex) parentOf(d *phpClassDecl) (*phpClassDecl, string) {
	for i := uint(0); i < d.node.NamedChildCount(); i++ {
		c := d.node.NamedChild(i)
		if c.Kind() != "base_clause" {
			continue
		}
		for j := uint(0); j < c.NamedChildCount(); j++ {
			if k := c.NamedChild(j); k.Kind() == "name" || k.Kind() == "qualified_name" {
				name := phpText(d.module, k)
				if p, _ := x.resolve(d.module, name, k.StartByte()); p != nil {
					return p, ""
				}
				return nil, name
			}
		}
	}
	return nil, ""
}

// traitsOf returns the traits a class uses, resolved, and the written names
// that do not resolve.
func (x *phpClassIndex) traitsOf(d *phpClassDecl) (traits []*phpClassDecl, unresolved []string) {
	body := phpField(d.node, "body")
	for i := uint(0); body != nil && i < body.NamedChildCount(); i++ {
		c := body.NamedChild(i)
		if c.Kind() != "use_declaration" {
			continue
		}
		for j := uint(0); j < c.NamedChildCount(); j++ {
			k := c.NamedChild(j)
			if k.Kind() != "name" && k.Kind() != "qualified_name" {
				continue
			}
			if t, _ := x.resolve(d.module, phpText(d.module, k), k.StartByte()); t != nil && t.kind == "trait" {
				traits = append(traits, t)
			} else {
				unresolved = append(unresolved, phpText(d.module, k))
			}
		}
	}
	return traits, unresolved
}

// phpOwnMethod returns a method declared directly in a class-like body.
func phpOwnMethod(d *phpClassDecl, name string) *sitter.Node {
	body := phpField(d.node, "body")
	for i := uint(0); body != nil && i < body.NamedChildCount(); i++ {
		c := body.NamedChild(i)
		if c.Kind() == "method_declaration" && strings.EqualFold(phpText(d.module, phpField(c, "name")), name) {
			return c
		}
	}
	return nil
}

// method finds a method through the class, its used traits and its
// in-repository extends chain, to depth phpClassDepth (D-9). It returns the
// declaring class and, when the method is not found, the reason: a parent
// outside the repository leaves a gap only when the method was not found
// before it.
func (x *phpClassIndex) method(d *phpClassDecl, name string) (owner *phpClassDecl, fn *sitter.Node, module *phpModule, reason string) {
	seen := map[*phpClassDecl]bool{}
	for depth := 0; d != nil && depth <= phpClassDepth; depth++ {
		if seen[d] {
			return nil, nil, nil, "class hierarchy cycle at " + d.fqn
		}
		seen[d] = true
		if fn := phpOwnMethod(d, name); fn != nil {
			return d, fn, d.module, ""
		}
		traits, unresolvedTraits := x.traitsOf(d)
		for _, t := range traits {
			if fn := phpOwnMethod(t, name); fn != nil {
				return d, fn, t.module, ""
			}
		}
		parent, outside := x.parentOf(d)
		if len(unresolvedTraits) > 0 {
			return nil, nil, nil, "trait " + strings.Join(unresolvedTraits, ", ") + " of " + d.fqn + " is not in the scanned files"
		}
		if outside != "" {
			return nil, nil, nil, "parent " + outside + " of " + d.fqn + " is not in the scanned files"
		}
		d = parent
	}
	if d != nil {
		return nil, nil, nil, "class hierarchy deeper than the bound"
	}
	return nil, nil, nil, ""
}

// propertyDefault returns the declared default of a property, searching the
// class and its in-repository parents.
func (x *phpClassIndex) propertyDefault(d *phpClassDecl, name string) (*phpClassDecl, *sitter.Node) {
	for depth := 0; d != nil && depth <= phpClassDepth; depth++ {
		body := phpField(d.node, "body")
		for i := uint(0); body != nil && i < body.NamedChildCount(); i++ {
			c := body.NamedChild(i)
			if c.Kind() != "property_declaration" {
				continue
			}
			for j := uint(0); j < c.NamedChildCount(); j++ {
				el := c.NamedChild(j)
				if el.Kind() == "property_element" && phpVarName(d.module, phpField(el, "name")) == name {
					return d, phpField(el, "default_value")
				}
			}
		}
		d, _ = x.parentOf(d)
	}
	return nil, nil
}

// Object flow (D-9, D-10).

// phpNewArguments returns the argument nodes of `new C(...)`, whose
// arguments child carries no field name.
func phpNewArguments(n *sitter.Node) []*sitter.Node {
	var args *sitter.Node
	for i := uint(0); i < n.NamedChildCount(); i++ {
		if c := n.NamedChild(i); c.Kind() == "arguments" {
			args = c
		}
	}
	var out []*sitter.Node
	for i := uint(0); args != nil && i < args.NamedChildCount(); i++ {
		c := args.NamedChild(i)
		if c.Kind() == "argument" && c.NamedChild(0) != nil {
			c = c.NamedChild(0)
		}
		out = append(out, c)
	}
	return out
}

// newObject binds `new C(args)` to its class across modules and expands
// __construct through the bounded helper (D-9). ok is false when the class
// does not resolve; reason then says why.
func (f *phpFlow) newObject(n, clsNode *sitter.Node, cls string) (phpValue, bool, string) {
	m := f.module
	idx := f.set.classIndex()
	var decl *phpClassDecl
	reason := ""
	switch strings.ToLower(cls) {
	case "self", "static":
		decl = f.class
	case "parent":
		if f.class != nil {
			decl, _ = idx.parentOf(f.class)
		}
	default:
		decl, reason = idx.resolve(m, cls, clsNode.StartByte())
	}
	if decl == nil || decl.kind != "class" {
		return phpValue{}, false, reason
	}
	f.set.objects++
	v := phpValue{binding: "php_class", class: decl.fqn, classDecl: decl, objectID: f.set.objects, props: map[string]phpValue{}, evidence: []analysis.Evidence{m.evidence("object_creation", n)}}
	nodes := phpNewArguments(n)
	values := make([]phpValue, len(nodes))
	for i, a := range nodes {
		values[i] = f.eval(a)
	}
	owner, ctor, module, why := idx.method(decl, "__construct")
	switch {
	case ctor != nil:
		self := v
		f.boundHelper(n, &phpBoundCallable{module: module, fn: ctor, object: &self, class: owner}, values)
		v = self
	case why != "":
		// The constructor may live in a parent outside the repository:
		// what it writes is not established.
		v.propsUnknown = true
	}
	return v, true, ""
}

// writeObject replaces every alias of an object with its updated value.
func (f *phpFlow) writeObject(v phpValue) {
	if v.objectID == 0 {
		return
	}
	for name, e := range f.env {
		if e.objectID == v.objectID {
			f.env[name] = v
			f.markDirty(name)
		}
	}
}

// propertyWrite records $obj->p = v on a tracked object; a dynamic property
// name marks the map unknown (D-10).
func (f *phpFlow) propertyWrite(left *sitter.Node, v phpValue) {
	m := f.module
	obj, name := phpField(left, "object"), phpField(left, "name")
	if obj == nil || name == nil || obj.Kind() != "variable_name" {
		return
	}
	base, ok := f.env[phpVarName(m, obj)]
	if !ok || base.classDecl == nil {
		return
	}
	props := make(map[string]phpValue, len(base.props)+1)
	for k, p := range base.props {
		props[k] = p
	}
	if name.Kind() == "name" {
		props[phpText(m, name)] = phpTransfer(v, m.evidence("property_write", left))
	} else {
		base.propsUnknown = true
	}
	base.props = props
	if base.objectID == 0 {
		f.env[phpVarName(m, obj)] = base
		f.markDirty(phpVarName(m, obj))
		return
	}
	f.writeObject(base)
}

// propertyRead reads $obj->p of a tracked object: a written value, else the
// declared default. ok is false for an untracked receiver.
func (f *phpFlow) propertyRead(n *sitter.Node) (phpValue, bool) {
	m := f.module
	obj, name := phpField(n, "object"), phpField(n, "name")
	if obj == nil || name == nil || obj.Kind() != "variable_name" {
		return phpValue{}, false
	}
	base, ok := f.env[phpVarName(m, obj)]
	if !ok || base.classDecl == nil {
		return phpValue{}, false
	}
	if name.Kind() != "name" {
		return phpValue{unknown: true, gaps: []analysis.Gap{f.gap("php_value_unresolved", "Property name is dynamic: "+phpText(m, n), n)}}, true
	}
	key := phpText(m, name)
	if p, ok := base.props[key]; ok && !base.propsUnknown {
		return phpTransfer(p, m.evidence("property_read", n)), true
	}
	if base.propsUnknown {
		return phpValue{unknown: true, gaps: []analysis.Gap{f.gap("php_value_unresolved", "Property is not resolved: ->"+key+" (the object's properties are not all established)", n)}}, true
	}
	if decl, def := f.set.classIndex().propertyDefault(base.classDecl, key); decl != nil {
		if def == nil {
			return phpValue{constant: true, literals: []phpLiteral{{text: ""}}}, true
		}
		h := f.clone()
		h.module = decl.module
		return phpTransfer(h.eval(def), m.evidence("property_read", n)), true
	}
	return phpValue{unknown: true, gaps: []analysis.Gap{f.gap("php_value_unresolved", "Property is not declared or written: ->"+key, n)}}, true
}

// classMethodCall expands a method of a tracked object or a scoped class
// reference (D-9). object is the receiver, nil for a static call.
func (f *phpFlow) classMethodCall(n *sitter.Node, decl *phpClassDecl, method string, object *phpValue, values []phpValue) (phpValue, bool) {
	owner, fn, module, reason := f.set.classIndex().method(decl, method)
	if fn == nil {
		if reason == "" {
			return phpValue{}, false
		}
		v := phpValue{unknown: true}
		for _, a := range values {
			v = phpCombine(v, a)
		}
		v = phpProtect(v, "unknown")
		v.gaps = append(v.gaps, f.classGap("method "+method+" is not resolved: "+reason, n))
		return v, true
	}
	if key := fmt.Sprintf("%s:%d", module.file, fn.StartByte()); f.depth >= phpHelperDepthLimit || *f.work >= phpHelperWorkLimit || f.stack[key] {
		// Beyond the expansion bound a method call keeps its unresolved
		// result; the object may then hold any property.
		if object != nil {
			object.propsUnknown = true
			f.writeObject(*object)
		}
		return phpValue{}, false
	}
	out := f.boundHelper(n, &phpBoundCallable{module: module, fn: fn, object: object, class: owner}, values)
	if object != nil {
		f.writeObject(*object)
	}
	return out, true
}

// classGap records a class-resolution failure once on the report (a
// coverage fact) and returns it for the value that carries it.
func (f *phpFlow) classGap(detail string, n *sitter.Node) analysis.Gap {
	g := f.gap("php_class_unresolved", detail, n)
	for _, e := range f.set.gaps {
		if e == g {
			return g
		}
	}
	f.set.gaps = append(f.set.gaps, g)
	return g
}
