package parse

import (
	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

func (f *pythonStatic) lookup(name string) *pythonStaticValue {
	if f.set.staticInvalid[f.module.file+":"+name] {
		// A framework receiver bound by an earlier statement is exact at this
		// program point when every other assignment comes textually later
		// (for example a conditional middleware wrapper).
		if v, ok := f.env[name]; ok && v.receiver && v.kind != "" && f.laterAssignmentsOnly(name) {
			return v
		}
		return staticUnknown()
	}
	if v, ok := f.env[name]; ok {
		if v.fn != nil && v.fn.Parent() != nil && v.fn.Parent().Kind() == "decorated_definition" {
			return staticUnknown()
		}
		if v.tainted != nil && *v.tainted {
			return staticUnknown()
		}
		return v
	}
	m, key := f.set.resolve(f.module, name, 0)
	if m == nil || f.set.staticInvalid[m.file+":"+key] {
		return staticUnknown()
	}
	if key == "" {
		return &pythonStaticValue{module: m, known: true}
	}
	if fn := m.funcs[key]; fn != nil {
		if fn.Parent() != nil && fn.Parent().Kind() == "decorated_definition" {
			return staticUnknown()
		}
		return &pythonStaticValue{module: m, fn: fn}
	}
	if n := m.vars[key]; n != nil {
		guard := "value:" + m.file + ":" + key
		if f.stack[guard] {
			return staticUnknown()
		}
		f.stack[guard] = true
		defer delete(f.stack, guard)
		h := *f
		h.module = m
		h.env = map[string]*pythonStaticValue{}
		return h.eval(n)
	}
	return staticUnknown()
}
func (f *pythonStatic) eval(n *sitter.Node) *pythonStaticValue {
	if n == nil || !f.tick(n) {
		return staticUnknown()
	}
	m := f.module
	if text, ok := pyLiteral(m, n); ok {
		v := staticText(text)
		v.evidence = []analysis.Evidence{f.evidence("generation_literal", n)}
		return v
	}
	switch n.Kind() {
	case "identifier":
		if pyText(m, n) == "__file__" {
			return staticText(m.file)
		}
		return f.lookup(pyText(m, n))
	case "integer", "true", "false", "none":
		return staticText(pyText(m, n))
	case "list", "tuple", "expression_list":
		v := &pythonStaticValue{known: true, tainted: new(bool), items: []*pythonStaticValue{}}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			v.items = append(v.items, f.eval(n.NamedChild(i)))
		}
		return v
	case "dictionary":
		v := &pythonStaticValue{known: true, tainted: new(bool), fields: map[string]*pythonStaticValue{}, keys: map[string][]analysis.Evidence{}}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			p := n.NamedChild(i)
			k := f.eval(p.ChildByFieldName("key"))
			if !k.known {
				return staticUnknown()
			}
			v.fields[k.text] = f.eval(p.ChildByFieldName("value"))
			v.keys[k.text] = k.evidence
		}
		return v
	case "class_definition":
		return f.classValue(n)
	case "call":
		return f.call(n)
	case "attribute":
		obj := f.eval(n.ChildByFieldName("object"))
		key := pyText(m, n.ChildByFieldName("attribute"))
		if obj.module != nil && obj.fn == nil {
			h := *f
			h.module = obj.module
			h.env = map[string]*pythonStaticValue{}
			v := h.lookup(key)
			if !v.known && v.fn == nil && v.module == nil && strings.HasSuffix(obj.module.file, "__init__.py") {
				// pkg.sub after `import pkg.sub`: the submodule is an attribute of its package.
				if sub := f.set.importModule(obj.module, "."+key); sub != nil {
					return &pythonStaticValue{module: sub, known: true}
				}
			}
			return v
		}
		return staticUnknown()
	case "subscript":
		if pyText(m, n.ChildByFieldName("value")) == "sys.modules" && pyText(m, n.ChildByFieldName("subscript")) == "__name__" && f.set.qualified(m, "sys.modules") == "sys.modules" {
			return &pythonStaticValue{module: m, known: true}
		}
		base := f.eval(n.ChildByFieldName("value"))
		idx := n.ChildByFieldName("subscript")
		if idx == nil {
			return staticUnknown()
		}
		if idx.Kind() == "slice" && base.known {
			// Bound string slicing uses syntax offsets, including omitted endpoints.
			raw := strings.Split(pyText(m, idx), ":")
			if len(raw) != 2 {
				return staticUnknown()
			}
			start, end := 0, len(base.text)
			var err error
			if raw[0] != "" {
				start, err = strconv.Atoi(raw[0])
				if err != nil {
					return staticUnknown()
				}
			}
			if raw[1] != "" {
				end, err = strconv.Atoi(raw[1])
				if err != nil {
					return staticUnknown()
				}
			}
			if start < 0 {
				start += len(base.text)
			}
			if end < 0 {
				end += len(base.text)
			}
			if start < 0 || end < start || end > len(base.text) {
				return staticUnknown()
			}
			v := staticText(base.text[start:end])
			v.evidence = append([]analysis.Evidence{}, base.evidence...)
			return v
		}
		key := f.eval(idx)
		if !key.known {
			return staticUnknown()
		}
		if base.fields != nil {
			if v := base.fields[key.text]; v != nil {
				return v
			}
		}
		if i, err := strconv.Atoi(key.text); err == nil && i >= 0 && i < len(base.items) {
			return base.items[i]
		}
		return staticUnknown()
	case "list_comprehension":
		return f.comprehension(n)
	case "comparison_operator":
		if n.NamedChildCount() != 2 {
			return staticUnknown()
		}
		a, b := f.eval(n.NamedChild(0)), f.eval(n.NamedChild(1))
		if !a.known || !b.known {
			return staticUnknown()
		}
		op := pyText(m, n.ChildByFieldName("operators"))
		switch op {
		case "==":
			return staticBool(a.text == b.text)
		case "!=":
			return staticBool(a.text != b.text)
		}
	case "boolean_operator":
		a, b := f.eval(n.ChildByFieldName("left")), f.eval(n.ChildByFieldName("right"))
		if !a.known || !b.known {
			return staticUnknown()
		}
		if pyText(m, n.ChildByFieldName("operator")) == "and" {
			return staticBool(staticTruth(a) && staticTruth(b))
		}
		return staticBool(staticTruth(a) || staticTruth(b))
	case "not_operator":
		v := f.eval(n.ChildByFieldName("argument"))
		if !v.known && n.NamedChildCount() > 0 {
			v = f.eval(n.NamedChild(0))
		}
		if v.known {
			return staticBool(!staticTruth(v))
		}
	case "binary_operator":
		a, b := f.eval(n.ChildByFieldName("left")), f.eval(n.ChildByFieldName("right"))
		if a.known && b.known && pyText(m, n.ChildByFieldName("operator")) == "+" {
			if a.items != nil && b.items != nil {
				out := &pythonStaticValue{known: true, tainted: new(bool), items: append(append([]*pythonStaticValue{}, a.items...), b.items...)}
				return out
			}
			return staticText(a.text + b.text)
		}
	}
	return staticUnknown()
}
func staticBool(b bool) *pythonStaticValue {
	if b {
		return staticText("True")
	}
	return staticText("False")
}
func staticTruth(v *pythonStaticValue) bool {
	return v != nil && v.known && v.text != "False" && v.text != "None" && (v.text != "" || len(v.items) > 0 || len(v.fields) > 0)
}

func staticItems(v *pythonStaticValue) ([]*pythonStaticValue, bool) {
	if v == nil || !v.known || v.tainted != nil && *v.tainted {
		return nil, false
	}
	if v.items != nil {
		return v.items, true
	}
	if v.fields != nil {
		keys := make([]string, 0, len(v.fields))
		for k := range v.fields {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		items := []*pythonStaticValue{}
		for _, k := range keys {
			key := staticText(k)
			key.evidence = pythonMergeEvidence(v.evidence, v.keys[k])
			items = append(items, key)
		}
		return items, true
	}
	return nil, false
}

func (f *pythonStatic) comprehension(n *sitter.Node) *pythonStaticValue {
	var clause, condition *sitter.Node
	for i := uint(0); i < n.NamedChildCount(); i++ {
		c := n.NamedChild(i)
		if c.Kind() == "for_in_clause" {
			if clause != nil {
				return staticUnknown()
			}
			clause = c
		}
		if c.Kind() == "if_clause" {
			condition = c
		}
	}
	if clause == nil {
		return staticUnknown()
	}
	items, ok := staticItems(f.eval(clause.ChildByFieldName("right")))
	if !ok {
		return staticUnknown()
	}
	h := *f
	h.env = staticEnv(f.env)
	out := &pythonStaticValue{known: true, tainted: new(bool), items: []*pythonStaticValue{}}
	for i, item := range items {
		if i >= 128 {
			f.gap(n, "Source comprehension limit (128) reached; remainder unexpanded")
			break
		}
		if !h.bind(clause.ChildByFieldName("left"), item) {
			return staticUnknown()
		}
		if condition != nil {
			c := h.eval(condition.NamedChild(0))
			if !c.known {
				return staticUnknown()
			}
			if !staticTruth(c) {
				continue
			}
		}
		out.items = append(out.items, h.eval(n.ChildByFieldName("body")))
	}
	return out
}

func (f *pythonStatic) method(n *sitter.Node, base *pythonStaticValue, method string, args []*pythonStaticValue) (*pythonStaticValue, bool) {
	if base.tainted != nil && *base.tainted {
		return staticUnknown(), true
	}
	if base.fields != nil {
		switch method {
		case "items":
			keys, _ := staticItems(base)
			v := &pythonStaticValue{known: true, tainted: new(bool), items: []*pythonStaticValue{}}
			for _, k := range keys {
				v.items = append(v.items, &pythonStaticValue{known: true, items: []*pythonStaticValue{k, base.fields[k.text]}, evidence: k.evidence})
			}
			return v, true
		case "setdefault":
			if len(args) == 2 && args[0].known {
				if v := base.fields[args[0].text]; v != nil {
					return v, true
				}
				base.fields[args[0].text] = args[1]
				if base.keys == nil {
					base.keys = map[string][]analysis.Evidence{}
				}
				base.keys[args[0].text] = args[0].evidence
				return args[1], true
			}
		}
	}
	if base.items != nil && method == "append" && len(args) == 1 {
		base.items = append(base.items, args[0])
		return staticText("None"), true
	}
	if base.known {
		switch method {
		case "title":
			return staticText(pythonTitle(base.text)), true
		case "format":
			text := base.text
			for _, a := range args {
				if !a.known {
					return staticUnknown(), true
				}
				if !strings.Contains(text, "{}") {
					return staticUnknown(), true
				}
				text = strings.Replace(text, "{}", a.text, 1)
			}
			if strings.Contains(text, "{") {
				return staticUnknown(), true
			}
			return staticText(text), true
		case "replace":
			if len(args) == 2 && args[0].known && args[1].known {
				return staticText(strings.ReplaceAll(base.text, args[0].text, args[1].text)), true
			}
		case "startswith", "endswith":
			if len(args) == 1 && args[0].known {
				if method == "startswith" {
					return staticBool(strings.HasPrefix(base.text, args[0].text)), true
				}
				return staticBool(strings.HasSuffix(base.text, args[0].text)), true
			}
		}
	}
	return nil, false
}
func (f *pythonStatic) libraryCall(n *sitter.Node, q string, args []*pythonStaticValue) (*pythonStaticValue, bool) {
	arg := func(i int) (string, bool) {
		if i >= len(args) || !args[i].known {
			return "", false
		}
		return args[i].text, true
	}
	switch q {
	case "falcon.API", "falcon.App", "falcon.asgi.App":
		return &pythonStaticValue{receiver: true, kind: "falcon"}, true
	case "flask.Flask", "flask.Blueprint", "fastapi.FastAPI", "fastapi.APIRouter", "quart.Quart", "quart.Blueprint":
		return &pythonStaticValue{receiver: true}, true
	case "bottle.Bottle":
		return &pythonStaticValue{receiver: true, kind: "bottle"}, true
	case "pyramid.config.Configurator":
		return &pythonStaticValue{receiver: true, kind: "pyramid", routes: map[string]string{}}, true
	case "os.path.dirname", "os.path.basename":
		a, ok := arg(0)
		if !ok {
			return staticUnknown(), true
		}
		if q == "os.path.dirname" {
			return staticText(filepath.ToSlash(filepath.Dir(a))), true
		}
		return staticText(filepath.Base(a)), true
	case "os.path.join":
		parts := []string{}
		for i := range args {
			v, ok := arg(i)
			if !ok {
				return staticUnknown(), true
			}
			parts = append(parts, v)
		}
		return staticText(filepath.ToSlash(filepath.Join(parts...))), true
	case "os.path.isfile":
		a, ok := arg(0)
		return staticBool(ok && f.set.modules[a] != nil), true
	case "glob.glob":
		pattern, ok := arg(0)
		if !ok || strings.Contains(pattern, "..") || filepath.IsAbs(pattern) {
			return staticUnknown(), true
		}
		out := &pythonStaticValue{known: true, tainted: new(bool), items: []*pythonStaticValue{}}
		for _, file := range f.set.files {
			match, err := filepath.Match(pattern, file)
			if err != nil {
				return staticUnknown(), true
			}
			if match {
				v := staticText(file)
				if m := f.set.modules[file]; m != nil {
					v.evidence = []analysis.Evidence{m.evidence("registry_module", m.tree.RootNode())}
				}
				out.items = append(out.items, v)
			}
		}
		return out, true
	case "importlib.import_module":
		name, ok := arg(0)
		if !ok {
			return staticUnknown(), true
		}
		// The existing module resolver enforces the selected source root.
		if m := f.set.importModule(f.module, name); m != nil {
			return &pythonStaticValue{module: m, known: true}, true
		}
		return staticUnknown(), true
	case "inspect.isclass":
		return staticBool(len(args) == 1 && args[0].class != nil), true
	case "inspect.getmembers":
		if len(args) != 1 || args[0].module == nil {
			return staticUnknown(), true
		}
		m := args[0].module
		names := []string{}
		for name := range m.funcs {
			names = append(names, name)
		}
		for name := range m.imports {
			names = append(names, name)
		}
		for name, node := range m.vars {
			if node != nil && node.Kind() == "class_definition" {
				names = append(names, name)
			}
		}
		for name := range f.set.dynamicMembers[m.file] {
			names = append(names, name)
		}
		sort.Strings(names)
		out := &pythonStaticValue{known: true, tainted: new(bool), items: []*pythonStaticValue{}}
		for _, name := range names {
			h := *f
			h.module = m
			h.env = map[string]*pythonStaticValue{}
			var v *pythonStaticValue
			if m.imports[name].node != nil && m.funcs[name] == nil {
				// An imported variable is not evaluated per enumeration (a registry such as
				// TRIGGER_MAP is costly); imported functions and modules still resolve.
				target, key := f.set.resolve(m, name, 0)
				if target != nil && (key == "" || target.funcs[key] != nil) {
					v = h.lookup(name)
				} else {
					v = staticUnknown()
				}
			} else {
				v = h.lookup(name)
			}
			if dyn := f.set.dynamicMembers[m.file][name]; dyn != nil {
				v = dyn
			}
			key := staticText(name)
			if v.fn != nil {
				key.evidence = []analysis.Evidence{v.module.evidence("registry_member", v.fn)}
			}
			out.items = append(out.items, &pythonStaticValue{known: true, items: []*pythonStaticValue{key, v}})
		}
		return out, true
	}
	if q == "setattr" && f.module.vars["setattr"] == nil && f.module.imports["setattr"].node == nil {
		if len(args) == 3 && args[0].module != nil && args[1].known {
			if f.set.dynamicMembers == nil {
				f.set.dynamicMembers = map[string]map[string]*pythonStaticValue{}
			}
			if f.set.dynamicMembers[args[0].module.file] == nil {
				f.set.dynamicMembers[args[0].module.file] = map[string]*pythonStaticValue{}
			}
			f.set.dynamicMembers[args[0].module.file][args[1].text] = args[2]
		}
		return staticUnknown(), true
	}
	if q == "getattr" && f.module.vars["getattr"] == nil && f.module.imports["getattr"].node == nil {
		if len(args) == 2 && args[0].module != nil && args[1].known {
			h := *f
			h.module = args[0].module
			h.env = map[string]*pythonStaticValue{}
			return h.lookup(args[1].text), true
		}
		return staticUnknown(), true
	}
	return nil, false
}

// laterAssignmentsOnly reports that, apart from its first binding, every
// assignment to name in the module starts after the statement being interpreted.
func (f *pythonStatic) laterAssignmentsOnly(name string) bool {
	first := true
	ok := true
	pyWalk(f.module.tree.RootNode(), func(n *sitter.Node) {
		if n.Kind() != "assignment" && n.Kind() != "augmented_assignment" {
			return
		}
		left := n.ChildByFieldName("left")
		if left == nil || left.Kind() != "identifier" || pyText(f.module, left) != name {
			return
		}
		if first {
			first = false
			return
		}
		if n.StartByte() <= f.pos {
			ok = false
		}
	})
	return ok
}

func (f *pythonStatic) classValue(n *sitter.Node) *pythonStaticValue {
	c := &staticClass{module: f.module, node: n, closure: staticEnv(f.env)}
	if supers := n.ChildByFieldName("superclasses"); supers != nil {
		for i := uint(0); i < supers.NamedChildCount(); i++ {
			c.bases = append(c.bases, f.eval(supers.NamedChild(i)))
		}
	}
	return &pythonStaticValue{known: true, class: c}
}

// pythonTitle follows str.title: letters after a non-letter are capitalized.
func pythonTitle(s string) string {
	out := []rune(strings.ToLower(s))
	boundary := true
	for i, r := range out {
		isLetter := r >= 'a' && r <= 'z'
		if isLetter && boundary {
			out[i] = r - 32
		}
		boundary = !isLetter
	}
	return string(out)
}
