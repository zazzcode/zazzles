package parse

import (
	"encoding/json"
	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
	"strings"
)

func pyCombine(a, b pythonValue) pythonValue {
	if pyEmpty(a) {
		return b
	}
	if pyEmpty(b) {
		return a
	}
	if !a.constant || !b.constant || a.literal != b.literal {
		a.constant = false
		a.literal = ""
	}
	if len(b.deps) > 0 && a.binding != b.binding {
		a.binding = ""
	}
	a.rendered = a.rendered && b.rendered
	a.unknown = a.unknown || b.unknown

	a.deps = pyMergeDeps(a.deps, b.deps)
	if len(a.deps) > 64 {
		a.deps = a.deps[:64]
		a.gaps = append(a.gaps, analysis.Gap{Kind: "dependency_limit", Detail: "Python value exceeds 64 dependency paths", At: a.deps[0].dep.Source.Span})
	}

	a.gaps = append(append([]analysis.Gap{}, a.gaps...), b.gaps...)
	a.built = a.built || b.built

	if a.table == "" {
		a.table = b.table
	}
	a.evidence = append(append([]analysis.Evidence{}, a.evidence...), b.evidence...)
	if a.fields == nil {
		a.fields = b.fields
	}
	return a
}
func pyEmpty(v pythonValue) bool {
	return len(v.deps) == 0 && len(v.gaps) == 0 && v.fields == nil && !v.constant && v.binding == "" && len(v.evidence) == 0 && !v.built && !v.rendered && !v.unknown && v.callable == nil
}
func pyMergeDeps(a, b []pythonDep) []pythonDep {
	out := []pythonDep{}
	seen := map[string]bool{}
	for _, d := range append(append([]pythonDep{}, a...), b...) {
		raw, _ := json.Marshal(d.dep)
		key := string(raw) + d.protection + d.container + d.key + d.entry
		if !seen[key] {
			seen[key] = true
			out = append(out, d)
		}
	}
	return out
}
func pyTransfer(v pythonValue, e analysis.Evidence) pythonValue {
	v.deps = append([]pythonDep{}, v.deps...)
	for i := range v.deps {
		v.deps[i].dep.Transfers = append(append([]analysis.Evidence{}, v.deps[i].dep.Transfers...), e)
		if len(v.deps[i].dep.Transfers) > 48 {
			v.deps[i].dep.Transfers = v.deps[i].dep.Transfers[:48]
			v.gaps = append(v.gaps, analysis.Gap{Kind: "transfer_limit", Detail: "Python path exceeds 48 transfers", At: e.Span})
		}

	}
	return v
}
func pyProtect(v pythonValue, p string) pythonValue {
	v.deps = append([]pythonDep{}, v.deps...)
	for i := range v.deps {
		v.deps[i].protection = p
	}
	return v
}
func (f *pythonFlow) evalChildren(n *sitter.Node) pythonValue {
	var v pythonValue
	for i := uint(0); i < n.NamedChildCount(); i++ {
		v = pyCombine(v, f.eval(n.NamedChild(i)))
	}
	return v
}
func (f *pythonFlow) eval(n *sitter.Node) pythonValue {
	if n == nil {
		return pythonValue{}
	}
	m := f.module
	switch n.Kind() {
	case "identifier":
		if v, ok := f.env[pyText(m, n)]; ok {
			return pyTransfer(v, m.evidence("value_reference", n))
		}
		if text, ok := pyStaticString(m, m.vars[pyText(m, n)]); ok {
			return pythonValue{literal: text, constant: true, evidence: []analysis.Evidence{m.evidence("constant_binding", n)}}
		}
		if global := m.vars[pyText(m, n)]; global != nil && global.Kind() == "call" {
			if q := f.qualified(pyText(m, global.ChildByFieldName("function"))); q == "logging.getLogger" {
				return pythonValue{binding: "logger", evidence: []analysis.Evidence{m.evidence("logger_binding", global)}}
			}
		}
		if f.qualified(pyText(m, n)) == "flask.request" {
			return pythonValue{binding: "flask_request"}
		}
		if f.qualified(pyText(m, n)) == "flask.session" {
			return f.source(n, "session", "")
		}
		return pythonValue{unknown: true, gaps: []analysis.Gap{f.gap("python_value_unresolved", "Value definition is not resolved: "+pyText(m, n), n)}}
	case "integer", "float", "true", "false", "none":
		return pythonValue{literal: pyText(m, n), constant: true}
	case "string":
		if text, ok := pyLiteral(m, n); ok {
			return pythonValue{literal: text, constant: true, evidence: []analysis.Evidence{m.evidence("literal", n)}}
		}
		v := f.evalChildren(n)
		v.built = true
		return pyTransfer(v, m.evidence("string_interpolation", n))
	case "interpolation":
		return pyTransfer(f.evalChildren(n), m.evidence("string_interpolation", n))
	case "assignment", "augmented_assignment":
		f.falconBody(n)
		left, right := n.ChildByFieldName("left"), n.ChildByFieldName("right")
		v := f.eval(right)
		if n.Kind() == "augmented_assignment" {
			v = pyCombine(f.eval(left), v)
			v.built = true
		}
		v = pyTransfer(v, m.evidence("assignment", n))
		if left != nil && left.Kind() == "identifier" {
			f.env[pyText(m, left)] = v
		} else if left != nil && n.Kind() == "assignment" && (left.Kind() == "pattern_list" || left.Kind() == "tuple_pattern") {
			// Tuple unpacking: each target conservatively inherits the whole value.
			for i := uint(0); i < left.NamedChildCount(); i++ {
				if target := left.NamedChild(i); target.Kind() == "identifier" {
					f.env[pyText(m, target)] = pyTransfer(v, m.evidence("tuple_unpack", target))
				}
			}
		}
		return v
	case "attribute", "subscript":
		return f.project(n)
	case "call":
		return f.call(n)
	case "conditional_expression":
		if n.NamedChildCount() == 3 {
			f.eval(n.NamedChild(1))
			v := pyJoin(f.eval(n.NamedChild(0)), f.eval(n.NamedChild(2)), 0)
			return pyTransfer(v, m.evidence("conditional_value", n))
		}
		return pythonValue{gaps: []analysis.Gap{f.gap("python_expression_unresolved", "unsupported conditional shape", n)}}
	case "binary_operator", "boolean_operator", "comparison_operator":
		if n.Kind() == "binary_operator" && pyText(m, n.ChildByFieldName("operator")) == "+" {
			a, aok := pyStaticString(m, n.ChildByFieldName("left"))
			b, bok := pyStaticString(m, n.ChildByFieldName("right"))
			if aok && bok {
				return pythonValue{literal: a + b, constant: true, evidence: []analysis.Evidence{m.evidence("literal", n)}}
			}
		}

		v := f.evalChildren(n)
		if n.Kind() == "binary_operator" {
			v.built = true
		}
		if n.Kind() == "comparison_operator" {
			v = pyProtect(v, "non_content")
		}
		return pyTransfer(v, m.evidence("expression", n))
	case "dictionary":
		v := pythonValue{fields: map[string]pythonValue{}}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			pair := n.NamedChild(i)
			key, ok := pyLiteral(m, pair.ChildByFieldName("key"))
			value := f.eval(pair.ChildByFieldName("value"))
			v = pyCombine(v, value)
			if ok {
				v.fields[key] = value
			}
		}
		return v
	case "list_comprehension", "dictionary_comprehension", "generator_expression":
		v := f.evalChildren(n)
		v.gaps = append(v.gaps, f.gap("python_comprehension_unresolved", "iteration, key restrictions and comprehensions require review", n))
		v.built = true
		return v
	case "list", "tuple", "expression_list", "parenthesized_expression", "await":
		return f.evalChildren(n)
	case "not_operator":
		return pyTransfer(pyProtect(f.evalChildren(n), "non_content"), m.evidence("expression", n))
	case "unary_operator":
		return pyTransfer(f.evalChildren(n), m.evidence("expression", n))
	default:
		return f.evalChildren(n)
	}
}
func (f *pythonFlow) project(n *sitter.Node) pythonValue {
	m := f.module
	text := pyText(m, n)
	// The request binding must originate from Flask; lexical assignments override it.
	if n.Kind() == "attribute" {
		obj := n.ChildByFieldName("object")
		key := pyText(m, n.ChildByFieldName("attribute"))
		if f.qualified(pyText(m, obj)) == "flask.request" {
			switch key {
			case "args", "form", "values", "json", "cookies", "headers", "data", "files", "GET", "POST", "META", "_params":
				return f.source(n, key, "")
			}
		}
		if f.qualified(pyText(m, obj)) == "flask.session" {
			return f.source(n, "session", key)
		}
		if f.qualified(pyText(m, obj)) == "flask.request.rel_url" && key == "query" {
			return f.source(n, "query", "")
		}
		if key == "payload" && f.set.receiver(m, pyText(m, obj), 0).kind == "flask_restx" {
			return f.source(n, "json", "")
		}
		v := f.eval(obj)
		if v.binding == "http_response" && (key == "text" || key == "content") {
			e := m.evidence("external_response_source", n)
			return pythonValue{deps: []pythonDep{{dep: analysis.Dependency{Source: e, Transfers: []analysis.Evidence{}}, protection: "raw"}}}
		}
		return f.projectValue(v, key, n)
	}
	obj := n.ChildByFieldName("value")
	index := n.ChildByFieldName("subscript")
	key, _ := pyLiteral(m, index)
	v := f.eval(obj)
	if f.route.route.Framework == "wsgi" && f.qualified(pyText(m, obj)) == "flask.request" && (key == "QUERY_STRING" || key == "PATH_INFO") {
		return f.source(n, "environ", key)
	}
	if f.qualified(pyText(m, obj)) == "flask.session" {
		return f.source(n, "session", key)
	}
	_ = text
	return f.projectValue(v, key, n)
}
func (f *pythonFlow) projectValue(v pythonValue, key string, n *sitter.Node) pythonValue {
	if field, ok := v.fields[key]; ok {
		return pyTransfer(field, f.module.evidence("field_projection", n))
	}
	if v.binding == "db_row" && v.table != "" {
		e := f.module.evidence("storage_source", n)
		return pythonValue{deps: []pythonDep{{dep: analysis.Dependency{Source: e, StorageKey: "python-sql:" + v.table + "." + key, Transfers: append([]analysis.Evidence{}, v.evidence...)}, protection: "raw"}}}
	}
	v = pyTransfer(v, f.module.evidence("field_projection", n))
	v.deps = append([]pythonDep{}, v.deps...)
	for i := range v.deps {
		if v.deps[i].key == "" {
			v.deps[i].key = key
			v.deps[i].dep.Transfers = append(v.deps[i].dep.Transfers, analysis.Evidence{Kind: "field_projection", Text: key, Span: spanOf(f.module.file, n), SHA256: f.module.hash})
		}
	}
	for _, d := range v.deps {
		if d.key != "" && d.container != "session" && d.dep.Source.Kind == "input_source" && f.inputs != nil {
			f.inputs[d.container+"."+d.key] = pythonValue{deps: []pythonDep{d}}
		}
	}
	return v
}

// qualified resolves a name to its import-qualified form. Quart's request
// proxy has the Flask request shape, so it shares that source model.
func (f *pythonFlow) qualified(name string) string {
	q := f.qualifiedRaw(name)
	for _, proxy := range []string{"quart.request", "bottle.request"} {
		if q == proxy || strings.HasPrefix(q, proxy+".") {
			return "flask.request" + strings.TrimPrefix(q, proxy)
		}
	}
	return q
}

func (f *pythonFlow) qualifiedRaw(name string) string {
	root := strings.Split(name, ".")[0]
	if value, shadow := f.env[root]; shadow {
		if value.binding == "flask_request" {
			return "flask.request" + strings.TrimPrefix(name, root)
		}
		return ""
	}
	if imp, ok := f.imports[root]; ok {
		q := imp.module
		if imp.name != "" {
			q += "." + imp.name
		}
		return q + strings.TrimPrefix(name, root)
	}
	if f.module.funcs[root] != nil || f.module.vars[root] != nil {
		return ""
	}
	return f.set.qualified(f.module, name)
}
