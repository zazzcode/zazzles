package langjs

import (
	"path/filepath"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
)

func definitionAt(m *sourceModule, reference *sitter.Node, name string) *sitter.Node {
	for parent := reference.Parent(); parent != nil; parent = parent.Parent() {
		if parent.Kind() != "statement_block" && parent.Kind() != "program" {
			continue
		}
		for i := uint(0); i < parent.NamedChildCount(); i++ {
			n := parent.NamedChild(i)
			if n.Kind() == "export_statement" {
				n = n.ChildByFieldName("declaration")
			}
			if n == nil || n.StartByte() >= reference.StartByte() || (n.Kind() != "lexical_declaration" && n.Kind() != "variable_declaration") {
				continue
			}
			for j := uint(0); j < n.NamedChildCount(); j++ {
				d := n.NamedChild(j)
				id := d.ChildByFieldName("name")
				if id != nil && id.Utf8Text(m.src) == name {
					return d.ChildByFieldName("value")
				}
			}
		}
	}
	return nil
}

func libraryObject(m *sourceModule, node *sitter.Node) string {
	if node == nil || node.Kind() != "identifier" {
		return ""
	}
	name := node.Utf8Text(m.src)
	if bindingReassigned(m, name) {
		return ""
	}
	if imp, ok := m.imports[name]; ok && !shadowed(node, name, m.src) {
		return imp.module
	}
	v := definitionAt(m, node, name)
	if v == nil {
		return ""
	}
	if path, _, ok := requireBinding(m, v); ok {
		return path
	}
	if v.Kind() == "member_expression" {
		prop := v.ChildByFieldName("property")
		if prop == nil || prop.Utf8Text(m.src) != "default" {
			return ""
		}
		v = v.ChildByFieldName("object")
	}
	for v != nil && (v.Kind() == "parenthesized_expression" || v.Kind() == "await_expression") && v.NamedChildCount() == 1 {
		v = v.NamedChild(0)
	}
	if v != nil && v.Kind() == "call_expression" {
		fn, args := v.ChildByFieldName("function"), v.ChildByFieldName("arguments")
		if fn != nil && fn.Utf8Text(m.src) == "import" && args != nil && args.NamedChildCount() == 1 {
			path, _ := stringLiteral(args.NamedChild(0), m.src)
			return path
		}
	}
	return ""
}

// readFileValue models an fs readFile/readFileSync result: a template file for
// a literal template path, otherwise file content with a file_read origin.
func (f *flow) readFileValue(call, args *sitter.Node) value {
	path, known := stringLiteral(args.NamedChild(0), f.module.src)
	v := value{}
	if known && (filepath.Ext(path) == ".pug" || filepath.Ext(path) == ".ejs" || filepath.Ext(path) == ".hbs" || filepath.Ext(path) == ".handlebars") {
		v.templateFile = path
		f.set.readText(path)
	} else {
		key := "file:" + path
		if !known {
			key = "file:unresolved:" + f.module.file
		}
		v.deps = []analysis.Dependency{{StorageKey: key, Source: f.module.evidence("file_read", call), Transfers: []analysis.Evidence{}}}
	}
	last := args.NamedChild(args.NamedChildCount() - 1)
	if isFunction(last) {
		f.modelCallback(last, v, "readFile")
	}
	return v
}

func (f *flow) templateCall(call, fn, args *sitter.Node) (value, bool) {
	if fn == nil || args == nil {
		return value{}, false
	}
	if fn.Kind() == "call_expression" {
		renderer := f.eval(fn)
		if renderer.outputHTML {
			return f.transfer(renderer, "template_execution", call), true
		}
		return value{}, false
	}
	if fn.Kind() == "identifier" {
		// A named fs import (`import { readFile } from "fs/promises"`) reads the
		// same file contents as fs.readFile; its result is file content, not
		// the request-derived path.
		if b, ok := f.nodeFSBinding(call, fn); ok && (b.op == "readFile" || b.op == "readFileSync") && args.NamedChildCount() > 0 {
			return f.readFileValue(call, args), true
		}
		name := fn.Utf8Text(f.module.src)
		if name == "String" && !moduleBinds(f.module, name) && args.NamedChildCount() == 1 {
			return f.transfer(f.eval(args.NamedChild(0)), "string_conversion", call), true
		}
		if renderer, ok := f.env[name]; ok && renderer.outputHTML {
			return f.transfer(renderer, "template_execution", call), true
		}
		return value{}, false
	}
	if fn.Kind() != "member_expression" {
		return value{}, false
	}
	obj, prop := fn.ChildByFieldName("object"), fn.ChildByFieldName("property")
	if obj == nil || prop == nil {
		return value{}, false
	}
	method := prop.Utf8Text(f.module.src)
	library := libraryObject(f.module, obj)
	if library == "fs" || library == "node:fs" || library == "fs/promises" || library == "node:fs/promises" {
		if (method == "readFile" || method == "readFileSync") && args.NamedChildCount() > 0 {
			return f.readFileValue(call, args), true
		}
	}
	if (library == "pug" || library == "ejs" || library == "handlebars") && (method == "compile" || method == "render") && args.NamedChildCount() > 0 {
		v := f.eval(args.NamedChild(0))
		v.outputHTML = true
		v.outputContext = "template_code"
		return f.transfer(v, "template_compilation", call), true
	}
	if method != "replace" && method != "toString" {
		return value{}, false
	}
	// Only inspect known locals or stored fields here. Evaluating arbitrary call
	// receivers twice would duplicate sinks and callback side effects.
	var receiver value
	if obj.Kind() == "identifier" {
		receiver = f.env[obj.Utf8Text(f.module.src)]
	} else if obj.Kind() == "member_expression" {
		receiver, _ = f.storedProperty(obj)
	}
	if method == "toString" && (receiver.templateFile != "" || len(receiver.deps) > 0) {
		return f.transfer(receiver, "string_conversion", call), true
	}
	if method == "replace" && (receiver.templateFile != "" || receiver.outputHTML) && args.NamedChildCount() >= 2 {
		replacement := f.eval(args.NamedChild(1))
		v := combine(receiver, replacement)
		if receiver.templateFile != "" && !receiver.outputHTML {
			v.outputContext = "template_code"
		} else if len(replacement.deps) > 0 {
			v.outputContext = responseOutputContext(args.NamedChild(1), f.module, "html_text")
		}
		v.outputHTML = true
		return f.transfer(v, "template_replacement", call), true
	}
	return value{}, false
}
