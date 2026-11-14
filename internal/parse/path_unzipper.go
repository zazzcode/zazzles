package parse

import (
	sitter "github.com/tree-sitter/go-tree-sitter"
)

// unzipperBufferCall verifies the actual package binding for Open.buffer. It
// exposes archive metadata, not a promise that caller-selected writes are safe.
func unzipperBufferCall(m *sourceModule, n *sitter.Node) (*sitter.Node, *sitter.Node, bool) {
	if n == nil || n.Kind() != "call_expression" {
		return nil, nil, false
	}
	fn, args := n.ChildByFieldName("function"), n.ChildByFieldName("arguments")
	if fn == nil || args == nil || args.NamedChildCount() == 0 || fn.Kind() != "member_expression" {
		return nil, nil, false
	}
	obj, p := fn.ChildByFieldName("object"), fn.ChildByFieldName("property")
	if obj == nil || p == nil || p.Utf8Text(m.src) != "buffer" || obj.Kind() != "member_expression" {
		return nil, nil, false
	}
	root, member := obj.ChildByFieldName("object"), obj.ChildByFieldName("property")
	if root == nil || member == nil || member.Utf8Text(m.src) != "Open" || root.Kind() != "identifier" {
		return nil, nil, false
	}
	name := root.Utf8Text(m.src)
	imp, ok := m.imports[name]
	if !ok || imp.module != "unzipper" || (imp.name != "default" && imp.name != "*") || shadowed(n, name, m.src) || bindingReassigned(m, name) {
		return nil, nil, false
	}
	return args.NamedChild(0), imp.declaration, true
}

func (f *flow) pathArchiveValue(n *sitter.Node) (value, bool) {
	if arg, decl, ok := unzipperBufferCall(f.module, n); ok {
		v := f.transfer(f.eval(arg), "archive_open", n)
		v.pathArchive = "directory"
		if decl != nil {
			e := f.module.evidence("sink_binding", decl)
			v.pathArchiveBinding = &e
			f.context = append(f.context, e)
		}
		return v, true
	}
	if n.Kind() == "await_expression" && n.NamedChildCount() == 1 {
		child := n.NamedChild(0)
		if _, _, ok := unzipperBufferCall(f.module, child); ok {
			return f.transfer(f.eval(child), "archive_await", n), true
		}
	}
	if n.Kind() != "member_expression" {
		return value{}, false
	}
	obj, p := n.ChildByFieldName("object"), n.ChildByFieldName("property")
	if obj == nil || p == nil || (p.Utf8Text(f.module.src) != "files" && p.Utf8Text(f.module.src) != "path") {
		return value{}, false
	}
	if obj.Kind() != "identifier" {
		return value{}, false
	}
	v, exists := f.env[obj.Utf8Text(f.module.src)]
	if !exists || v.pathArchive == "" {
		return value{}, false
	}
	if v.pathArchive == "directory" && p.Utf8Text(f.module.src) == "files" {
		v.pathArchive = "files"
		return f.transfer(v, "archive_files", n), true
	}
	if v.pathArchive == "entry" && p.Utf8Text(f.module.src) == "path" {
		v.pathArchive = "path"
		return f.transfer(v, "archive_entry_path", n), true
	}
	return value{}, false
}

func (f *flow) pathArchiveForOf(n *sitter.Node) bool {
	left, right, body := n.ChildByFieldName("left"), n.ChildByFieldName("right"), n.ChildByFieldName("body")
	op := n.ChildByFieldName("operator")
	if left == nil || right == nil || body == nil || op == nil || op.Utf8Text(f.module.src) != "of" || left.Kind() != "identifier" {
		return false
	}
	known := false
	if right.Kind() == "identifier" {
		known = f.env[right.Utf8Text(f.module.src)].pathArchive == "files"
	}
	if right.Kind() == "member_expression" {
		obj, p := right.ChildByFieldName("object"), right.ChildByFieldName("property")
		known = obj != nil && p != nil && obj.Kind() == "identifier" && p.Utf8Text(f.module.src) == "files" && f.env[obj.Utf8Text(f.module.src)].pathArchive == "directory"
	}
	if !known {
		return false
	}
	v := f.eval(right)
	if v.pathArchive != "files" {
		return false
	}
	v.pathArchive = "entry"
	name := left.Utf8Text(f.module.src)
	old, had := f.env[name]
	f.env[name] = f.transfer(v, "archive_entry", left)
	f.context = append(f.context, f.module.evidence("archive_iteration", n))
	f.statement(body)
	if had {
		f.env[name] = old
	} else {
		delete(f.env, name)
	}
	return true
}
