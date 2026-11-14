package parse

import (
	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
)

// pathUploadAdapter verifies a memory-storage multer.single binding. Custom
// fileFilter callbacks and dynamic option spreads remain unresolved controls.
func pathUploadAdapter(m *sourceModule, n *sitter.Node) []analysis.Evidence {
	if n == nil || n.Kind() != "call_expression" {
		return nil
	}
	fn, args := n.ChildByFieldName("function"), n.ChildByFieldName("arguments")
	if fn == nil || args == nil || args.NamedChildCount() != 1 || fn.Kind() != "member_expression" {
		return nil
	}
	obj, p := fn.ChildByFieldName("object"), fn.ChildByFieldName("property")
	if obj == nil || p == nil || obj.Kind() != "identifier" || p.Utf8Text(m.src) != "single" {
		return nil
	}
	if _, ok := stringLiteral(args.NamedChild(0), m.src); !ok {
		return nil
	}
	ctor := singleDeclaration(obj.Utf8Text(m.src), m.tree.RootNode(), m.src)
	if ctor == nil || ctor.Kind() != "call_expression" || ctor.StartByte() > n.StartByte() && n.Parent() == m.tree.RootNode() {
		return nil
	}
	name, options := ctor.ChildByFieldName("function"), ctor.ChildByFieldName("arguments")
	if name == nil || name.Kind() != "identifier" || options == nil || options.NamedChildCount() != 1 {
		return nil
	}
	imp, ok := m.imports[name.Utf8Text(m.src)]
	if !ok || imp.module != "multer" || (imp.name != "default" && imp.name != "*") || shadowed(ctor, name.Utf8Text(m.src), m.src) || bindingReassigned(m, name.Utf8Text(m.src)) {
		return nil
	}
	cfg := options.NamedChild(0)
	if cfg.Kind() != "object" || property(cfg, "fileFilter", m.src) != nil {
		return nil
	}
	for i := uint(0); i < cfg.NamedChildCount(); i++ {
		if cfg.NamedChild(i).Kind() == "spread_element" {
			return nil
		}
	}
	storage := property(cfg, "storage", m.src)
	if storage == nil || storage.Kind() != "call_expression" {
		return nil
	}
	sf := storage.ChildByFieldName("function")
	if sf == nil || sf.Kind() != "member_expression" {
		return nil
	}
	root, method := sf.ChildByFieldName("object"), sf.ChildByFieldName("property")
	if root == nil || method == nil || root.Utf8Text(m.src) != name.Utf8Text(m.src) || method.Utf8Text(m.src) != "memoryStorage" {
		return nil
	}
	return []analysis.Evidence{m.evidence("path_upload_binding", imp.declaration), m.evidence("path_upload_binding", ctor), m.evidence("path_upload_binding", n)}
}
