package langjs

import (
	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

// multerBinding is a verified multer middleware call: the module's multer
// import, the one multer(...) call the receiver is bound to, and the storage
// that call configures. multer documents the storage rule
// (https://github.com/expressjs/multer#multeropts): a `storage` engine is
// used when given, otherwise `dest` selects disk storage, otherwise uploads
// are kept in memory.
type multerBinding struct {
	declaration, ctor, call *sitter.Node
	method                  string       // single, array, fields, any or none
	config                  *sitter.Node // the options object of multer(...), nil when it has none
	storage                 string       // "memory" or "disk"
	engine                  *sitter.Node // the memoryStorage()/diskStorage(...) call, nil when storage is implied
	inline                  bool         // the storage option is the engine call itself
	options                 *sitter.Node // the options object of diskStorage(...)
	dest                    *sitter.Node // the value of the dest option, when it selects disk storage
	filter                  *sitter.Node // the value of the fileFilter option
}

var multerMethods = map[string]bool{"single": true, "array": true, "fields": true, "any": true, "none": true}

// multerMiddleware verifies that n is a middleware-building method call on a
// constant bound once to a call of the multer import. A dynamic option spread,
// a storage engine other than multer's own two and a storage value that does
// not resolve to one of them are not verified.
func multerMiddleware(m *sourceModule, n *sitter.Node) (multerBinding, bool) {
	var b multerBinding
	if n == nil || n.Kind() != "call_expression" {
		return b, false
	}
	fn, args := n.ChildByFieldName("function"), n.ChildByFieldName("arguments")
	if fn == nil || args == nil || fn.Kind() != "member_expression" {
		return b, false
	}
	obj, p := fn.ChildByFieldName("object"), fn.ChildByFieldName("property")
	if obj == nil || p == nil || obj.Kind() != "identifier" || !multerMethods[p.Utf8Text(m.src)] {
		return b, false
	}
	ctor := singleDeclaration(obj.Utf8Text(m.src), m.tree.RootNode(), m.src)
	if ctor == nil || ctor.Kind() != "call_expression" || ctor.StartByte() > n.StartByte() && n.Parent() == m.tree.RootNode() {
		return b, false
	}
	name, options := ctor.ChildByFieldName("function"), ctor.ChildByFieldName("arguments")
	if name == nil || name.Kind() != "identifier" || options == nil || options.NamedChildCount() > 1 {
		return b, false
	}
	library := name.Utf8Text(m.src)
	imp, ok := m.imports[library]
	if !ok || imp.module != "multer" || (imp.name != "default" && imp.name != "*") || shadowed(ctor, library, m.src) || bindingReassigned(m, library) {
		return b, false
	}
	b = multerBinding{declaration: imp.declaration, ctor: ctor, call: n, method: p.Utf8Text(m.src), storage: "memory"}
	if options.NamedChildCount() == 0 {
		return b, true
	}
	cfg := options.NamedChild(0)
	if cfg.Kind() != "object" {
		return b, false
	}
	for i := uint(0); i < cfg.NamedChildCount(); i++ {
		if cfg.NamedChild(i).Kind() == "spread_element" {
			return b, false
		}
	}
	b.config, b.filter = cfg, property(cfg, "fileFilter", m.src)
	storage := property(cfg, "storage", m.src)
	if storage == nil {
		if b.dest = property(cfg, "dest", m.src); b.dest != nil {
			b.storage = "disk"
		}
		return b, true
	}
	b.inline = storage.Kind() == "call_expression"
	if storage.Kind() == "identifier" && !shadowed(ctor, storage.Utf8Text(m.src), m.src) && !bindingReassigned(m, storage.Utf8Text(m.src)) {
		storage = topVariable(m, storage.Utf8Text(m.src))
	}
	if storage == nil || storage.Kind() != "call_expression" {
		return b, false
	}
	sf := storage.ChildByFieldName("function")
	if sf == nil || sf.Kind() != "member_expression" {
		return b, false
	}
	root, method := sf.ChildByFieldName("object"), sf.ChildByFieldName("property")
	if root == nil || method == nil || root.Utf8Text(m.src) != library {
		return b, false
	}
	b.engine = storage
	switch method.Utf8Text(m.src) {
	case "memoryStorage":
	case "diskStorage":
		b.storage = "disk"
		if a := storage.ChildByFieldName("arguments"); a != nil && a.NamedChildCount() > 0 {
			if b.options = a.NamedChild(0); b.options.Kind() != "object" {
				return b, false
			}
		}
	default:
		return b, false
	}
	return b, true
}

// pathUploadAdapter verifies a memory-storage multer.single binding. Custom
// fileFilter callbacks and dynamic option spreads remain unresolved controls.
func pathUploadAdapter(m *sourceModule, n *sitter.Node) []analysis.Evidence {
	b, ok := multerMiddleware(m, n)
	if !ok || b.method != "single" || b.storage != "memory" || !b.inline || b.filter != nil {
		return nil
	}
	args := n.ChildByFieldName("arguments")
	if args.NamedChildCount() != 1 {
		return nil
	}
	if _, ok := stringLiteral(args.NamedChild(0), m.src); !ok {
		return nil
	}
	return []analysis.Evidence{m.evidence("path_upload_binding", b.declaration), m.evidence("path_upload_binding", b.ctor), m.evidence("path_upload_binding", n)}
}
