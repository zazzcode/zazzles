package langjs

import (
	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/parse"
)

// practicePersonal follows actual request-context values, never variable names.
func practicePersonal(m *sourceModule, n *sitter.Node, depth int) bool {
	n = practiceUnwrap(n)
	if n == nil || depth > 6 {
		return false
	}
	if n.Kind() == "identifier" || n.Kind() == "shorthand_property_identifier" {
		return practicePersonal(m, practiceConst(m, n), depth+1)
	}
	if n.Kind() == "call_expression" {
		fn := n.ChildByFieldName("function")
		if fn != nil {
			if imp, ok := m.imports[fn.Utf8Text(m.src)]; ok && !shadowed(n, fn.Utf8Text(m.src), m.src) {
				if imp.module == "next/headers" && (imp.name == "cookies" || imp.name == "headers") || imp.name == "auth" || imp.name == "getServerSession" {
					return true
				}
			}
		}
	}
	for i := uint(0); i < n.NamedChildCount(); i++ {
		if practicePersonal(m, n.NamedChild(i), depth+1) {
			return true
		}
	}
	return false
}

func (s *moduleSet) practiceCacheBoundaries(ps *practiceSet, m *sourceModule, out *analysis.AnalysisReport) {
	root := m.tree.RootNode()
	for _, e := range out.Entries {
		if e.HTTP == nil || e.Location.Span.File != m.file {
			continue
		}
		scope := parse.NodeAt(root, e.Location.Span.StartByte, e.Location.Span.EndByte)
		personal := false
		walkCalls(scope, func(n *sitter.Node) { personal = personal || practicePersonal(m, n, 0) })
		if !personal {
			continue
		}
		walkNodes(root, func(n *sitter.Node) {
			if n.Kind() != "variable_declarator" {
				return
			}
			parent := n.Parent()
			if parent != nil {
				parent = parent.Parent()
			}
			if parent == nil || parent.Kind() != "export_statement" {
				return
			}
			name, v := n.ChildByFieldName("name"), n.ChildByFieldName("value")
			if name == nil || v == nil {
				return
			}
			if name.Utf8Text(m.src) == "dynamic" && v.Utf8Text(m.src) == "'force-static'" || name.Utf8Text(m.src) == "dynamic" && v.Utf8Text(m.src) == `"force-static"` || name.Utf8Text(m.src) == "revalidate" && v.Utf8Text(m.src) != "0" && v.Utf8Text(m.src) != "false" {
				ps.add("NX-BP-15", "Shared caching with user context", "review", "an entry reads user context while exporting shared caching configuration", e.Name, m.evidence("cache_configuration", n))
			}
		})
		// Scope cache calls to this entry; unrelated functions elsewhere in the module
		// cannot inherit the entry's personal context.
		walkCalls(scope, func(call *sitter.Node) {
			fn, args := call.ChildByFieldName("function"), call.ChildByFieldName("arguments")
			if fn == nil || args == nil {
				return
			}
			cache := false
			if fn.Utf8Text(m.src) == "fetch" && !topLevelBinding(m, "fetch") && !shadowed(call, "fetch", m.src) && args.NamedChildCount() > 1 {
				mode, _ := stringLiteral(property(args.NamedChild(1), "cache", m.src), m.src)
				cache = mode == "force-cache" && practicePersonal(m, args, 0)
			}
			if imp, ok := m.imports[fn.Utf8Text(m.src)]; ok && imp.module == "next/cache" && imp.name == "unstable_cache" && !shadowed(call, fn.Utf8Text(m.src), m.src) {
				cache = practicePersonal(m, args, 0)
				if args.NamedChildCount() == 0 || practiceLiteral(m, args.NamedChild(0), 0) == nil {
					cache = true // An unresolved callback cannot establish independence from user context.
				}
				if cache && practiceCacheKeyed(m, scope, call, args) {
					cache = false
				}
			}
			if cache {
				ps.add("NX-BP-15", "Shared caching with user context", "review", "user-context data reaches shared caching without an established matching user-specific key", e.Name, m.evidence("cache_call", call))
			}
		})
	}
}

func practiceCacheKeyed(m *sourceModule, scope, call, args *sitter.Node) bool {
	if args.NamedChildCount() > 1 {
		key, captured := map[string]bool{}, map[string]bool{}
		practiceCacheSources(m, args.NamedChild(1), 0, key)
		practiceCacheSources(m, args.NamedChild(0), 0, captured)
		covered := len(captured) > 0
		for source := range captured {
			covered = covered && key[source]
		}
		if covered {
			return true
		}
	}
	// Arguments supplied to the returned cached function participate in its key.
	// Accept only direct local invocation and no personal closure capture.
	if args.NamedChildCount() == 0 || practicePersonal(m, args.NamedChild(0), 0) {
		return false
	}
	callback := practiceLiteral(m, args.NamedChild(0), 0)
	if callback == nil || !isFunction(callback) {
		return false
	}
	decl := call.Parent()
	if decl == nil || decl.Kind() != "variable_declarator" {
		return false
	}
	name := decl.ChildByFieldName("name")
	if name == nil {
		return false
	}
	found, all := false, true
	walkCalls(scope, func(n *sitter.Node) {
		fn, a := n.ChildByFieldName("function"), n.ChildByFieldName("arguments")
		if fn == nil || a == nil || fn.Utf8Text(m.src) != name.Utf8Text(m.src) {
			return
		}
		found = true
		all = all && practicePersonal(m, a, 0)
	})
	return found && all
}

// Keys must contain the actual primitive request value used by the cached
// computation. A whole cookie jar or a different cookie is not that identity.
func practiceCacheSources(m *sourceModule, n *sitter.Node, depth int, sources map[string]bool) {
	n = practiceUnwrap(n)
	if n == nil || depth > 12 {
		return
	}
	if n.Kind() == "identifier" || n.Kind() == "shorthand_property_identifier" {
		practiceCacheSources(m, practiceConst(m, n), depth+1, sources)
		return
	}
	if n.Kind() == "call_expression" {
		fn, args := n.ChildByFieldName("function"), n.ChildByFieldName("arguments")
		if fn != nil && fn.Kind() == "member_expression" && args != nil && args.NamedChildCount() == 1 {
			obj, prop := fn.ChildByFieldName("object"), fn.ChildByFieldName("property")
			key, literal := stringLiteral(args.NamedChild(0), m.src)
			if obj != nil && prop != nil && prop.Utf8Text(m.src) == "get" && literal {
				if kind := practiceContextKind(m, obj, 0); kind != "" {
					sources[kind+":"+key] = true
					return
				}
			}
		}
	}
	if n.Kind() == "member_expression" {
		if kind := practiceContextKind(m, n.ChildByFieldName("object"), 0); kind != "" && kind != "cookies" && kind != "headers" {
			sources[kind] = true
			return
		}
	}
	for i := uint(0); i < n.NamedChildCount(); i++ {
		practiceCacheSources(m, n.NamedChild(i), depth+1, sources)
	}
}

func practiceContextKind(m *sourceModule, n *sitter.Node, depth int) string {
	n = practiceUnwrap(n)
	if n == nil || depth > 6 {
		return ""
	}
	if n.Kind() == "identifier" {
		return practiceContextKind(m, practiceConst(m, n), depth+1)
	}
	if n.Kind() == "member_expression" {
		return practiceContextKind(m, n.ChildByFieldName("object"), depth+1)
	}
	if n.Kind() == "call_expression" {
		fn := n.ChildByFieldName("function")
		if fn != nil {
			if imp, ok := m.imports[fn.Utf8Text(m.src)]; ok && !shadowed(n, fn.Utf8Text(m.src), m.src) {
				if imp.module == "next/headers" && (imp.name == "cookies" || imp.name == "headers") {
					return imp.name
				}
				if imp.name == "auth" || imp.name == "getServerSession" {
					return imp.module + ":" + imp.name
				}
			}
		}
	}
	return ""
}
