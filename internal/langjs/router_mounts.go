package langjs

import (
	"fmt"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/parse"
)

func expressConstructor(m *sourceModule, fn *sitter.Node) bool {
	if fn.Kind() == "identifier" {
		imp := m.imports[fn.Utf8Text(m.src)]
		return m.express[fn.Utf8Text(m.src)] || (imp.module == "express" && imp.name == "Router")
	}
	if fn.Kind() == "member_expression" {
		obj, prop := fn.ChildByFieldName("object"), fn.ChildByFieldName("property")
		if obj != nil && prop != nil && prop.Utf8Text(m.src) == "Router" {
			imp := m.imports[obj.Utf8Text(m.src)]
			return imp.module == "express" && (imp.name == "*" || imp.name == "default") && !bindingReassigned(m, obj.Utf8Text(m.src))
		}
	}
	return false
}

func exportedReceiver(m *sourceModule) string {
	result := ""
	root := m.tree.RootNode()
	for i := uint(0); i < root.NamedChildCount(); i++ {
		n := root.NamedChild(i)
		var value *sitter.Node
		if n.Kind() == "expression_statement" && n.NamedChildCount() == 1 {
			a := n.NamedChild(0)
			left := a.ChildByFieldName("left")
			if a.Kind() == "assignment_expression" && left != nil && left.Utf8Text(m.src) == "module.exports" && !topLevelBinding(m, "module") {
				value = a.ChildByFieldName("right")
			}
		}
		if n.Kind() == "export_statement" {
			value = n.ChildByFieldName("value")
		}
		if value != nil && value.Kind() == "identifier" && m.receivers[value.Utf8Text(m.src)] && !bindingReassigned(m, value.Utf8Text(m.src)) {
			result = value.Utf8Text(m.src)
		} else if value != nil {
			result = ""
		}
	}
	return result
}

func (s *moduleSet) mountedRoutes(out *analysis.AnalysisReport, selected []string) {
	s.mountedOrigins = map[string]bool{}
	for _, file := range selected {
		if m := s.modules[file]; m != nil {
			s.scanMounts(out, m, m, "", 0, map[string]bool{})
		}
	}
	entries := []analysis.EntryPoint{}
	for _, entry := range out.Entries {
		if !s.mountedOrigins[entry.HTTPRoute().ID] {
			entries = append(entries, entry)
		}
	}
	uses := []analysis.CandidateUse{}
	for _, use := range out.Uses {
		if !s.mountedOrigins[use.EntryID] {
			uses = append(uses, use)
		}
	}
	out.Entries, out.Uses = entries, uses
	keep := map[string]bool{}
	for _, e := range entries {
		keep[e.ID] = true
	}
	out.SelectEntries(keep)
}

func (s *moduleSet) scanMounts(out *analysis.AnalysisReport, m, owner *sourceModule, prefix string, depth int, stack map[string]bool) {
	if depth > 3 || stack[m.file] {
		out.Gaps = append(out.Gaps, analysis.Gap{Kind: "router_mount_limit", Detail: "Router mount nesting is cyclic or exceeds three levels", At: parse.Span(m.file, m.tree.RootNode())})
		return
	}
	stack[m.file] = true
	defer delete(stack, m.file)
	walkCalls(m.tree.RootNode(), func(call *sitter.Node) {
		fn, args := call.ChildByFieldName("function"), call.ChildByFieldName("arguments")
		if fn == nil || fn.Kind() != "member_expression" || args == nil || args.NamedChildCount() < 2 {
			return
		}
		obj, prop := fn.ChildByFieldName("object"), fn.ChildByFieldName("property")
		if obj == nil || prop == nil || prop.Utf8Text(m.src) != "use" || !m.receivers[obj.Utf8Text(m.src)] || shadowed(call, obj.Utf8Text(m.src), m.src) {
			return
		}
		path, ok := stringLiteral(args.NamedChild(0), m.src)
		if !ok || !strings.HasPrefix(path, "/") {
			return
		}
		mount := args.NamedChild(args.NamedChildCount() - 1)
		imp, imported := m.imports[mount.Utf8Text(m.src)]
		if !imported || !strings.HasPrefix(imp.module, ".") || (imp.name != "*" && imp.name != "default") || bindingReassigned(m, mount.Utf8Text(m.src)) {
			return
		}
		target := s.importModule(m, imp.module)
		if target == nil {
			return
		}
		receiver := exportedReceiver(target)
		if receiver == "" {
			return
		}
		for i := range out.Entries {
			entry := &out.Entries[i]
			if entry.HTTPRoute().Method == "USE" && entry.HTTPRoute().Registration.File == m.file && entry.HTTPRoute().Registration.StartByte == int(call.StartByte()) {
				var gaps []analysis.Gap
				for _, gap := range entry.Gaps {
					if gap.Kind != "unresolved_handler" {
						gaps = append(gaps, gap)
					}
				}
				entry.Gaps = append(gaps, analysis.Gap{Kind: "router_container", Detail: "Imported router endpoints are listed separately; effective middleware remains unresolved.", At: entry.HTTPRoute().Registration})
			}
		}
		fullPrefix := strings.TrimRight(prefix, "/") + path
		context := []analysis.Evidence{m.evidence("router_mount", call), m.evidence("router_import", imp.declaration)}
		locals := map[string]*sitter.Node{}
		collectFuncs(target.tree.RootNode(), target.src, locals)
		walkCalls(target.tree.RootNode(), func(child *sitter.Node) {
			fn := child.ChildByFieldName("function")
			if fn == nil || fn.Kind() != "member_expression" {
				return
			}
			obj := fn.ChildByFieldName("object")
			if obj == nil || obj.Utf8Text(target.src) != receiver {
				return
			}
			if s.finiteRoutesAt(out, target, owner, child, receiver, fullPrefix, context) {
				return
			}
			routes, _ := routesFromCall(target.file, target.src, child, locals)
			for _, route := range routes {
				rawPath := route.PathPattern
				s.mountedOrigins[parse.HTTPEntry(route, target.evidence("entry_registration", child), target.file+":"+target.hash+":"+receiver).ID] = true
				route.PathPattern = strings.TrimRight(fullPrefix, "/") + "/" + strings.TrimLeft(route.PathPattern, "/")
				route.PathPattern = strings.TrimRight(route.PathPattern, "/")
				if route.PathPattern == "" {
					route.PathPattern = "/"
				}
				route.ID = fmt.Sprintf("%s:mount:%s:%d:%s", route.ID, m.file, call.StartByte(), fullPrefix)
				s.analyzeRoute(out, target, owner, route, child, receiver, context, rawPath, fullPrefix)
			}
		})
		s.scanMounts(out, target, owner, fullPrefix, depth+1, stack)
	})
}
