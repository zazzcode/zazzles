package parse

import (
	"fmt"
	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
	"strings"
)

type pathHandlerTarget struct {
	module *sourceModule
	node   *sitter.Node
	index  int
}

// pathHandler resolves an explicit local export list without widening the shared
// resolver's historical records. The export clause itself must name the binding.
func (s *moduleSet) pathHandler(m *sourceModule, h *sitter.Node) (*sourceModule, *sitter.Node) {
	if hm, body, _, _ := s.handler(m, h); body != nil {
		return hm, body.Parent()
	}
	if h == nil || h.Kind() != "identifier" || shadowed(h, h.Utf8Text(m.src), m.src) {
		return nil, nil
	}
	imp, ok := m.imports[h.Utf8Text(m.src)]
	if !ok || !strings.HasPrefix(imp.module, ".") || bindingReassigned(m, h.Utf8Text(m.src)) {
		return nil, nil
	}
	target := s.importModule(m, imp.module)
	if target == nil || target.tree.RootNode().HasError() {
		return nil, nil
	}
	root := target.tree.RootNode()
	for i := uint(0); i < root.NamedChildCount(); i++ {
		n := root.NamedChild(i)
		if n.Kind() != "export_statement" || n.ChildByFieldName("source") != nil {
			continue
		}
		for j := uint(0); j < n.NamedChildCount(); j++ {
			clause := n.NamedChild(j)
			if clause.Kind() != "export_clause" {
				continue
			}
			for k := uint(0); k < clause.NamedChildCount(); k++ {
				item := clause.NamedChild(k)
				name, alias := item.ChildByFieldName("name"), item.ChildByFieldName("alias")
				if name == nil {
					continue
				}
				exported := name.Utf8Text(target.src)
				if alias != nil {
					exported = alias.Utf8Text(target.src)
				}
				if exported == imp.name && !bindingReassigned(target, name.Utf8Text(target.src)) {
					if fn := target.funcs[name.Utf8Text(target.src)]; fn != nil {
						return target, fn
					}
				}
			}
		}
	}
	return nil, nil
}

func appendPathAcquisition(out, extra *analysis.AnalysisReport) {
	var uses []analysis.CandidateUse
	for _, u := range extra.Uses {
		if u.Kind == "path_traversal_candidate" {
			uses = append(uses, u)
		}
	}
	if len(uses) == 0 {
		return
	}
	out.Entries = append(out.Entries, extra.Entries...)
	out.Registrations = append(out.Registrations, extra.Registrations...)
	out.DispatchBindings = append(out.DispatchBindings, extra.DispatchBindings...)
	out.Callables = append(out.Callables, extra.Callables...)
	out.InvocationContexts = append(out.InvocationContexts, extra.InvocationContexts...)
	out.Uses = append(out.Uses, uses...)
}

// pathConfiguredMounts admits mounts on verified configuration-function
// parameters that the historical mount inventory leaves unresolved.
func (s *moduleSet) pathConfiguredMounts(out *analysis.AnalysisReport, files []string) {
	for _, file := range files {
		m := s.modules[file]
		if m == nil {
			continue
		}
		walkCalls(m.tree.RootNode(), func(call *sitter.Node) {
			fn, args := call.ChildByFieldName("function"), call.ChildByFieldName("arguments")
			if fn == nil || args == nil || args.NamedChildCount() != 2 || fn.Kind() != "member_expression" {
				return
			}
			obj, p := fn.ChildByFieldName("object"), fn.ChildByFieldName("property")
			if obj == nil || p == nil || p.Utf8Text(m.src) != "use" || !shadowed(call, obj.Utf8Text(m.src), m.src) || !parameterReceiver(m, call, obj.Utf8Text(m.src)) {
				return
			}
			prefix, ok := stringLiteral(args.NamedChild(0), m.src)
			if !ok || !strings.HasPrefix(prefix, "/") {
				return
			}
			ref := args.NamedChild(1)
			imp, ok := m.imports[ref.Utf8Text(m.src)]
			if !ok || imp.name != "default" || bindingReassigned(m, ref.Utf8Text(m.src)) {
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
			context := []analysis.Evidence{m.evidence("router_mount", call), m.evidence("router_import", imp.declaration)}
			locals := map[string]*sitter.Node{}
			collectFuncs(target.tree.RootNode(), target.src, locals)
			walkCalls(target.tree.RootNode(), func(child *sitter.Node) {
				c := child.ChildByFieldName("function")
				if c == nil || c.Kind() != "member_expression" {
					return
				}
				o := c.ChildByFieldName("object")
				if o == nil || o.Utf8Text(target.src) != receiver {
					return
				}
				routes, _ := routesFromCall(target.file, target.src, child, locals)
				for _, r := range routes {
					raw := r.PathPattern
					r.PathPattern = strings.TrimRight(prefix, "/") + "/" + strings.TrimLeft(raw, "/")
					r.PathPattern = strings.TrimRight(r.PathPattern, "/")
					if r.PathPattern == "" {
						r.PathPattern = "/"
					}
					r.ID = fmt.Sprintf("%s:path-mount:%s:%d", r.ID, m.file, call.StartByte())
					a := child.ChildByFieldName("arguments")
					if a == nil || a.NamedChildCount() < 2 {
						continue
					}
					h := a.NamedChild(a.NamedChildCount() - 1)
					hm, node := s.pathHandler(target, h)
					if hm == nil {
						continue
					}
					extra := &analysis.AnalysisReport{}
					s.analyzeHTTPHandler(extra, target, m, r, child, receiver, context, raw, prefix, nil, h, pathHandlerTarget{module: hm, node: node, index: int(a.NamedChildCount() - 1)})
					appendPathAcquisition(out, extra)
				}
			})
		})
	}
}
