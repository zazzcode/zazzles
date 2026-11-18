package langjs

import (
	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/parse"
)

// httpPredecessors includes only supported earlier matching stages that forward
// through next(). Other earlier registrations remain an applicability gap, not a
// source of borrowed protection. Later declarations never protect an earlier use.
func (s *moduleSet) httpPredecessors(m *sourceModule, entry analysis.EntryPoint, current *sitter.Node) ([]*sitter.Node, []analysis.Gap) {
	calls := []*sitter.Node{}
	gaps := []analysis.Gap{}
	if entry.HTTP == nil || entry.HTTP.Receiver == "" {
		return calls, gaps
	}
	locals := map[string]*sitter.Node{}
	collectFuncs(m.tree.RootNode(), m.src, locals)
	count := 0
	walkCalls(m.tree.RootNode(), func(call *sitter.Node) {
		if call.StartByte() >= current.StartByte() {
			return
		}
		fn := call.ChildByFieldName("function")
		if fn == nil || fn.Kind() != "member_expression" {
			return
		}
		obj := fn.ChildByFieldName("object")
		if obj == nil || obj.Utf8Text(m.src) != entry.HTTP.Receiver || shadowed(call, obj.Utf8Text(m.src), m.src) {
			return
		}
		routes, _ := routesFromCall(m.file, m.src, call, locals)
		path := entry.HTTP.SourcePath
		if path == "" {
			path = entry.HTTP.Path
		}
		matches := false
		for _, r := range routes {
			matches = matches || ((r.Method == entry.HTTP.Method || r.Method == "ALL") && r.PathPattern == path)
		}
		if !matches {
			return
		}
		count++
		if count > 128 {
			if count == 129 {
				gaps = append(gaps, analysis.Gap{Kind: "prior_registration_limit", Detail: "Earlier matching registration expansion exceeded 128 stages", At: parse.Span(m.file, call)})
			}
			return
		}
		parent := call.Parent()
		direct := parent != nil && parent.Kind() == "expression_statement" && parent.Parent() != nil && parent.Parent().Kind() == "program"
		args := call.ChildByFieldName("arguments")
		forward := direct && args != nil
		if forward {
			for i := uint(1); i < args.NamedChildCount(); i++ {
				hm, body, _, missing := s.handler(m, args.NamedChild(i))
				if body == nil || len(missing) > 0 || !forwardsNext(hm, body) {
					forward = false
					break
				}
			}
		}
		if forward {
			calls = append(calls, call)
		} else {
			gaps = append(gaps, analysis.Gap{Kind: "prior_dispatch_unresolved", Detail: "Earlier matching registration may terminate or conditionally forward; its controls are not assumed applicable", At: parse.Span(m.file, call)})
		}
	})
	return calls, gaps
}

func forwardsNext(m *sourceModule, body *sitter.Node) bool {
	next := handlerParameter(body, 2, m.src)
	if next == "" || body.Kind() != "statement_block" || body.NamedChildCount() == 0 {
		return false
	}
	last := body.NamedChild(body.NamedChildCount() - 1)
	if (last.Kind() != "expression_statement" && last.Kind() != "return_statement") || last.NamedChildCount() != 1 {
		return false
	}
	call := last.NamedChild(0)
	fn := call.ChildByFieldName("function")
	if call.Kind() != "call_expression" || fn == nil || fn.Kind() != "identifier" || fn.Utf8Text(m.src) != next {
		return false
	}
	args := call.ChildByFieldName("arguments")
	if args == nil || args.NamedChildCount() != 0 {
		return false
	}
	count := 0
	escapes := false
	walkCalls(body, func(call *sitter.Node) {
		fn := call.ChildByFieldName("function")
		if fn != nil && fn.Kind() == "identifier" && fn.Utf8Text(m.src) == next {
			count++
		}
		args := call.ChildByFieldName("arguments")
		if args != nil {
			for i := uint(0); i < args.NamedChildCount(); i++ {
				if args.NamedChild(i).Utf8Text(m.src) == next {
					escapes = true
				}
			}
		}
	})
	var inspect func(*sitter.Node)
	inspect = func(n *sitter.Node) {
		if n.Kind() == "identifier" && n.Utf8Text(m.src) == next && (n.StartByte() != fn.StartByte() || n.EndByte() != fn.EndByte()) {
			escapes = true
		}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			inspect(n.NamedChild(i))
		}
	}
	inspect(body)
	return count == 1 && !escapes
}
