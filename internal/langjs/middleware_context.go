package langjs

import (
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/parse"
)

// middlewareContext preserves applicable earlier USE registrations. Built-in
// transport/parser adapters are declared assumptions, not custom validator guidelines.
func (s *moduleSet) middlewareContext(m *sourceModule, route analysis.Route) ([]analysis.Evidence, []analysis.Gap) {
	out := []analysis.Evidence{}
	gaps := []analysis.Gap{}
	seen := map[string]bool{}
	walkCalls(m.tree.RootNode(), func(call *sitter.Node) {
		if int(call.StartByte()) >= route.Registration.StartByte {
			return
		}
		fn := call.ChildByFieldName("function")
		if fn == nil || fn.Kind() != "member_expression" {
			return
		}
		obj := fn.ChildByFieldName("object")
		prop := fn.ChildByFieldName("property")
		if obj == nil || prop == nil || prop.Utf8Text(m.src) != "use" || !m.receivers[obj.Utf8Text(m.src)] {
			return
		}
		args := call.ChildByFieldName("arguments")
		if args == nil || args.NamedChildCount() == 0 {
			return
		}
		first := uint(0)
		if args.NamedChild(0).Kind() == "array" {
			paths, dynamic, _ := pathArgs(args.NamedChild(0), m.src)
			if dynamic {
				gaps = append(gaps, analysis.Gap{Kind: "middleware_mount_unresolved", Detail: "dynamic middleware path array", At: parse.Span(m.file, call)})
				return
			}
			applies := false
			for _, path := range paths {
				if path == "/" || route.PathPattern == path || strings.HasPrefix(route.PathPattern, path+"/") {
					applies = true
				}
			}
			if !applies {
				return
			}
			first = 1
		}
		if path, ok := stringLiteral(args.NamedChild(0), m.src); ok {
			if strings.ContainsAny(path, "*:?()+[]") {
				prefix := path
				for i, c := range path {
					if strings.ContainsRune("*:?()+[]", c) {
						prefix = path[:i]
						break
					}
				}
				if prefix != "" && !strings.HasPrefix(route.PathPattern, prefix) && route.PathPattern != strings.TrimSuffix(prefix, "/") {
					return
				}
				gaps = append(gaps, analysis.Gap{Kind: "middleware_mount_unresolved", Detail: "pattern middleware applicability requires a framework path model", At: parse.Span(m.file, call)})
			} else if path != "/" && route.PathPattern != path && !strings.HasPrefix(route.PathPattern, path+"/") {
				return
			}
			first = 1
		}
		out = append(out, m.evidence("middleware_registration", call))
		for i := first; i < args.NamedChildCount(); i++ {
			arg := args.NamedChild(i)
			if adapter := middlewareAdapterEvidence(m, arg); len(adapter) > 0 {
				out = append(out, adapter...)
				continue
			}
			if transportMiddleware(m, arg) {
				continue
			}
			hm, body, _, more := s.handler(m, arg)
			if body == nil {
				for _, g := range more {
					g.Kind = "applicable_middleware_unresolved"
					gaps = append(gaps, g)
				}
				continue
			}
			if headerOnlyMiddleware(hm, body) && !stableMiddleware(m, arg, hm, body) {
				more = append(more, analysis.Gap{Kind: "applicable_middleware_unresolved", Detail: "middleware binding is mutable or escapes; original declaration alone does not establish its effective behavior", At: parse.Span(m.file, arg)})
			}
			// The full source is usable for judging even when the dependency engine
			// cannot lower a destructured URL-only request parameter.
			for _, g := range more {
				if g.Kind != "request_projection_unresolved" {
					gaps = append(gaps, g)
				}
			}
			evidence := hm.evidence("middleware_handler", body)
			if len(more) == 0 && stableMiddleware(m, arg, hm, body) && headerOnlyMiddleware(hm, body) {
				evidence.Kind = "middleware_summary"
				evidence.ModelText = middlewareSummary(hm, body)
				out = append(out, evidence)
				continue
			}
			out = append(out, evidence)
			s.includeHelpers(hm, body, &out, seen, 0)
		}
	})
	return out, gaps
}

// noteMiddlewareFields records request fields read by applicable app.use middleware
// and by middleware arguments on this route registration. A read is not proof
// that the middleware rejects a bad value.
func (s *moduleSet) noteMiddlewareFields(f *flow, registration *sourceModule, call *sitter.Node) {
	if f == nil || f.facts == nil || registration == nil {
		return
	}
	if call != nil {
		args := call.ChildByFieldName("arguments")
		if args != nil && args.NamedChildCount() > 2 {
			for i := uint(1); i+1 < args.NamedChildCount(); i++ {
				s.markMiddlewareArg(f, registration, args.NamedChild(i))
			}
		}
	}
	evidence, _ := s.middlewareContext(registration, f.entry.HTTPRoute())
	for _, item := range evidence {
		if item.Kind != "middleware_handler" {
			continue
		}
		module := s.modules[item.Span.File]
		if module == nil {
			continue
		}
		body := parse.NodeAt(module.tree.RootNode(), item.Span.StartByte, item.Span.EndByte)
		if body == nil || body.Parent() == nil {
			continue
		}
		markMiddlewareFields(f, module, body, requestParamName(body.Parent(), module.src))
	}
}

func (s *moduleSet) markMiddlewareArg(f *flow, m *sourceModule, arg *sitter.Node) {
	target, body, req, _ := s.handler(m, arg)
	if body == nil || target == nil || req == "" {
		return
	}
	markMiddlewareFields(f, target, body, req)
}

func markMiddlewareFields(f *flow, m *sourceModule, body *sitter.Node, req string) {
	if f.facts == nil || body == nil || req == "" {
		return
	}
	var walk func(*sitter.Node)
	walk = func(n *sitter.Node) {
		if n == nil {
			return
		}
		if n.Kind() == "if_statement" {
			if condition := n.ChildByFieldName("condition"); condition != nil && weakPredicate(condition.Utf8Text(m.src)) {
				markWeakFields(f, m, condition, req)
			}
		}
		if isRequestField(n, m.src, req) {
			node := n
			if field := requestFieldNode(n, m.src, req); field != nil {
				node = field
			}
			f.facts.middleware[node.Utf8Text(m.src)] = true
		}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			walk(n.NamedChild(i))
		}
	}
	walk(body)
}

func markWeakFields(f *flow, m *sourceModule, condition *sitter.Node, req string) {
	if f.facts == nil || condition == nil {
		return
	}
	var walk func(*sitter.Node)
	walk = func(n *sitter.Node) {
		if n == nil {
			return
		}
		if isRequestField(n, m.src, req) {
			node := n
			if field := requestFieldNode(n, m.src, req); field != nil {
				node = field
			}
			f.facts.weak[node.Utf8Text(m.src)] = true
		}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			walk(n.NamedChild(i))
		}
	}
	walk(condition)
}

func requestParamName(fn *sitter.Node, src []byte) string {
	params := fn.ChildByFieldName("parameters")
	if params == nil || params.NamedChildCount() == 0 {
		return ""
	}
	p := params.NamedChild(0)
	if p.Kind() == "required_parameter" || p.Kind() == "optional_parameter" {
		p = p.ChildByFieldName("pattern")
	}
	if p != nil && p.Kind() == "identifier" {
		return p.Utf8Text(src)
	}
	return ""
}

func transportMiddleware(m *sourceModule, n *sitter.Node) bool {
	if n.Kind() == "call_expression" {
		n = n.ChildByFieldName("function")
	}
	if n == nil {
		return false
	}
	name := n.Utf8Text(m.src)
	if parts := strings.Split(name, "."); len(parts) > 1 {
		name = parts[0]
	}
	imp, ok := m.imports[name]
	if !ok {
		return false
	}
	switch imp.module {
	case "express", "body-parser", "cookie-parser", "compression", "morgan", "cors", "helmet", "i18n", "feature-policy", "express-robots-txt":
		return true
	}
	return false
}
