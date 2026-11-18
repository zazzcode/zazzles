package langjs

import (
	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
	"strings"
)

func (s *moduleSet) practiceModuleBoundaries(ps *practiceSet, m *sourceModule, client bool, out *analysis.AnalysisReport) {
	root := m.tree.RootNode()
	walkCalls(root, func(call *sitter.Node) {
		fn, args := call.ChildByFieldName("function"), call.ChildByFieldName("arguments")
		if fn == nil || args == nil {
			return
		}
		text := fn.Utf8Text(m.src)
		if s.verifiedCookieWrite(m, call) {
			practiceCookieOptions(ps, m, call, args)
		}
		if client && (text == "postMessage" || text == "window.postMessage" || strings.HasSuffix(text, ".postMessage")) && args.NamedChildCount() >= 2 {
			target, ok := stringLiteral(args.NamedChild(1), m.src)
			if ok && target == "*" && sensitiveExpression(m, args.NamedChild(0)) {
				ps.add("NX-BP-21", "Sensitive wildcard message", "review", "sensitive-named data is sent with targetOrigin '*'; confirm the recipient boundary", "", m.evidence("message_send", call))
			}
		}
		if client && (text == "addEventListener" || text == "window.addEventListener") && args.NamedChildCount() >= 2 {
			event, _ := stringLiteral(args.NamedChild(0), m.src)
			cb := args.NamedChild(1)
			if event != "message" || !isFunction(cb) {
				return
			}
			params := nextParams(cb, m.src)
			if len(params) == 0 || params[0].name == "" {
				return
			}
			name := params[0].name
			body := cb.ChildByFieldName("body")
			if body == nil {
				return
			}
			if practiceMessageUnenforced(m, cb, body, name) {
				ps.add("NX-BP-21", "Message data without enforcing origin check", "review", "the message listener consumes "+name+".data without an established enforcing origin check before that use; confirm the sender boundary", "", m.evidence("message_listener", cb))
			}
		}
	})
	s.practiceCacheBoundaries(ps, m, out)
	s.practiceSensitiveResponses(ps, m, out)
}

func walkNodes(n *sitter.Node, visit func(*sitter.Node)) {
	if n == nil {
		return
	}
	visit(n)
	for i := uint(0); i < n.NamedChildCount(); i++ {
		walkNodes(n.NamedChild(i), visit)
	}
}

func sensitiveExpression(m *sourceModule, n *sitter.Node) bool {
	if n == nil {
		return false
	}
	sensitive := false
	walkIdentifiers(n, func(id *sitter.Node) {
		name := id.Utf8Text(m.src)
		sensitive = sensitive || secretName.MatchString(name) || strings.EqualFold(name, "email")
	})
	text := strings.ToLower(n.Utf8Text(m.src))
	return sensitive || strings.Contains(text, ".email") || strings.Contains(text, ".password") || strings.Contains(text, ".token")
}

func (s *moduleSet) practiceSensitiveResponses(ps *practiceSet, m *sourceModule, out *analysis.AnalysisReport) {
	// Proven whole-row ORM returns retain a model/read marker. A field projection
	// containing only non-sensitive fields does not produce this observation.
	for _, p := range s.producers {
		if p.sink.Span.File != m.file || !nextFramework(p.route.Framework) {
			continue
		}
		if s.sensitiveBrowserValue(p.value) {
			ps.add("NX-BP-18", "Sensitive fields in browser response", "review", "a JSON response exposes sensitive-named fields or a whole database row; project only the browser's required fields", p.route.Method+" "+p.route.PathPattern, p.sink)
		}
	}
	for _, e := range out.Entries {
		if e.HTTP == nil || e.HTTP.Surface != "server_action" || e.Location.Span.File != m.file {
			continue
		}
		// Action observations require an argument reaching a recorded use. Validator
		// evidence and authorization context are evaluated on that same entry.
		for _, u := range out.Uses {
			if u.Kind == "input_validation_candidate" || u.Kind == "xss_data_candidate" {
				continue
			}
			if u.EntryID != e.ID || len(u.Dependencies) == 0 {
				continue
			}
			if !practiceValueValidated(value{deps: u.Dependencies}) {
				ps.add("NX-BP-09", "Server Action arguments reach a sensitive use", "review", "public Server Action arguments reach a sink without established validation of every request-derived value; authorization is a separate boundary", e.Name, e.Location, u.Sink)
			}
		}
	}
}

func (s *moduleSet) verifiedCookieWrite(m *sourceModule, call *sitter.Node) bool {
	fn := call.ChildByFieldName("function")
	if fn == nil || fn.Kind() != "member_expression" {
		return false
	}
	obj, prop := fn.ChildByFieldName("object"), fn.ChildByFieldName("property")
	if obj == nil || prop == nil || prop.Utf8Text(m.src) != "set" {
		return false
	}
	obj = unwrapTS(obj)
	if obj.Kind() == "await_expression" && obj.NamedChildCount() == 1 {
		obj = unwrapTS(obj.NamedChild(0))
	}
	if obj.Kind() == "identifier" {
		obj = unwrapTS(localInitializer(m, call, obj.Utf8Text(m.src)))
		if obj == nil {
			return false
		}
		if obj.Kind() == "await_expression" && obj.NamedChildCount() == 1 {
			obj = unwrapTS(obj.NamedChild(0))
		}
	}
	if obj.Kind() == "call_expression" {
		callee := obj.ChildByFieldName("function")
		if callee == nil {
			return false
		}
		name := callee.Utf8Text(m.src)
		imp, ok := m.imports[name]
		return ok && imp.module == "next/headers" && imp.name == "cookies" && !shadowed(call, name, m.src)
	}
	if obj.Kind() != "member_expression" {
		return false
	}
	recv, key := obj.ChildByFieldName("object"), obj.ChildByFieldName("property")
	if recv == nil || key == nil || key.Utf8Text(m.src) != "cookies" {
		return false
	}
	if recv.Kind() == "identifier" {
		recv = unwrapTS(localInitializer(m, call, recv.Utf8Text(m.src)))
	}
	if recv == nil {
		return false
	}
	ctor := recv.ChildByFieldName("constructor")
	if ctor == nil {
		ctor = recv.ChildByFieldName("function")
	}
	if ctor == nil {
		return false
	}
	name := strings.Split(ctor.Utf8Text(m.src), ".")[0]
	imp, ok := m.imports[name]
	return ok && imp.module == "next/server" && imp.name == "NextResponse" && !shadowed(call, name, m.src)
}
