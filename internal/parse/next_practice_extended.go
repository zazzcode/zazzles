package parse

import (
	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
	"strings"
)

// practiceConfigBoundaries examines only resolved literal configuration members.
func (s *moduleSet) practiceConfigBoundaries(ps *practiceSet, p *nextProject) {
	c := s.nextConfig(p)
	if c == nil || c.object == nil {
		return
	}
	m := c.module
	images := property(c.object, "images", m.src)
	if images != nil {
		if patterns := property(images, "remotePatterns", m.src); patterns != nil && patterns.Kind() == "array" {
			for i := uint(0); i < patterns.NamedChildCount(); i++ {
				item := patterns.NamedChild(i)
				if host, ok := stringLiteral(property(item, "hostname", m.src), m.src); ok && strings.Contains(host, "*") {
					ps.add("NX-BP-13", "Broad image optimizer source", "observed", "images.remotePatterns permits wildcard hostname "+host, "", m.evidence("image_configuration", item))
				}
			}
		}
		if svg := property(images, "dangerouslyAllowSVG", m.src); svg != nil && svg.Utf8Text(m.src) == "true" && property(images, "contentSecurityPolicy", m.src) == nil {
			ps.add("NX-BP-13", "SVG optimizer without content policy", "observed", "dangerouslyAllowSVG is enabled without an images.contentSecurityPolicy", "", m.evidence("image_configuration", images))
		}
	}
	exp := property(c.object, "experimental", m.src)
	if exp == nil {
		return
	}
	actions := property(exp, "serverActions", m.src)
	if actions == nil {
		return
	}
	origins := property(actions, "allowedOrigins", m.src)
	if origins == nil || origins.Kind() != "array" {
		return
	}
	for i := uint(0); i < origins.NamedChildCount(); i++ {
		item := origins.NamedChild(i)
		if origin, ok := stringLiteral(item, m.src); ok && strings.Contains(origin, "*") {
			ps.add("NX-BP-14", "Wildcard Server Action origins", "observed", "serverActions.allowedOrigins contains "+origin, "", m.evidence("action_origin", item))
		}
	}
}

func (s *moduleSet) practiceModuleBoundaries(ps *practiceSet, m *sourceModule, client bool, out *analysis.AnalysisReport) {
	root := m.tree.RootNode()
	walkCalls(root, func(call *sitter.Node) {
		fn, args := call.ChildByFieldName("function"), call.ChildByFieldName("arguments")
		if fn == nil || args == nil {
			return
		}
		text := fn.Utf8Text(m.src)
		if s.verifiedCookieWrite(m, call) {
			var options *sitter.Node
			if args.NamedChildCount() >= 3 {
				options = unwrapTS(args.NamedChild(2))
			}
			if args.NamedChildCount() == 1 {
				options = unwrapTS(args.NamedChild(0))
			}
			if options != nil && options.Kind() != "object" {
				return
			}
			var missing []string
			for _, key := range []string{"httpOnly", "secure", "sameSite"} {
				var v *sitter.Node
				if options != nil {
					v = property(options, key, m.src)
				}
				if v == nil || v.Utf8Text(m.src) == "false" || key == "secure" && strings.Contains(v.Utf8Text(m.src), "NODE_ENV") {
					missing = append(missing, key)
				}
			}
			if len(missing) > 0 {
				ps.add("NX-BP-11", "Cookie security options", "observed", "cookie write omits or conditionally disables "+strings.Join(missing, ", "), "", m.evidence("cookie_write", call))
			}
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
			data, origin := false, false
			walkNodes(body, func(n *sitter.Node) {
				if n.Kind() == "member_expression" && n.Utf8Text(m.src) == name+".data" {
					data = true
				}
				if n.Kind() == "binary_expression" && (strings.Contains(n.Utf8Text(m.src), "===") || strings.Contains(n.Utf8Text(m.src), "!==")) && strings.Contains(n.Utf8Text(m.src), name+".origin") {
					origin = true
				}
			})
			if data && !origin {
				ps.add("NX-BP-21", "Message data without origin comparison", "review", "the message listener reads "+name+".data without comparing "+name+".origin; confirm the sender boundary", "", m.evidence("message_listener", cb))
			}
		}
	})
	// Caching checks apply to a registered entry that reads user context.
	for _, e := range out.Entries {
		if e.HTTP == nil || e.Location.Span.File != m.file {
			continue
		}
		personal := false
		scope := nodeAt(root, e.Location.Span.StartByte, e.Location.Span.EndByte)
		walkCalls(scope, func(call *sitter.Node) {
			fn := call.ChildByFieldName("function")
			if fn == nil {
				return
			}
			name := fn.Utf8Text(m.src)
			imp, ok := m.imports[name]
			if ok && !shadowed(call, name, m.src) {
				personal = personal || imp.module == "next/headers" && (imp.name == "cookies" || imp.name == "headers") || imp.name == "auth" || imp.name == "getServerSession"
			}
		})
		if !personal {
			continue
		}
		walkNodes(root, func(n *sitter.Node) {
			if n.Kind() == "variable_declarator" {
				name, v := n.ChildByFieldName("name"), n.ChildByFieldName("value")
				if name == nil || v == nil {
					return
				}
				if name.Utf8Text(m.src) == "dynamic" && strings.Contains(v.Utf8Text(m.src), "force-static") || name.Utf8Text(m.src) == "revalidate" && v.Utf8Text(m.src) != "0" && v.Utf8Text(m.src) != "false" {
					ps.add("NX-BP-15", "Shared caching with user context", "review", "an entry reads cookies, headers or auth while declaring shared caching; verify that user identity participates in its cache key", e.Name, m.evidence("cache_configuration", n))
				}
			}
			if n.Kind() == "call_expression" {
				fn, args := n.ChildByFieldName("function"), n.ChildByFieldName("arguments")
				if fn == nil || args == nil {
					return
				}
				cache := false
				if fn.Utf8Text(m.src) == "fetch" && !topLevelBinding(m, "fetch") && !shadowed(n, "fetch", m.src) && args.NamedChildCount() > 1 {
					if setting := property(args.NamedChild(1), "cache", m.src); setting != nil {
						mode, _ := stringLiteral(setting, m.src)
						cache = mode == "force-cache"
					}
				}
				if imp, ok := m.imports[fn.Utf8Text(m.src)]; ok && imp.module == "next/cache" && imp.name == "unstable_cache" {
					cache = true
					if args.NamedChildCount() > 1 && cacheKeyHasIdentity(m, args.NamedChild(1)) {
						cache = false
					}
				}
				if cache {
					ps.add("NX-BP-15", "Shared caching with user context", "review", "an entry reads user context and uses shared caching without an established user-specific key", e.Name, m.evidence("cache_call", n))
				}
			}
		})
	}
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
			validation, auth := false, false
			for _, c := range u.Context {
				validation = validation || c.Kind == "validation_control"
				auth = auth || c.Kind == "authorization_context"
			}
			for _, d := range u.Dependencies {
				for _, tr := range d.Transfers {
					validation = validation || tr.Kind == "validated_parse"
				}
			}
			if !validation && !auth {
				ps.add("NX-BP-09", "Server Action arguments reach a sensitive use", "review", "public Server Action arguments reach a sink without an established enforcing validator or authorization context", e.Name, e.Location, u.Sink)
			}
		}
	}
}

func cacheKeyHasIdentity(m *sourceModule, n *sitter.Node) bool {
	found := false
	walkIdentifiers(n, func(id *sitter.Node) {
		name := strings.ToLower(id.Utf8Text(m.src))
		found = found || name == "userid" || name == "user" || name == "session" || name == "accountid"
	})
	return found
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

func (s *moduleSet) practiceClientAuthorization(ps *practiceSet, m *sourceModule, out *analysis.AnalysisReport) {
	var gates []analysis.Evidence
	walkNodes(m.tree.RootNode(), func(n *sitter.Node) {
		if n.Kind() != "if_statement" && n.Kind() != "ternary_expression" {
			return
		}
		c := n.ChildByFieldName("condition")
		if c == nil {
			return
		}
		text := c.Utf8Text(m.src)
		walkIdentifiers(c, func(id *sitter.Node) {
			if def := definitionAt(m, id, id.Utf8Text(m.src)); def != nil {
				text += " " + def.Utf8Text(m.src)
			}
		})
		lower := strings.ToLower(text)
		if (strings.Contains(lower, "admin") || strings.Contains(lower, "role")) && (strings.Contains(text, "localStorage") || strings.Contains(text, "jwtDecode") || strings.Contains(text, "atob(")) {
			gates = append(gates, m.evidence("client_authorization_gate", c))
		}
	})
	if len(gates) == 0 {
		return
	}
	for _, r := range s.next.clientRequests {
		if r.module != m {
			continue
		}
		url := s.clientURL(m, r.url, nil, 0)
		if url == "" {
			continue
		}
		matched, authorized := false, false
		for _, entry := range out.Entries {
			if entry.HTTP == nil || !routePatternMatch(entry.HTTPRoute().PathPattern, url) || !strings.EqualFold(entry.HTTP.Method, r.method) {
				continue
			}
			matched = true
			for _, ctx := range out.InvocationContexts {
				if ctx.EntryID != entry.ID {
					continue
				}
				for _, c := range ctx.Controls {
					authorized = authorized || c.Evidence.Kind == "authorization_context"
				}
			}
			// A directly imported auth helper is context too. Its presence must be in
			// this handler, not elsewhere in the file.
			if server := s.modules[entry.Location.Span.File]; server != nil {
				if decl := nodeAt(server.tree.RootNode(), entry.Location.Span.StartByte, entry.Location.Span.EndByte); decl != nil {
					walkCalls(decl, func(call *sitter.Node) {
						if fn := call.ChildByFieldName("function"); fn != nil {
							name := fn.Utf8Text(server.src)
							imp, imported := server.imports[name]
							authorized = authorized || imported && (imp.name == "auth" || imp.name == "getServerSession" || imp.name == "requireAdmin" || imp.name == "requireAuth")
						}
					})
				}
			}
		}
		if !authorized {
			detail := "client-controlled role data gates admin UI and calls " + r.method + " " + url + "; no matching server authorization check is established"
			if !matched {
				detail += " (API entry unresolved)"
			}
			ev := append([]analysis.Evidence{}, gates...)
			ev = append(ev, m.evidence("client_request", r.call))
			ps.add("NX-BP-22", "Client-only admin authorization", "review", detail, "", ev...)
		}
	}
}
