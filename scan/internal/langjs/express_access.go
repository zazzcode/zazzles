package langjs

import (
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/parse"
)

// Express entry access (lane decision D-2). Authentication is established by a
// closed list of library contracts on the middleware chain of the route, never
// by a name:
//
//   - express-jwt: the default export and `expressjwt` (documented as the
//     middleware that rejects a request without a valid token, with 401).
//   - passport: `passport.authenticate(strategy, options)` (documented as the
//     middleware that authenticates a request).
//   - express-openid-connect: `requiresAuth()` (documented as the middleware
//     that requires an authenticated session).
//
// A local function that returns one of these calls counts. A local middleware
// that ends the response on one branch and calls next() on another is recorded
// as unresolved with a gap; this scanner does not decide what its condition
// checks (the authorization family lists it as a guard).
var authMiddlewareContracts = map[string]map[string]bool{
	"express-jwt":            {"default": true, "expressjwt": true},
	"passport":               {"authenticate": true},
	"express-openid-connect": {"requiresAuth": true},
}

const maxAuthWrapperDepth = 3

// expressAccess builds the EntryAccess record of one Express route
// registration. rel is the route path relative to the registering receiver;
// mounts are the router mount calls (outermost first) that carry the route.
func (s *moduleSet) expressAccess(m *sourceModule, call *sitter.Node, rel string, context []analysis.Evidence) analysis.EntryAccess {
	access := analysis.EntryAccess{Authentication: analysis.AccessNone, Sources: []analysis.Evidence{}}
	var required []analysis.Evidence
	var guarded []analysis.Evidence
	var gaps []analysis.Gap

	note := func(item chainItem) {
		switch item.kind {
		case chainAuth:
			required = append(required, item.evidence...)
		case chainGuard:
			guarded = append(guarded, item.evidence...)
			gaps = append(gaps, analysis.Gap{Kind: "access_guard_unmodeled", Detail: "A local middleware ends the response on one branch and calls next() on another; its condition is not modeled as an authentication contract", At: item.evidence[0].Span})
		case chainPattern:
			guarded = append(guarded, item.evidence...)
			gaps = append(gaps, analysis.Gap{Kind: "middleware_mount_unresolved", Detail: "Middleware mounted on a path pattern; whether it covers this route requires a framework path model", At: item.evidence[0].Span})
		}
	}

	// Router mounts that carry this route, then the receiver's own earlier
	// app.use calls, then the route call's own middleware arguments.
	for _, ev := range context {
		if ev.Kind != "router_mount" {
			continue
		}
		mm := s.modules[ev.Span.File]
		if mm == nil {
			continue
		}
		mount := parse.NodeAt(mm.tree.RootNode(), ev.Span.StartByte, ev.Span.EndByte)
		if mount == nil {
			continue
		}
		for _, item := range s.useChain(mm, mount, "", true) {
			note(item)
		}
	}
	walkCalls(m.tree.RootNode(), func(use *sitter.Node) {
		if use.StartByte() >= call.StartByte() {
			return
		}
		fn := use.ChildByFieldName("function")
		if fn == nil || fn.Kind() != "member_expression" {
			return
		}
		obj, prop := fn.ChildByFieldName("object"), fn.ChildByFieldName("property")
		if obj == nil || prop == nil || prop.Utf8Text(m.src) != "use" || !m.receivers[obj.Utf8Text(m.src)] || shadowed(use, obj.Utf8Text(m.src), m.src) {
			return
		}
		for _, item := range s.useChain(m, use, rel, false) {
			note(item)
		}
	})
	if args := call.ChildByFieldName("arguments"); args != nil && args.NamedChildCount() > 2 {
		for i := uint(1); i+1 < args.NamedChildCount(); i++ {
			for _, item := range s.chainItems(m, args.NamedChild(i), call) {
				note(item)
			}
		}
	}

	switch {
	case len(required) > 0:
		access.Authentication = analysis.AccessRequired
		access.Sources = required
	case len(guarded) > 0:
		access.Authentication = analysis.AccessUnresolved
		access.Sources = guarded
		access.Gaps = gaps
	}
	return access
}

type chainKind int

const (
	chainNone chainKind = iota
	chainAuth
	chainGuard
	chainPattern
)

type chainItem struct {
	kind     chainKind
	evidence []analysis.Evidence
}

// useChain returns the chain items of one app.use or router mount call. With
// unconditional set the mount path always applies (the route was reached
// through it). Otherwise the literal path must cover rel.
func (s *moduleSet) useChain(m *sourceModule, use *sitter.Node, rel string, unconditional bool) []chainItem {
	args := use.ChildByFieldName("arguments")
	if args == nil || args.NamedChildCount() == 0 {
		return nil
	}
	first := uint(0)
	kind := chainAuth // the kind a covering mount keeps; pattern mounts downgrade it
	if path, ok := stringLiteral(args.NamedChild(0), m.src); ok {
		first = 1
		if !unconditional {
			switch {
			case strings.ContainsAny(path, "*:?()+[]"):
				prefix := path
				for i, c := range path {
					if strings.ContainsRune("*:?()+[]", c) {
						prefix = path[:i]
						break
					}
				}
				if prefix != "" && !strings.HasPrefix(rel, prefix) {
					return nil
				}
				kind = chainPattern
			case path != "/" && rel != path && !strings.HasPrefix(rel, strings.TrimRight(path, "/")+"/"):
				return nil
			}
		}
	} else if args.NamedChild(0).Kind() == "array" {
		// A path array is not modeled; a middleware behind it is unresolved.
		if _, dynamic, _ := pathArgs(args.NamedChild(0), m.src); dynamic {
			return nil
		}
		first = 1
		kind = chainPattern
	}
	var out []chainItem
	for i := first; i < args.NamedChildCount(); i++ {
		arg := args.NamedChild(i)
		for _, item := range s.chainItems(m, arg, use) {
			if item.kind == chainAuth && kind == chainPattern {
				item.kind = chainPattern
			}
			if item.kind == chainAuth {
				item.evidence = append([]analysis.Evidence{m.evidence("access_registration", use)}, item.evidence...)
			}
			out = append(out, item)
		}
	}
	return out
}

// chainItems classifies one middleware argument (an array contributes each
// element).
func (s *moduleSet) chainItems(m *sourceModule, arg, registration *sitter.Node) []chainItem {
	if arg == nil {
		return nil
	}
	if arg.Kind() == "array" {
		var out []chainItem
		for i := uint(0); i < arg.NamedChildCount(); i++ {
			out = append(out, s.chainItems(m, arg.NamedChild(i), registration)...)
		}
		return out
	}
	if evidence, ok := s.authMiddleware(m, arg, 0); ok {
		return []chainItem{{kind: chainAuth, evidence: append([]analysis.Evidence{m.evidence("access_middleware", arg)}, evidence...)}}
	}
	if s.respondsOrContinues(m, arg) {
		return []chainItem{{kind: chainGuard, evidence: []analysis.Evidence{m.evidence("access_middleware", arg)}}}
	}
	return nil
}

// authMiddleware reports whether n is a call of a listed authentication
// contract, directly or through local functions that return one.
func (s *moduleSet) authMiddleware(m *sourceModule, n *sitter.Node, depth int) ([]analysis.Evidence, bool) {
	if n == nil || n.Kind() != "call_expression" || depth > maxAuthWrapperDepth {
		return nil, false
	}
	fn := n.ChildByFieldName("function")
	if fn == nil {
		return nil, false
	}
	switch fn.Kind() {
	case "identifier":
		name := fn.Utf8Text(m.src)
		if shadowed(n, name, m.src) {
			return nil, false
		}
		if imp, ok := m.imports[name]; ok && authContract(imp.module, imp.name) {
			return []analysis.Evidence{m.evidence("access_library_call", n)}, true
		}
	case "member_expression":
		obj, prop := fn.ChildByFieldName("object"), fn.ChildByFieldName("property")
		if obj != nil && prop != nil && obj.Kind() == "identifier" && !shadowed(n, obj.Utf8Text(m.src), m.src) {
			if imp, ok := m.imports[obj.Utf8Text(m.src)]; ok && (imp.name == "default" || imp.name == "*") && authContract(imp.module, prop.Utf8Text(m.src)) && !bindingReassigned(m, obj.Utf8Text(m.src)) {
				return []analysis.Evidence{m.evidence("access_library_call", n)}, true
			}
		}
	default:
		return nil, false
	}
	if args := n.ChildByFieldName("arguments"); args != nil && args.NamedChildCount() > 0 {
		// A wrapper call with arguments is not followed: the argument could
		// select a different middleware.
		return nil, false
	}
	name := fn.Utf8Text(m.src)
	if shadowed(n, strings.Split(name, ".")[0], m.src) {
		return nil, false
	}
	target, wrapper := s.resolve(m, name)
	if target == nil || wrapper == nil || !isFunction(wrapper) && wrapper.Kind() != "function_declaration" {
		return nil, false
	}
	returned := returnedCall(wrapper)
	if returned == nil {
		return nil, false
	}
	evidence, ok := s.authMiddleware(target, returned, depth+1)
	if !ok {
		return nil, false
	}
	return evidence, true
}

func authContract(module, name string) bool {
	names := authMiddlewareContracts[module]
	return names != nil && names[name]
}

// returnedCall returns the call expression a function returns as its whole
// result: an arrow with an expression body, or a block that is one return.
func returnedCall(fn *sitter.Node) *sitter.Node {
	body := fn.ChildByFieldName("body")
	if body == nil {
		return nil
	}
	if body.Kind() == "call_expression" {
		return body
	}
	if body.Kind() == "parenthesized_expression" && body.NamedChildCount() == 1 {
		inner := body.NamedChild(0)
		if inner.Kind() == "as_expression" && inner.NamedChildCount() > 0 {
			inner = inner.NamedChild(0)
		}
		if inner.Kind() == "call_expression" {
			return inner
		}
	}
	if body.Kind() == "statement_block" && body.NamedChildCount() == 1 {
		r := body.NamedChild(0)
		if r.Kind() == "return_statement" && r.NamedChildCount() == 1 && r.NamedChild(0).Kind() == "call_expression" {
			return r.NamedChild(0)
		}
	}
	return nil
}

var responseEnders = map[string]bool{"send": true, "json": true, "end": true, "sendStatus": true, "redirect": true, "sendFile": true, "render": true}

// respondsOrContinues reports whether arg resolves to a local middleware that
// ends the response on one branch and calls next() on another.
func (s *moduleSet) respondsOrContinues(m *sourceModule, arg *sitter.Node) bool {
	if arg == nil || (arg.Kind() != "identifier" && arg.Kind() != "member_expression" && arg.Kind() != "call_expression" && !isFunction(arg)) {
		return false
	}
	hm, body, _, gaps := s.handler(m, arg)
	if body == nil || len(gaps) > 0 || body.Parent() == nil {
		return false
	}
	params := plainParameters(body.Parent(), hm.src)
	if len(params) != 3 {
		return false
	}
	res, next := params[1], params[2]
	ends, continues := false, false
	var walk func(*sitter.Node)
	walk = func(n *sitter.Node) {
		if n == nil || (n != body && isFunction(n)) {
			return
		}
		if n.Kind() == "call_expression" {
			fn := n.ChildByFieldName("function")
			args := n.ChildByFieldName("arguments")
			if fn != nil && fn.Kind() == "identifier" && fn.Utf8Text(hm.src) == next && args != nil && args.NamedChildCount() == 0 {
				continues = true
			}
			if fn != nil && fn.Kind() == "member_expression" {
				if prop := fn.ChildByFieldName("property"); prop != nil && responseEnders[prop.Utf8Text(hm.src)] && chainRoot(fn, hm.src) == res {
					ends = true
				}
			}
		}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			walk(n.NamedChild(i))
		}
	}
	walk(body)
	return ends && continues
}

// chainRoot returns the identifier at the base of a member/call chain.
func chainRoot(n *sitter.Node, src []byte) string {
	for n != nil {
		switch n.Kind() {
		case "identifier":
			return n.Utf8Text(src)
		case "member_expression":
			n = n.ChildByFieldName("object")
		case "call_expression":
			n = n.ChildByFieldName("function")
		default:
			return ""
		}
	}
	return ""
}

// expressEntryAccess returns the D-2 access record of an HTTP entry. For an
// Express entry whose chain holds no listed authentication middleware and no
// guard-like local middleware (authentication none) the report stores no
// record, so the serialized report of such an entry is the one the scanner
// produced before D-2; this function reads that absence as none. Entries of
// other frameworks have no access record (ok is false).
func expressEntryAccess(e analysis.EntryPoint) (analysis.EntryAccess, bool) {
	if e.Access != nil {
		return *e.Access, true
	}
	if e.HTTP != nil && e.HTTP.Framework == "express" && e.HTTP.Method != "USE" {
		return analysis.EntryAccess{Authentication: analysis.AccessNone, Sources: []analysis.Evidence{}}, true
	}
	return analysis.EntryAccess{}, false
}
