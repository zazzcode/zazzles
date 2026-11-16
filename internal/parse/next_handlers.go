package parse

import (
	"sort"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
)

// nextResolved is a route export resolved to the function Next.js invokes, plus
// the verified wrappers around it. Wrapper checks are authorization context,
// never destination controls.
type nextResolved struct {
	module   *sourceModule
	fn       *sitter.Node
	wrappers []analysis.Evidence
	auth     []analysis.Evidence
	gaps     []analysis.Gap
}

func unwrapTS(n *sitter.Node) *sitter.Node {
	for n != nil {
		switch n.Kind() {
		case "parenthesized_expression", "as_expression", "satisfies_expression", "non_null_expression", "type_assertion":
			if n.NamedChildCount() == 0 {
				return n
			}
			n = n.NamedChild(0)
		default:
			return n
		}
	}
	return n
}

// nextHandler resolves an exported value to a callable. Supported: a function,
// an identifier bound to one (same module or imported), and a call to a resolved
// higher-order wrapper whose returned function forwards its own request and
// context unchanged to the wrapped handler.
func (s *moduleSet) nextHandler(m *sourceModule, n *sitter.Node, depth int) nextResolved {
	n = unwrapTS(n)
	if n == nil || depth > 4 {
		return nextResolved{gaps: []analysis.Gap{{Kind: "unresolved_handler", Detail: "no supported handler export"}}}
	}
	switch {
	case isFunction(n) || n.Kind() == "function_declaration":
		return nextResolved{module: m, fn: n}
	case n.Kind() == "identifier":
		name := n.Utf8Text(m.src)
		if v := topVariable(m, name); v != nil && !isFunction(v) && !bindingReassigned(m, name) {
			return s.nextHandler(m, v, depth+1)
		}
		hm, fn := s.resolve(m, name)
		if hm == nil || fn == nil {
			return nextResolved{gaps: []analysis.Gap{{Kind: "unresolved_handler", Detail: "handler binding is not resolved: " + name, At: spanOf(m.file, n)}}}
		}
		if !supportedCallee(fn) {
			return s.nextHandler(hm, fn, depth+1)
		}
		return nextResolved{module: hm, fn: fn}
	case n.Kind() == "call_expression":
		callee, args := n.ChildByFieldName("function"), n.ChildByFieldName("arguments")
		if callee == nil || args == nil || args.NamedChildCount() != 1 {
			return nextResolved{gaps: []analysis.Gap{{Kind: "unresolved_wrapper", Detail: "handler factory call is not a single-argument wrapper", At: spanOf(m.file, n)}}}
		}
		wm, wrapper := s.resolveCall(m, n)
		if wm == nil || wrapper == nil || !supportedCallee(wrapper) {
			return nextResolved{gaps: []analysis.Gap{{Kind: "unresolved_wrapper", Detail: "wrapper is not a resolved function: " + callee.Utf8Text(m.src), At: spanOf(m.file, n)}}}
		}
		auth, ok := s.forwardingWrapper(wm, wrapper, 0)
		if !ok {
			return nextResolved{gaps: []analysis.Gap{{Kind: "unresolved_wrapper", Detail: "wrapper does not provably forward the request and context unchanged: " + callee.Utf8Text(m.src), At: spanOf(m.file, n)}}}
		}
		inner := s.nextHandler(m, args.NamedChild(0), depth+1)
		inner.wrappers = append([]analysis.Evidence{wm.evidence("wrapper_definition", wrapper)}, inner.wrappers...)
		inner.auth = append(auth, inner.auth...)
		return inner
	}
	return nextResolved{gaps: []analysis.Gap{{Kind: "unresolved_handler", Detail: "unsupported handler export shape: " + n.Kind(), At: spanOf(m.file, n)}}}
}

// forwardingWrapper verifies `function w(handler) { return async (req, ctx) => {
// ...; return handler(req, ctx, extra) } }`, also when the returned value is
// another verified wrapper applied to such a forwarding function. Early returns
// before the forwarding call are returned as authorization context.
func (s *moduleSet) forwardingWrapper(m *sourceModule, wrapper *sitter.Node, depth int) ([]analysis.Evidence, bool) {
	if depth > 3 {
		return nil, false
	}
	params := plainParameters(wrapper, m.src)
	if len(params) != 1 {
		return nil, false
	}
	inner := params[0]
	var ret *sitter.Node
	body := wrapper.ChildByFieldName("body")
	if body == nil {
		return nil, false
	}
	if body.Kind() != "statement_block" {
		ret = body
	} else {
		for i := uint(0); i < body.NamedChildCount(); i++ {
			c := body.NamedChild(i)
			if c.Kind() == "return_statement" && c.NamedChildCount() == 1 {
				if ret != nil {
					return nil, false
				}
				ret = c.NamedChild(0)
			}
		}
	}
	ret = unwrapTS(ret)
	if ret == nil {
		return nil, false
	}
	if isFunction(ret) {
		return forwardsTo(m, ret, inner)
	}
	if ret.Kind() == "call_expression" {
		args := ret.ChildByFieldName("arguments")
		if args == nil || args.NamedChildCount() != 1 || !isFunction(args.NamedChild(0)) {
			return nil, false
		}
		wm, outer := s.resolveCall(m, ret)
		if wm == nil || outer == nil || !supportedCallee(outer) {
			return nil, false
		}
		outerAuth, ok := s.forwardingWrapper(wm, outer, depth+1)
		if !ok {
			return nil, false
		}
		own, ok := forwardsTo(m, args.NamedChild(0), inner)
		if !ok {
			return nil, false
		}
		return append(append(outerAuth, wm.evidence("wrapper_definition", outer)), own...), true
	}
	return nil, false
}

// forwardsTo checks that fn calls `inner(p0, p1, ...)` with its own first two
// parameters, unreassigned, as its single forwarding call.
func forwardsTo(m *sourceModule, fn *sitter.Node, inner string) ([]analysis.Evidence, bool) {
	params := plainParameters(fn, m.src)
	if len(params) < 1 {
		return nil, false
	}
	calls := 0
	ok := true
	var auth []analysis.Evidence
	walkCalls(fn.ChildByFieldName("body"), func(call *sitter.Node) {
		callee := call.ChildByFieldName("function")
		if callee == nil || callee.Kind() != "identifier" || callee.Utf8Text(m.src) != inner {
			return
		}
		calls++
		args := call.ChildByFieldName("arguments")
		for i, p := range params {
			if i > 1 {
				break
			}
			if args == nil || args.NamedChildCount() <= uint(i) || args.NamedChild(uint(i)).Kind() != "identifier" || args.NamedChild(uint(i)).Utf8Text(m.src) != p {
				ok = false
			}
		}
	})
	if calls != 1 || !ok {
		return nil, false
	}
	body := fn.ChildByFieldName("body")
	for _, p := range params[:min(2, len(params))] {
		if writesName(body, p, m.src) {
			return nil, false
		}
	}
	if body != nil && body.Kind() == "statement_block" {
		for i := uint(0); i < body.NamedChildCount(); i++ {
			c := body.NamedChild(i)
			if c.Kind() == "if_statement" {
				auth = append(auth, m.evidence("authorization_context", c))
			}
		}
	}
	return auth, true
}

func writesName(n *sitter.Node, name string, src []byte) bool {
	if n == nil {
		return false
	}
	found := false
	var visit func(*sitter.Node)
	visit = func(c *sitter.Node) {
		if found {
			return
		}
		switch c.Kind() {
		case "assignment_expression", "augmented_assignment_expression":
			if l := c.ChildByFieldName("left"); l != nil && l.Kind() == "identifier" && l.Utf8Text(src) == name {
				found = true
			}
		case "variable_declarator":
			if l := c.ChildByFieldName("name"); l != nil && l.Kind() == "identifier" && l.Utf8Text(src) == name {
				found = true
			}
		}
		for i := uint(0); i < c.NamedChildCount(); i++ {
			visit(c.NamedChild(i))
		}
	}
	visit(n)
	return found
}

// nextParam is a handler parameter: a name, or an object pattern's fields.
type nextParam struct {
	name   string
	fields map[string]string // object pattern: property -> local name
	node   *sitter.Node
}

func nextParams(fn *sitter.Node, src []byte) []nextParam {
	params := fn.ChildByFieldName("parameters")
	if params == nil {
		if p := fn.ChildByFieldName("parameter"); p != nil && p.Kind() == "identifier" {
			return []nextParam{{name: p.Utf8Text(src), node: p}}
		}
		return nil
	}
	var out []nextParam
	for i := uint(0); i < params.NamedChildCount(); i++ {
		n := params.NamedChild(i)
		if n.Kind() == "required_parameter" || n.Kind() == "optional_parameter" {
			n = n.ChildByFieldName("pattern")
		}
		if n != nil && n.Kind() == "assignment_pattern" {
			n = n.ChildByFieldName("left")
		}
		p := nextParam{node: n}
		if n != nil && n.Kind() == "identifier" {
			p.name = n.Utf8Text(src)
		} else if n != nil && n.Kind() == "object_pattern" {
			p.fields = map[string]string{}
			for j := uint(0); j < n.NamedChildCount(); j++ {
				b := n.NamedChild(j)
				switch b.Kind() {
				case "shorthand_property_identifier_pattern":
					p.fields[b.Utf8Text(src)] = b.Utf8Text(src)
				case "pair_pattern":
					k, v := b.ChildByFieldName("key"), b.ChildByFieldName("value")
					if k != nil && v != nil && v.Kind() == "identifier" {
						p.fields[k.Utf8Text(src)] = v.Utf8Text(src)
					}
				}
			}
		}
		out = append(out, p)
	}
	return out
}

// analyzeNextHandler runs the shared flow over one Next.js entry. The adapter
// supplies only acquisition: the entry, the request and context bindings and
// web-request origins. Sinks, guards and claims are the shared engine's.
func (s *moduleSet) analyzeNextHandler(out *analysis.AnalysisReport, m *sourceModule, r analysis.Route, ex nextExport, p *nextProject, segments []nextSegment, surface, router string) {
	e := httpEntry(r, m.evidence("entry_registration", ex.decl), m.file+":"+m.hash+":nextjs")
	e.HTTP.SourcePath = r.PathPattern
	e.HTTP.Router = router
	e.HTTP.Surface = surface
	for _, seg := range segments {
		e.HTTP.Segments = append(e.HTTP.Segments, seg.raw)
	}
	e.HTTP.Aliases = s.nextAliases(p, r.PathPattern)
	e.Gaps = append([]analysis.Gap{}, ex.gaps...)
	var res nextResolved
	if ex.value != nil {
		res = s.nextHandler(ex.owner, ex.value, 0)
	} else {
		res = nextResolved{gaps: []analysis.Gap{}}
	}
	e.Gaps = append(e.Gaps, res.gaps...)
	if res.fn == nil || res.module == nil {
		registerInvocation(out, e, nil, "filesystem_route", nil, e.Gaps)
		noteHTTPDeclaration(out, r, nil)
		return
	}
	if res.module.tree.RootNode().HasError() {
		e.Gaps = append(e.Gaps, analysis.Gap{Kind: "parse_error", Detail: "handler module has syntax errors", At: spanOf(res.module.file, res.fn)})
		registerInvocation(out, e, nil, "filesystem_route", nil, e.Gaps)
		noteHTTPDeclaration(out, r, nil)
		return
	}
	hm, fn := res.module, res.fn
	body := fn.ChildByFieldName("body")
	r.Handler = analysis.Symbol{Name: ex.name, Kind: "function", Span: spanOf(hm.file, fn)}
	params := nextParams(fn, hm.src)
	web := &webState{project: p, segments: map[string]nextSegment{}, framework: r.Framework, surface: surface}
	for _, seg := range segments {
		if seg.param != "" {
			web.segments[seg.param] = seg
		}
	}
	req := ""
	if len(params) > 0 && params[0].name != "" {
		req = params[0].name
	}
	if len(params) > 1 {
		web.context = params[1].name
		if params[1].fields != nil {
			web.paramsName = params[1].fields["params"]
		}
	}
	context := append([]analysis.Evidence{}, res.wrappers...)
	context = append(context, res.auth...)
	evidence := hm.evidence("handler", body)
	inputs := []analysis.InputBinding{}
	if req != "" {
		inputs = append(inputs, httpInput("http.request", req, parameterEvidence(hm, body, 0)))
	} else if len(params) > 0 && router == "app" {
		e.Gaps = append(e.Gaps, analysis.Gap{Kind: "request_projection_unresolved", Detail: "request parameter uses an unsupported projection", At: spanOf(hm.file, fn)})
	}
	response := ""
	if router == "pages" && len(params) > 1 && params[1].name != "" {
		response = params[1].name
		web.context = ""
		inputs = append(inputs, httpInput("http.response", response, parameterEvidence(hm, body, 1)))
	}
	s.rememberNodeHTTP(e, m, hm, ex.decl, body, req, "", context)
	if c := s.nodeHTTP[e.ID]; c != nil {
		c.controls = append(c.controls, res.auth...)
		c.stages = append(c.stages, s.nextMiddlewareStages(p, r.PathPattern, surface)...)
	}
	invocation := registerInvocation(out, e, &evidence, "filesystem_route", inputs, e.Gaps)
	f := flow{module: hm, set: s, entry: e, invocation: invocation, registration: m,
		env: map[string]value{}, context: append([]analysis.Evidence{m.evidence("registration", ex.decl), evidence}, context...),
		gaps: append([]analysis.Gap{}, e.Gaps...), helpers: &helperExpansion{budget: 24, stack: map[string]bool{}}, facts: newInputFacts(), web: web}
	f.seedInvocation()
	// Extra wrapper arguments (an authenticated user) are values the wrapper
	// derived; they are not request origins and carry no gap of their own.
	for i := 2; i < len(params); i++ {
		if params[i].name != "" && len(res.wrappers) > 0 {
			f.env[params[i].name] = value{}
		}
	}
	if router == "pages" {
		// Pages Router handlers use the Express-shaped req.query/body/cookies members.
		f.web = nil
	}
	f.statements(body)
	f.finishValidation()
	out.Uses = append(out.Uses, f.uses...)
	e.Gaps = append(e.Gaps, f.gaps[len(e.Gaps):]...)
	out.Entries[len(out.Entries)-1].Gaps = e.Gaps
	noteHTTPDeclaration(out, r, context)
}

// nextAliases lists literal rewrite sources whose destination reaches pattern.
func (s *moduleSet) nextAliases(p *nextProject, pattern string) []string {
	cfg := s.nextConfig(p)
	if cfg == nil {
		return nil
	}
	var out []string
	for _, rw := range cfg.rewrites {
		dest := strings.ReplaceAll(rw.destination, ":path*", ":path")
		pat := pattern
		pat = strings.ReplaceAll(pat, "*?", "")
		pat = strings.ReplaceAll(pat, "*", "")
		if routePatternMatch(pat, strings.ReplaceAll(dest, "*", "")) || strings.TrimSuffix(dest, "/:path") == strings.TrimSuffix(pat, "/:path") {
			out = append(out, rw.source)
		}
	}
	sort.Strings(out)
	return out
}
