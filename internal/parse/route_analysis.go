package parse

import (
	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
	"sort"
)

func (s *moduleSet) analyzeRoute(out *analysis.AnalysisReport, m, owner *sourceModule, r analysis.Route, call *sitter.Node, receiver string, context []analysis.Evidence, sourcePath, mount string) {
	s.analyzeSeededRoute(out, m, owner, r, call, receiver, context, sourcePath, mount, nil)
}

func (s *moduleSet) analyzeSeededRoute(out *analysis.AnalysisReport, m, owner *sourceModule, r analysis.Route, call *sitter.Node, receiver string, context []analysis.Evidence, sourcePath, mount string, seeds registrationSeeds) {
	args := call.ChildByFieldName("arguments")
	var h *sitter.Node
	if args != nil && args.NamedChildCount() > 1 {
		h = args.NamedChild(args.NamedChildCount() - 1)
	}
	if h != nil && h.Kind() == "identifier" && seeds[h.Utf8Text(m.src)] != nil {
		h = seeds[h.Utf8Text(m.src)]
	}
	s.analyzeHTTPHandler(out, m, owner, r, call, receiver, context, sourcePath, mount, seeds, h)
}

func (s *moduleSet) analyzeHTTPHandler(out *analysis.AnalysisReport, m, owner *sourceModule, r analysis.Route, call *sitter.Node, receiver string, context []analysis.Evidence, sourcePath, mount string, seeds registrationSeeds, h *sitter.Node) {
	e := httpEntry(r, m.evidence("entry_registration", call), owner.file+":"+owner.hash+":"+receiver)
	e.HTTP.Receiver = receiver
	e.HTTP.SourcePath = sourcePath
	e.HTTP.Mount = mount
	e.Gaps = []analysis.Gap{}
	if shadowed(call, receiver, m.src) && !parameterReceiver(m, call, receiver) {
		e.Gaps = append(e.Gaps, analysis.Gap{Kind: "ambiguous_receiver", Detail: "receiver is shadowed in enclosing scope", At: r.Registration})
		registerInvocation(out, e, nil, "direct_registration", nil, e.Gaps)
		noteHTTPDeclaration(out, r, context)
		return
	}
	hm, body, req, gaps := s.handler(m, h)
	mechanism := "direct_registration"
	if len(seeds) > 0 {
		mechanism = "table_expansion"
	}
	if fm, fb, fr, fs, provenance, ok := s.literalFactory(m, h, seeds); ok {
		hm, body, req, gaps = fm, fb, fr, nil
		seeds = fs
		context = append(context, provenance...)
		mechanism = "factory_expansion"
	}
	var parts map[string]string
	if body != nil && req == "" {
		parts, gaps = requestParts(hm, body, gaps)
	}
	e.Gaps = append(e.Gaps, gaps...)
	if body != nil {
		if r.Handler.Span.File == "" {
			r.Handler = analysis.Symbol{Name: textNode(h, m.src), Kind: "function", Span: spanOf(hm.file, body.Parent())}
		}
		evidence := hm.evidence("handler", body)
		s.rememberNodeHTTP(e, m, hm, call, body, req, receiver, context)
		inputs := []analysis.InputBinding{}
		if req != "" {
			inputs = append(inputs, httpInput("http.request", req, parameterEvidence(hm, body, 0)))
		}
		keys := []string{}
		for name := range parts {
			keys = append(keys, name)
		}
		sort.Strings(keys)
		for _, name := range keys {
			inputs = append(inputs, httpInput("http."+parts[name], name, hm.evidence("input_binding", body.Parent().ChildByFieldName("parameters"))))
		}
		response := handlerParameter(body, 1, hm.src)
		if response != "" {
			inputs = append(inputs, httpInput("http.response", response, parameterEvidence(hm, body, 1)))
		}
		invocation := registerInvocation(out, e, &evidence, mechanism, inputs, e.Gaps)
		invocation.Closures = registrationClosures(m, seeds)
		out.InvocationContexts[len(out.InvocationContexts)-1] = invocation
		f := flow{module: hm, set: s, entry: e, invocation: invocation, registration: owner,
			constants: seeds, env: map[string]value{}, context: append([]analysis.Evidence{m.evidence("registration", call), evidence}, context...),
			gaps: append([]analysis.Gap{}, e.Gaps...), helpers: &helperExpansion{budget: 24, stack: map[string]bool{}}, facts: newInputFacts(), parts: parts}
		f.seedInvocation()
		for name, node := range seeds {
			f.env[name] = f.eval(node)
		}
		f.gaps = append(f.gaps, analysis.Gap{Kind: "middleware_unresolved", Detail: "effective middleware/guard chain is not modeled", At: r.Registration})
		if r.Framework == "express" {
			s.noteMiddlewareFields(&f, m, call)
		}
		f.statements(body)
		f.finishValidation()
		s.requestLineLogs(&f, m, call, receiver)
		f.uses = s.withRequestURLPaths(f, m, hm, body, call, seeds, context, e, parts, r)
		out.Uses = append(out.Uses, f.uses...)
		e.Gaps = append(e.Gaps, f.gaps[len(e.Gaps):]...)
	}
	if body == nil {
		registerInvocation(out, e, nil, "direct_registration", nil, e.Gaps)
	} else {
		out.Entries[len(out.Entries)-1].Gaps = e.Gaps
	}
	noteHTTPDeclaration(out, r, context)
}

func noteHTTPDeclaration(out *analysis.AnalysisReport, r analysis.Route, derived []analysis.Evidence) {
	reg := &out.Registrations[len(out.Registrations)-1]
	reg.DeclaredHandler = &r.Handler
	reg.SyntaxSteps = r.Steps
	reg.DerivedFrom = append([]analysis.Evidence{}, derived...)
}

func parameterEvidence(m *sourceModule, body *sitter.Node, index uint) analysis.Evidence {
	fn := body.Parent()
	if fn != nil {
		params := fn.ChildByFieldName("parameters")
		if params != nil && params.NamedChildCount() > index {
			return m.evidence("input_binding", params.NamedChild(index))
		}
	}
	return m.evidence("input_binding", body)
}
