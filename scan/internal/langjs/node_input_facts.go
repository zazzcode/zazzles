package langjs

import (
	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/parse"
	"strings"
)

func (f *flow) hapiPayload(n *sitter.Node) bool {
	if f.entry.HTTP == nil || f.entry.HTTP.Framework != "hapi" || f.entry.HTTP.Method == "GET" || f.entry.HTTP.Method == "HEAD" {
		return false
	}
	field := requestFieldNode(n, f.module.src, f.request)
	if field == nil {
		return false
	}
	return strings.HasPrefix(field.Utf8Text(f.module.src), f.request+".payload.")
}
func (s *moduleSet) assembleNodeInputs(r *analysis.AnalysisReport) {
	entries := map[string]analysis.EntryPoint{}
	for _, e := range r.Entries {
		entries[e.ID] = e
	}
	for i := range r.Uses {
		u := &r.Uses[i]
		if c := s.nodeHTTP[u.EntryID]; c != nil {
			s.nodeInputFacts(u, c)
			continue
		}
		e := entries[u.EntryID]
		if e.Kind != "grpc" && e.Kind != "graphql" {
			continue
		}
		facts := &analysis.InputFacts{Version: 1, Acquisition: e.Kind, Binding: e.Location, Values: []analysis.InputValueFact{}}
		for j, d := range u.Dependencies {
			facts.Values = append(facts.Values, analysis.InputValueFact{Dependency: j, Origin: e.Kind + ".request", InitialType: "unknown", SinkType: "unknown", Source: d.Source, Transfers: append([]analysis.Evidence{}, d.Transfers...)})
		}
		u.InputFacts = facts
	}
}
func (s *moduleSet) nodeInputFacts(u *analysis.CandidateUse, c *nodeHTTPContext) {
	// Next.js web-request reads keep acquisition "http" (it must equal the entry
	// kind); the framework value and per-value origins carry the adapter.
	facts := &analysis.InputFacts{Version: 1, Acquisition: "http", Framework: c.entry.HTTP.Framework, Binding: c.entry.Location, Values: []analysis.InputValueFact{}, Controls: append([]analysis.Evidence{}, c.controls...), Stages: append([]analysis.InputStage{}, c.stages...), Gaps: append([]analysis.Gap{}, c.gaps...)}
	if u.Completeness != nil {
		facts.Gaps = append(facts.Gaps, u.Completeness.Blockers...)
	}
	stable := requestParamsStable(c.handler, c.body, c.request)
	if c.entry.HTTP.Framework == "express" {
		for _, e := range u.Context {
			if e.Kind != "middleware_handler" {
				continue
			}
			facts.Controls = append(facts.Controls, e)
			m := s.modules[e.Span.File]
			if m == nil {
				stable = false
				continue
			}
			body := parse.NodeAt(m.tree.RootNode(), e.Span.StartByte, e.Span.EndByte)
			if body == nil || body.Parent() == nil {
				stable = false
				continue
			}
			req := requestParamName(body.Parent(), m.src)
			stable = stable && req != "" && requestParamsStable(m, body, req)
		}
		if hasParamRegistration(c.registration) {
			stable = false
			facts.Gaps = append(facts.Gaps, analysis.Gap{Kind: "input_type_unresolved", Detail: "app.param can replace captured parameter values", At: c.entry.Location.Span})
		}
	}
	for i, d := range u.Dependencies {
		v := analysis.InputValueFact{Dependency: i, Origin: "unknown", InitialType: "unknown", SinkType: "unknown", Source: d.Source, Transfers: append([]analysis.Evidence{}, d.Transfers...)}
		m := s.modules[d.Source.Span.File]
		if o, ok := s.webOriginFor(d.Source); ok {
			// web-request-v1 reads record their origin where the flow created them.
			v.Origin, v.InitialType = o.origin, o.initialType
			m = nil
		}
		if m != nil {
			n := parse.NodeAt(m.tree.RootNode(), d.Source.Span.StartByte, d.Source.Span.EndByte)
			if n != nil && n.Kind() == "member_expression" {
				container, key := n.ChildByFieldName("object"), n.ChildByFieldName("property")
				if container != nil && key != nil {
					prop := key.Utf8Text(m.src)
					if container.Kind() == "identifier" && container.Utf8Text(m.src) == c.request {
						v.Origin = nodeURLUploadOrigin(prop, "")
					}
					parts := strings.Split(container.Utf8Text(m.src), ".")
					if len(parts) == 2 && parts[0] == c.request {
						switch parts[1] {
						case "params":
							v.Origin = "http.path"
							if namedHTTPParameter(c.entry.HTTP.Path, prop, c.entry.HTTP.Framework) {
								v.InitialType = "string"
								if stable && !inputEffects(facts.Controls) && len(facts.Gaps) == 0 && preservesInputType(d.Transfers) {
									v.SinkType = "string"
								}
							}
						case "body", "payload":
							v.Origin = "http.body"
						case "query":
							v.Origin = "http.query"
						case "headers":
							v.Origin = "http.headers"
						case "cookies":
							v.Origin = "http.cookies"
						case "file", "files":
							v.Origin = nodeURLUploadOrigin(parts[1], prop)
						case "path", "url", "originalUrl", "baseUrl":
							// Nested reads on URL members keep the URL origin.
							v.Origin = nodeURLUploadOrigin(parts[1], "")
						}
					}
				}
			}
		}
		if typ := s.nativeSinkInputType(*u); typ != "" && len(u.Dependencies) == 1 {
			v.SinkType = typ
		}
		facts.Values = append(facts.Values, v)
	}
	// Controls can be present and fully supplied while their effects remain a
	// semantic question. Unknown bodies, not unknown safety, are completeness gaps.
	u.InputFacts = facts
}

// nodeURLUploadOrigin maps Express URL/upload request members to acquisition origins.
// property is set for req.file.<property> / req.files.<property> projections.
func nodeURLUploadOrigin(member, property string) string {
	switch member {
	case "path":
		return "http.url_path"
	case "url":
		return "http.url"
	case "originalUrl":
		return "http.original_url"
	case "baseUrl":
		return "http.base_url"
	case "file", "files":
		switch property {
		case "originalname", "filename", "name":
			return "http.upload_filename"
		case "buffer", "data", "stream":
			return "http.upload_content"
		case "":
			return "http.upload"
		default:
			return "http.upload"
		}
	}
	return "unknown"
}

func namedHTTPParameter(path, key, framework string) bool {
	for _, part := range strings.Split(path, "/") {
		if (framework == "hapi" && part == "{"+key+"}") || (framework != "hapi" && part == ":"+key) {
			return true
		}
	}
	return false
}
func preservesInputType(transfers []analysis.Evidence) bool {
	for _, e := range transfers {
		switch e.Kind {
		case "assignment":
		default:
			return false
		}
	}
	return true
}

func inputEffects(controls []analysis.Evidence) bool {
	for _, e := range controls {
		switch e.Kind {
		case "http_hook", "http_schema", "http_configuration", "middleware_handler":
			return true
		}
	}
	return false
}

func (s *moduleSet) nativeSinkInputType(u analysis.CandidateUse) string {
	if u.APIModel == nil || u.APIModel.ID != "mongoose-find-by-id-objectid-v1" {
		return ""
	}
	m := s.modules[u.Sink.Span.File]
	if m == nil {
		return ""
	}
	call := parse.NodeAt(m.tree.RootNode(), u.Sink.Span.StartByte, u.Sink.Span.EndByte)
	if call == nil {
		return ""
	}
	args := call.ChildByFieldName("arguments")
	if args == nil || args.NamedChildCount() == 0 {
		return ""
	}
	arg := args.NamedChild(0)
	if arg.Kind() != "call_expression" || !nativeStringOperation(m, arg) {
		return ""
	}
	fn := arg.ChildByFieldName("function")
	if fn == nil {
		return ""
	}
	switch fn.Utf8Text(m.src) {
	case "Number":
		return "number"
	case "String":
		return "string"
	}
	return ""
}

func (f *flow) nodeFieldAvailable(n *sitter.Node) bool {
	e := f.entry.HTTP
	if e == nil || (e.Framework != "fastify" && e.Framework != "hapi") || (e.Method != "GET" && e.Method != "HEAD") {
		return true
	}
	text := n.Utf8Text(f.module.src)
	for _, base := range []string{f.request + ".body", f.request + ".payload"} {
		if text == base || strings.HasPrefix(text, base+".") || strings.HasPrefix(text, base+"[") {
			return false
		}
	}
	for name, part := range f.parts {
		if part == "body" || part == "payload" {
			if text == name || strings.HasPrefix(text, name+".") || strings.HasPrefix(text, name+"[") {
				return false
			}
		}
	}
	return true
}
