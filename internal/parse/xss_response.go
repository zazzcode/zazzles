package parse

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
)

func handlerParameter(body *sitter.Node, index uint, src []byte) string {
	if body == nil || body.Parent() == nil {
		return ""
	}
	params := body.Parent().ChildByFieldName("parameters")
	if params == nil || params.NamedChildCount() <= index {
		return ""
	}
	p := params.NamedChild(index)
	if p.Kind() == "required_parameter" || p.Kind() == "optional_parameter" {
		p = p.ChildByFieldName("pattern")
	}
	if p != nil && p.Kind() == "identifier" {
		return p.Utf8Text(src)
	}
	return ""
}

func (f *flow) isResponse(n *sitter.Node) bool {
	if n == nil || f.response == "" {
		return false
	}
	if n.Kind() == "identifier" {
		return n.Utf8Text(f.module.src) == f.response
	}
	if n.Kind() == "call_expression" {
		fn := n.ChildByFieldName("function")
		if fn != nil && fn.Kind() == "member_expression" {
			prop := fn.ChildByFieldName("property")
			if prop != nil {
				switch prop.Utf8Text(f.module.src) {
				case "status", "type", "set", "header", "setHeader", "contentType":
					return f.isResponse(fn.ChildByFieldName("object"))
				}
			}
		}
	}
	return false
}

func (f *flow) responseCall(call, fn, args *sitter.Node, values []value) bool {
	if fn == nil || fn.Kind() != "member_expression" || !f.isResponse(fn.ChildByFieldName("object")) {
		return false
	}
	prop := fn.ChildByFieldName("property")
	if prop == nil {
		return false
	}
	method := prop.Utf8Text(f.module.src)
	if method == "type" || method == "contentType" || method == "set" || method == "header" || method == "setHeader" {
		if args != nil && args.NamedChildCount() > 0 {
			pos := uint(0)
			if method != "type" && method != "contentType" {
				key, ok := stringLiteral(args.NamedChild(0), f.module.src)
				if !ok || !strings.EqualFold(key, "content-type") || args.NamedChildCount() < 2 {
					return true
				}
				pos = 1
			}
			contentType, ok := stringLiteral(args.NamedChild(pos), f.module.src)
			if !ok {
				contentType = "unknown"
			}
			for p := call.Parent(); p != nil && p.Kind() != "function_expression" && p.Kind() != "arrow_function"; p = p.Parent() {
				if p.Kind() == "if_statement" || p.Kind() == "switch_statement" {
					contentType = "unknown"
				}
			}
			f.responseType = strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
		}
		return true
	}
	if method == "render" {
		f.renderTemplate(call, args)
		return true
	}
	if method == "json" && len(values) > 0 && len(values[0].deps) > 0 {
		f.recordXSSData(call, values[0], "api_json", "cross_tier")
		return true
	}
	if method == "json" && len(values) > 0 && hasModelRows(values[0], 0) {
		f.recordProducer(call, values[0])
		return true
	}
	if method != "send" && method != "write" && method != "end" {
		return method == "json" || method == "status" || method == "redirect" || method == "sendStatus"
	}
	if len(values) == 0 || len(values[0].deps) == 0 {
		return true
	}
	// Express serializes an object argument as JSON, not HTML.
	if method == "send" && args != nil && args.NamedChildCount() > 0 && args.NamedChild(0).Kind() == "object" {
		f.recordXSSData(call, values[0], "api_json", "cross_tier")
		return true
	}
	contentType := f.responseType
	if contentType == "" && method == "send" && args != nil && (values[0].outputHTML || stringOutput(args.NamedChild(0), f.module, 0)) {
		contentType = "text/html"
	}
	if contentType != "" && contentType != "unknown" && contentType != "html" && contentType != "text/html" && contentType != "application/xhtml+xml" {
		return true
	}
	context := "html_text"
	if contentType == "" || contentType == "unknown" {
		context = "unknown"
	}
	if args != nil && args.NamedChildCount() > 0 {
		context = responseOutputContext(args.NamedChild(0), f.module, context)
	}
	if values[0].outputContext != "" {
		context = values[0].outputContext
	}
	if contentType == "" || contentType == "unknown" {
		context = "unknown"
	}
	sink := f.module.evidence("html_response", call)
	if contentType == "" || contentType == "unknown" {
		f.recordXSS(sink, values[0], context, contentType, false, nil)
		return true
	}
	groups := outputGroups(values[0], context)
	for _, g := range groups {
		before := len(f.uses)
		f.recordXSS(sink, g.value, g.context, contentType, false, nil)
		if len(groups) > 1 && len(f.uses) > before {
			f.uses[len(f.uses)-1].ID += ":" + g.context
		}
	}
	return true
}

func stringOutput(n *sitter.Node, m *sourceModule, depth int) bool {
	if n == nil || depth > 4 {
		return false
	}
	switch n.Kind() {
	case "string", "template_string":
		return true
	case "binary_expression":
		return strings.Contains(n.Utf8Text(m.src), "+") && (stringOutput(n.ChildByFieldName("left"), m, depth+1) || stringOutput(n.ChildByFieldName("right"), m, depth+1))
	case "identifier":
		return stringOutput(definitionAt(m, n, n.Utf8Text(m.src)), m, depth+1)
	}
	return false
}

func responseOutputContext(n *sitter.Node, m *sourceModule, fallback string) string {
	if n.Kind() == "template_string" {
		contexts := map[string]bool{}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			child := n.NamedChild(i)
			if child.Kind() == "template_substitution" {
				contexts[htmlOutputContext(string(m.src[n.StartByte():child.StartByte()]))] = true
			}
		}
		if len(contexts) == 1 {
			for context := range contexts {
				return context
			}
		}
		if len(contexts) > 1 {
			return "mixed"
		}
	}
	if n.Kind() == "binary_expression" {
		if prefix, ok := stringLiteral(n.ChildByFieldName("left"), m.src); ok {
			return htmlOutputContext(prefix)
		}
		return responseOutputContext(n.ChildByFieldName("left"), m, fallback)
	}
	return fallback
}

func (f *flow) recordXSS(sink analysis.Evidence, v value, context, contentType string, escaped bool, extra []analysis.Evidence) {
	if len(v.deps) == 0 {
		return
	}
	protection, reason, protections := f.xssPathProtection(v, context, escaped)
	paths := xssPaths(protections, nil)
	if ext := strings.ToLower(filepath.Ext(sink.Span.File)); escaped && (ext == ".hbs" || ext == ".handlebars") {
		safe := make([]string, len(v.deps))
		for i, d := range v.deps {
			safe[i] = protection
			if f.handlebarsSafeString(d) {
				safe[i] = "raw"
				protection, reason = "raw", "A Handlebars SafeString reaches this output; Handlebars does not escape SafeString content."
			}
		}
		if protection == "raw" {
			paths = xssPaths(safe, nil)
		}
	}
	if context == "unknown" || context == "mixed" {
		protection, reason, paths = "unknown", "Rendering context is not established for every value.", nil
	}
	ctx := append(append([]analysis.Evidence{}, f.context...), extra...)
	if m := f.registration; m != nil {
		var names []string
		for name := range m.imports {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			imp := m.imports[name]
			if imp.module == "express" {
				ctx = append(ctx, m.evidence("render_binding", imp.declaration))
			}
		}
	}
	gaps := append(append([]analysis.Gap{}, f.gaps...), v.gaps...)
	kind := "reflected"
	for _, dependency := range v.deps {
		if dependency.StorageKey != "" {
			kind = "stored"
		}
		if dependency.Source.Kind == "unresolved_source" && !escaped {
			protection, reason, paths = "unknown", "The value source and transfer into rendering are not established.", nil
		}
	}

	entryKind := "server"
	identity := f.entry.ID
	if f.client != nil {
		kind, entryKind, identity = "dom", "client", f.client.entry.ID
	}
	f.uses = append(f.uses, analysis.CandidateUse{
		ID: fmt.Sprintf("xss:%s:%s:%d", identity, sink.Span.File, sink.Span.StartByte), EntryID: f.entry.ID, InvocationContextID: f.invocation.ID, EntryKind: f.entry.Kind,
		Kind: "xss_candidate", Sink: sink, Dependencies: v.deps, Context: ctx, Gaps: gaps,
		XSS: &analysis.XSSFacts{Type: kind, EntryKind: entryKind, OutputContext: context, OriginResolved: kind == "reflected" || kind == "dom",
			ContentType: contentType, Protection: protection, ProtectionReason: reason, Paths: paths},
		APIModel:   analysispacks.XSSContract("html-output-v1", "express"),
		Assessment: analysis.Assessment{Status: "not_run"},
	})
	if f.client != nil {
		last := &f.uses[len(f.uses)-1]
		last.APIModel = analysispacks.XSSContract("browser-output-v1", f.client.entry.Browser.Framework)
	}
}
