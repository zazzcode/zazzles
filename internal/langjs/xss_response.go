package langjs

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
	"github.com/zazzcode/zazzles/internal/parse"
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
	var body *sitter.Node
	if args != nil && args.NamedChildCount() > 0 {
		body = args.NamedChild(0)
	}
	f.recordHTMLResponse(call, body, values[0], contentType, nil)
	return true
}

// recordHTMLResponse records an HTML response body at call. contentType is an
// HTML media type, or "" / "unknown" when the response type is not
// established; binding is extra rendering evidence for the response API.
func (f *flow) recordHTMLResponse(call, body *sitter.Node, v value, contentType string, binding []analysis.Evidence) {
	context := "html_text"
	if contentType == "" || contentType == "unknown" {
		context = "unknown"
	}
	if body != nil {
		context = responseOutputContext(body, f.module, context)
	}
	if v.outputContext != "" {
		context = v.outputContext
	}
	if contentType == "" || contentType == "unknown" {
		context = "unknown"
	}
	sink := f.module.evidence("html_response", call)
	if contentType == "" || contentType == "unknown" {
		f.recordXSS(sink, v, context, contentType, false, binding)
		return
	}
	groups := outputGroups(v, context)
	for _, g := range groups {
		before := len(f.uses)
		markup := binding
		if len(groups) > 1 {
			markup = append(append([]analysis.Evidence{}, binding...), f.outputMarkup(g.value)...)
		}
		f.recordXSS(sink, g.value, g.context, contentType, false, markup)
		if len(groups) > 1 && len(f.uses) > before {
			f.uses[len(f.uses)-1].ID += ":" + g.context
		}
	}
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
				contexts[parse.HTMLOutputContext(string(m.src[n.StartByte():child.StartByte()]))] = true
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
			return parse.HTMLOutputContext(prefix)
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

// closedTypeMap resolves a Content-Type operand read from a closed constant
// map. The map is a module-level const object literal with literal keys and
// literal string values that is only ever read by subscript (never assigned,
// exported or passed out), the operand is a never-reassigned const set from
// MAP[key], and a missing-key branch returns before the response at. It
// returns every value the map can give; ok is false when any rule fails.
func closedTypeMap(m *sourceModule, at, operand *sitter.Node) (types []string, ok bool) {
	if operand == nil {
		return nil, false
	}
	operand = unwrapTS(operand)
	if operand.Kind() != "identifier" {
		return nil, false
	}
	name := operand.Utf8Text(m.src)
	if bindingReassigned(m, name) {
		return nil, false
	}
	init := localInitializer(m, at, name)
	if init == nil {
		return nil, false
	}
	init = unwrapTS(init)
	if init.Kind() != "subscript_expression" {
		return nil, false
	}
	object := init.ChildByFieldName("object")
	if object == nil || object.Kind() != "identifier" {
		return nil, false
	}
	table := object.Utf8Text(m.src)
	literal := topConstObject(m, table)
	if literal == nil || exportedName(m, table) || bindingReassigned(m, table) || !subscriptReadsOnly(m, table) || !missingKeyReturns(m, at, name) {
		return nil, false
	}
	for i := uint(0); i < literal.NamedChildCount(); i++ {
		pair := literal.NamedChild(i)
		if pair.Kind() == "comment" {
			continue
		}
		if pair.Kind() != "pair" {
			return nil, false
		}
		if _, ok := propertyKey(pair.ChildByFieldName("key"), m.src); !ok {
			return nil, false
		}
		text, ok := stringLiteral(pair.ChildByFieldName("value"), m.src)
		if !ok {
			return nil, false
		}
		types = append(types, strings.ToLower(strings.TrimSpace(strings.Split(text, ";")[0])))
	}
	return types, len(types) > 0
}

// htmlCapableType reports a media type a browser can render as markup with
// script: HTML, XHTML, SVG and other XML types.
func htmlCapableType(t string) bool {
	return t == "text/html" || strings.Contains(t, "xml") || strings.HasSuffix(t, "+xml")
}

// topConstObject returns the object literal of a module-level const binding.
func topConstObject(m *sourceModule, name string) *sitter.Node {
	root := m.tree.RootNode()
	for i := uint(0); i < root.NamedChildCount(); i++ {
		n := root.NamedChild(i)
		if n.Kind() != "lexical_declaration" || !strings.HasPrefix(n.Utf8Text(m.src), "const") {
			continue
		}
		for j := uint(0); j < n.NamedChildCount(); j++ {
			d := n.NamedChild(j)
			id, value := d.ChildByFieldName("name"), d.ChildByFieldName("value")
			if id != nil && id.Utf8Text(m.src) == name && value != nil {
				value = unwrapTS(value)
				if value.Kind() == "object" {
					return value
				}
				return nil
			}
		}
	}
	return nil
}

// subscriptReadsOnly reports that every reference to name in the module is
// its declaration or the object of a read subscript: never written through,
// deleted, passed, returned or aliased.
func subscriptReadsOnly(m *sourceModule, name string) bool {
	ok := true
	var walk func(n *sitter.Node)
	walk = func(n *sitter.Node) {
		if n == nil || !ok {
			return
		}
		if n.Kind() == "identifier" && n.Utf8Text(m.src) == name {
			p := n.Parent()
			switch {
			case p != nil && p.Kind() == "variable_declarator" && p.ChildByFieldName("name") != nil && p.ChildByFieldName("name").StartByte() == n.StartByte():
			case p != nil && p.Kind() == "subscript_expression" && p.ChildByFieldName("object") != nil && p.ChildByFieldName("object").StartByte() == n.StartByte():
				if g := p.Parent(); g != nil {
					switch g.Kind() {
					case "assignment_expression", "augmented_assignment_expression":
						if left := g.ChildByFieldName("left"); left != nil && left.StartByte() == p.StartByte() {
							ok = false
						}
					case "update_expression", "unary_expression":
						if strings.HasPrefix(g.Utf8Text(m.src), "delete") || g.Kind() == "update_expression" {
							ok = false
						}
					}
				}
			default:
				ok = false
			}
		}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			walk(n.NamedChild(i))
		}
	}
	walk(m.tree.RootNode())
	return ok
}

// missingKeyReturns reports that a statement before at, in an enclosing block
// of the same function, is `if (!name) return ...` (or a block ending in
// return or throw), or `if (name === undefined)` / `== null`.
func missingKeyReturns(m *sourceModule, at *sitter.Node, name string) bool {
	child := at
	for p := at.Parent(); p != nil && !isFunction(p); child, p = p, p.Parent() {
		if p.Kind() != "statement_block" && p.Kind() != "program" {
			continue
		}
		for i := uint(0); i < p.NamedChildCount(); i++ {
			s := p.NamedChild(i)
			if s.StartByte() >= child.StartByte() {
				break
			}
			if s.Kind() == "if_statement" && missingKeyTest(m, s.ChildByFieldName("condition"), name) && exits(s.ChildByFieldName("consequence")) && s.ChildByFieldName("alternative") == nil {
				return true
			}
		}
	}
	return false
}

func missingKeyTest(m *sourceModule, cond *sitter.Node, name string) bool {
	if cond == nil {
		return false
	}
	text := strings.Join(strings.Fields(strings.Trim(strings.TrimSpace(cond.Utf8Text(m.src)), "()")), " ")
	switch text {
	case "!" + name, name + " === undefined", name + " == undefined", name + " == null", name + " === null", "undefined === " + name, "null == " + name:
		return true
	}
	return false
}

func exits(n *sitter.Node) bool {
	if n == nil {
		return false
	}
	switch n.Kind() {
	case "return_statement", "throw_statement":
		return true
	case "statement_block":
		for i := int(n.NamedChildCount()) - 1; i >= 0; i-- {
			last := n.NamedChild(uint(i))
			if last.Kind() == "comment" {
				continue
			}
			return last.Kind() == "return_statement" || last.Kind() == "throw_statement"
		}
	}
	return false
}
