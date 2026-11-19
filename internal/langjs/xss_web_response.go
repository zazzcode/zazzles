package langjs

import (
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
)

// webResponseConstructor evaluates `new Response(body, init)` or Next.js
// `new NextResponse(body, init)` in a web-standard handler and records the body
// as an HTML response when init sets an HTML Content-Type. The Fetch
// constructor sends a string body as text/plain unless init.headers sets a
// type, so a non-HTML or omitted type records nothing. An init or header value
// that is not a closed literal records an unresolved-context candidate.
//
// The returned value is the one eval's default case would produce, so
// non-HTML responses keep their existing flow.
func (f *flow) webResponseConstructor(n *sitter.Node) (value, bool) {
	ctor, args := n.ChildByFieldName("constructor"), n.ChildByFieldName("arguments")
	if f.web == nil || f.client != nil || ctor == nil || ctor.Kind() != "identifier" || args == nil || args.NamedChildCount() == 0 {
		return value{}, false
	}
	binding, ok := f.webResponseBinding(n, ctor)
	if !ok || f.work >= 10000 {
		return value{}, false
	}
	// Mirror eval's default case: transfer(children(n)), where the arguments
	// child is itself transfer(children(arguments)).
	var operands []*sitter.Node // arguments without comments
	for j := uint(0); j < args.NamedChildCount(); j++ {
		if a := args.NamedChild(j); a.Kind() != "comment" {
			operands = append(operands, a)
		}
	}
	if len(operands) == 0 {
		return value{}, false
	}
	out, body, limited := value{}, value{}, false
	for i := uint(0); i < n.NamedChildCount(); i++ {
		child := n.NamedChild(i)
		if child.Kind() != "arguments" || child.StartByte() != args.StartByte() {
			out = combine(out, f.eval(child))
			continue
		}
		// eval(arguments) counts one unit of work and enforces the limit.
		f.work++
		if f.work > 10000 {
			gap := f.gap("work_limit", "handler expression work limit reached", args)
			if f.work == 10001 {
				f.gaps = append(f.gaps, gap)
			}
			out, limited = combine(out, value{gaps: []analysis.Gap{gap}}), true
			continue
		}
		argv := value{}
		for j := uint(0); j < args.NamedChildCount(); j++ {
			a := args.NamedChild(j)
			v := f.eval(a)
			if a.StartByte() == operands[0].StartByte() && a.Kind() == operands[0].Kind() {
				body = v
			}
			argv = combine(argv, v)
		}
		out = combine(out, f.transfer(argv, "expression", args))
	}
	var init *sitter.Node
	if len(operands) > 1 {
		init = operands[1]
	}
	contentType, header := webResponseContentType(init, f.module.src)
	if !limited && (contentType == "unknown" || contentType == "text/html" || contentType == "application/xhtml+xml") {
		evidence := []analysis.Evidence{binding}
		if header != nil {
			evidence = append(evidence, f.module.evidence("render_binding", header))
		}
		before := len(f.uses)
		f.recordHTMLResponse(n, operands[0], body, contentType, evidence)
		for i := before; i < len(f.uses); i++ {
			f.uses[i].APIModel = analysispacks.XSSContract("html-output-v1", analysispacks.FetchResponseLibrary)
		}
	}
	return f.transfer(out, "expression", n), true
}

// webResponseBinding verifies the constructor: the global Response, or
// NextResponse imported from next/server, neither shadowed.
func (f *flow) webResponseBinding(n, ctor *sitter.Node) (analysis.Evidence, bool) {
	name := ctor.Utf8Text(f.module.src)
	if shadowed(n, name, f.module.src) {
		return analysis.Evidence{}, false
	}
	switch name {
	case "NextResponse":
		imp, ok := f.module.imports[name]
		if !ok || imp.module != "next/server" || imp.name != "NextResponse" || imp.declaration == nil {
			return analysis.Evidence{}, false
		}
		return f.module.evidence("render_binding", imp.declaration), true
	case "Response":
		if moduleBinds(f.module, name) || topClass(f.module, name) {
			return analysis.Evidence{}, false
		}
		return f.module.evidence("render_binding", ctor), true
	}
	return analysis.Evidence{}, false
}

// topClass reports a module-level class declaration with this name.
func topClass(m *sourceModule, name string) bool {
	root := m.tree.RootNode()
	for i := uint(0); i < root.NamedChildCount(); i++ {
		n := root.NamedChild(i)
		if n.Kind() == "export_statement" {
			n = n.ChildByFieldName("declaration")
		}
		if n != nil && n.Kind() == "class_declaration" {
			if id := n.ChildByFieldName("name"); id != nil && id.Utf8Text(m.src) == name {
				return true
			}
		}
	}
	return false
}

// webResponseContentType reads the Content-Type a Response init sets. It
// returns the lowercased media type and its header pair, "" when no type is
// set, or "unknown" when the init or its headers are not a closed literal.
func webResponseContentType(init *sitter.Node, src []byte) (string, *sitter.Node) {
	if init == nil {
		return "", nil
	}
	if init.Kind() != "object" {
		return "unknown", nil
	}
	// A later spread or computed key may replace headers; an earlier one is
	// overridden by an explicit headers property.
	contentType, header, have, spread := "", (*sitter.Node)(nil), false, false
	replaceable := func() {
		if have {
			contentType, header = "unknown", nil
		} else {
			spread = true
		}
	}
	for i := uint(0); i < init.NamedChildCount(); i++ {
		child := init.NamedChild(i)
		switch child.Kind() {
		case "spread_element":
			replaceable()
		case "shorthand_property_identifier":
			if child.Utf8Text(src) == "headers" {
				contentType, header, have = "unknown", nil, true
			}
		case "pair":
			key, ok := propertyKey(child.ChildByFieldName("key"), src)
			if !ok {
				replaceable()
				continue
			}
			if key != "headers" {
				continue
			}
			contentType, header, have = initHeaders(child.ChildByFieldName("value"), src)
		}
	}
	if !have && spread {
		return "unknown", nil
	}
	return contentType, header
}

// initHeaders reads an init.headers value: an object literal or
// `new Headers({...})`; anything else is unknown.
func initHeaders(headers *sitter.Node, src []byte) (string, *sitter.Node, bool) {
	if headers != nil && headers.Kind() == "new_expression" {
		ctor, args := headers.ChildByFieldName("constructor"), headers.ChildByFieldName("arguments")
		if ctor == nil || ctor.Utf8Text(src) != "Headers" || shadowed(headers, "Headers", src) || args == nil || args.NamedChildCount() != 1 {
			return "unknown", nil, true
		}
		headers = args.NamedChild(0)
	}
	if headers == nil || headers.Kind() != "object" {
		return "unknown", nil, true
	}
	contentType, header := headerContentType(headers, src)
	return contentType, header, true
}

func headerContentType(headers *sitter.Node, src []byte) (string, *sitter.Node) {
	contentType, found, spread := "", (*sitter.Node)(nil), false
	for i := uint(0); i < headers.NamedChildCount(); i++ {
		child := headers.NamedChild(i)
		switch child.Kind() {
		case "shorthand_property_identifier":
			// `{ etag }` names its own header; it cannot be Content-Type.
		case "spread_element":
			// A later spread may replace an earlier type.
			spread = true
			if found != nil {
				contentType = "unknown"
			}
		case "pair":
			key, ok := propertyKey(child.ChildByFieldName("key"), src)
			if !ok {
				spread = true
				if found != nil {
					contentType = "unknown"
				}
				continue
			}
			if !strings.EqualFold(key, "content-type") {
				continue
			}
			found = child
			text, literal := literalText(child.ChildByFieldName("value"), src)
			if !literal {
				contentType = "unknown"
				continue
			}
			contentType = strings.ToLower(strings.TrimSpace(strings.Split(text, ";")[0]))
		}
	}
	if found == nil && spread {
		return "unknown", nil
	}
	return contentType, found
}

// propertyKey returns a literal object key; computed keys are not literal.
func propertyKey(key *sitter.Node, src []byte) (string, bool) {
	if key == nil {
		return "", false
	}
	switch key.Kind() {
	case "property_identifier":
		return key.Utf8Text(src), true
	case "string":
		return stringLiteral(key, src)
	}
	return "", false
}

// literalText returns a string or substitution-free template literal.
func literalText(n *sitter.Node, src []byte) (string, bool) {
	if n == nil {
		return "", false
	}
	if n.Kind() == "template_string" {
		for i := uint(0); i < n.NamedChildCount(); i++ {
			if n.NamedChild(i).Kind() == "template_substitution" {
				return "", false
			}
		}
		text := n.Utf8Text(src)
		return text[1 : len(text)-1], true
	}
	return stringLiteral(n, src)
}
