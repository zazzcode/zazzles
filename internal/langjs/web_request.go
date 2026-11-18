package langjs

import (
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
)

// webState is the web-request-v1 acquisition context of one Next.js entry: the
// handler's context parameter and the route segments that type path params.
type webState struct {
	project    *nextProject
	segments   map[string]nextSegment
	context    string // second handler parameter (route context)
	paramsName string // local name of a destructured `{ params }` parameter
	framework  string
	surface    string
	// pageProps names the page/layout props object or destructured locals.
	searchParamsName string
}

func nextFramework(f string) bool { return f == "nextjs" || f == "nextjs-pages" }

// webKindOrigin is the acquisition origin of a whole web object of a kind.
var webKindOrigin = map[string]string{
	"searchParams": "http.query",
	"headers":      "http.headers",
	"cookies":      "http.cookies",
	"formData":     "http.body",
	"url":          "http.url",
	"nexturl":      "http.url",
	"params":       "http.path",
	"pageSearch":   "http.query",
}

// webRecv classifies an expression as a verified web-request object. Values
// already bound in the flow carry their kind; otherwise the receiver chain must
// reach the handler's own request or context parameter. Names alone never
// qualify: a local `headers` or `searchParams` is an ordinary binding.
func (f *flow) webRecv(n *sitter.Node) (kind string, recv value, bound bool) {
	n = unwrapTS(n)
	if n == nil || f.web == nil {
		return "", value{}, false
	}
	src := f.module.src
	switch n.Kind() {
	case "identifier":
		name := n.Utf8Text(src)
		if v, ok := f.env[name]; ok {
			return v.web, v, true
		}
		if f.request != "" && name == f.request {
			return "request", value{}, false
		}
		if f.web.context != "" && name == f.web.context {
			return "context", value{}, false
		}
		if f.web.paramsName != "" && name == f.web.paramsName {
			return "params", value{}, false
		}
		if f.web.searchParamsName != "" && name == f.web.searchParamsName {
			return "pageSearch", value{}, false
		}
	case "member_expression":
		obj, prop := n.ChildByFieldName("object"), n.ChildByFieldName("property")
		if obj == nil || prop == nil {
			return "", value{}, false
		}
		base, baseValue, baseBound := f.webRecv(obj)
		switch base + "." + prop.Utf8Text(src) {
		case "validated.data":
			v := f.transfer(baseValue, "property_read", n)
			return "validatedData", v, baseBound
		case "request.nextUrl":
			return "nexturl", value{}, false
		case "request.headers":
			return "headers", value{}, false
		case "request.cookies":
			return "cookies", value{}, false
		case "nexturl.searchParams", "url.searchParams":
			return "searchParams", value{}, false
		case "context.params":
			return "params", value{}, false
		case "context.searchParams":
			return "pageSearch", value{}, false
		}
	case "new_expression":
		ctor, args := n.ChildByFieldName("constructor"), n.ChildByFieldName("arguments")
		if ctor != nil && ctor.Kind() == "identifier" && ctor.Utf8Text(src) == "URL" && !moduleBinds(f.module, "URL") && args != nil && args.NamedChildCount() >= 1 {
			a := unwrapTS(args.NamedChild(0))
			if a.Kind() == "member_expression" {
				if b, _, _ := f.webRecv(a.ChildByFieldName("object")); b == "request" || b == "nexturl" {
					if p := a.ChildByFieldName("property"); p != nil && (p.Utf8Text(src) == "url" || p.Utf8Text(src) == "href") {
						return "url", value{}, false
					}
				}
			}
			if b, _, _ := f.webRecv(a); b == "nexturl" {
				return "url", value{}, false
			}
		}
	case "await_expression":
		if n.NamedChildCount() == 1 {
			k, v, b := f.webRecv(n.NamedChild(0))
			if k == "formDataPromise" {
				k = "formData"
			}
			return k, v, b
		}
	case "call_expression":
		fn := n.ChildByFieldName("function")
		if fn == nil {
			return "", value{}, false
		}
		if fn.Kind() == "identifier" {
			if imp, ok := f.module.imports[fn.Utf8Text(src)]; ok && imp.module == "next/headers" && !shadowed(n, fn.Utf8Text(src), src) {
				switch imp.name {
				case "headers":
					return "headers", value{}, false
				case "cookies":
					return "cookies", value{}, false
				}
			}
			return "", value{}, false
		}
		if fn.Kind() == "member_expression" {
			base, _, _ := f.webRecv(fn.ChildByFieldName("object"))
			prop := fn.ChildByFieldName("property")
			if prop != nil && base == "request" {
				switch prop.Utf8Text(src) {
				case "formData":
					return "formDataPromise", value{}, false
				case "clone":
					return "request", value{}, false
				}
			}
		}
	}
	return "", value{}, false
}

// keyFragment returns the literal key node of a get(k) style call and its text.
func keyFragment(args *sitter.Node, src []byte) (*sitter.Node, string, bool) {
	if args == nil || args.NamedChildCount() == 0 {
		return nil, "", false
	}
	a := args.NamedChild(0)
	text, ok := stringLiteral(a, src)
	if !ok {
		return nil, "", false
	}
	for i := uint(0); i < a.NamedChildCount(); i++ {
		if c := a.NamedChild(i); c.Kind() == "string_fragment" {
			return c, text, true
		}
	}
	return a, text, true
}

// webSource returns a value for a web-request read at n. A read on a bound value
// of the same origin keeps that value's source and adds a request_read transfer;
// any other read is a new source whose origin is recorded for input facts.
func (f *flow) webSource(n *sitter.Node, origin, typ, field string, keyNode *sitter.Node, recv value, bound bool, kind string) value {
	var v value
	sameOrigin := bound && len(recv.deps) > 0 && webValueOrigin(f.set, recv) == origin
	if sameOrigin {
		v = f.transfer(recv, "request_read", n)
		v.web, v.gaps = kind, append([]analysis.Gap{}, recv.gaps...)
	} else {
		source := f.module.evidence("input_source", n)
		f.rememberInput(source)
		if f.set != nil {
			f.set.recordWebOrigin(source, webOrigin{origin: origin, initialType: typ, field: field})
		}
		v = value{web: kind, deps: []analysis.Dependency{{Source: source, Transfers: []analysis.Evidence{}}}}
	}
	if keyNode != nil && field != "" {
		v = f.transfer(v, "field_projection", keyNode)
	}
	return v
}

func webValueOrigin(s *moduleSet, v value) string {
	if s == nil || len(v.deps) == 0 {
		return ""
	}
	o, ok := s.webOriginFor(v.deps[0].Source)
	if !ok {
		return ""
	}
	return o.origin
}

// webMember models a property read on a web object of kind.
func (f *flow) webMember(kind string, recv value, bound bool, prop string, n, keyNode *sitter.Node) (value, bool) {
	switch kind {
	case "request":
		switch prop {
		case "url":
			return f.webSource(n, "http.url", "string", "", nil, recv, bound, ""), true
		case "method":
			return f.webSource(n, "http.method", "string", "", nil, recv, bound, ""), true
		case "body":
			return f.webSource(n, "http.body", "stream", "", nil, recv, bound, ""), true
		case "nextUrl":
			return value{web: "nexturl"}, true
		case "headers", "cookies":
			return f.webSource(n, webKindOrigin[prop], "object", "", nil, recv, bound, prop), true
		}
	case "nexturl", "url":
		switch prop {
		case "searchParams":
			return f.webSource(n, "http.query", "URLSearchParams", "", nil, recv, bound, "searchParams"), true
		case "pathname", "href", "search", "hash", "host", "hostname", "origin", "port", "protocol":
			return f.webSource(n, "http.url", "string", "", nil, recv, bound, ""), true
		}
	case "context":
		switch prop {
		case "params":
			return value{web: "params"}, true
		case "searchParams":
			return value{web: "pageSearch"}, true
		}
	case "params":
		typ := "string"
		if seg, ok := f.web.segments[prop]; ok {
			typ = seg.paramType
		}
		if keyNode == nil {
			keyNode = n
		}
		v := f.webSource(n, "http.path", typ, prop, nil, recv, bound, "")
		return f.transfer(v, "field_projection", keyNode), true
	case "pageSearch":
		v := f.webSource(n, "http.query", "string | string[] | undefined", prop, nil, recv, bound, "")
		if keyNode == nil {
			keyNode = n
		}
		return f.transfer(v, "field_projection", keyNode), true
	case "validated":
		// parsed.data is the schema's output object; its fields are projections.
		if prop == "data" {
			v := f.transfer(recv, "property_read", n)
			v.web = "validatedData"
			return v, true
		}
		if prop == "success" || prop == "response" || prop == "error" {
			return value{}, true
		}
	case "validatedData":
		v := f.transfer(recv, "property_read", n)
		v = f.transfer(v, "field_projection", keyNode)
		v.web = ""
		return v, true
	case "formEntry":
		switch prop {
		case "name":
			return f.webSource(n, "http.upload_filename", "string", "", nil, value{}, false, ""), true
		case "type":
			return f.webSource(n, "http.upload_content_type", "string", "", nil, value{}, false, ""), true
		case "size":
			return value{}, true
		}
	}
	return value{}, false
}

// webValue is the web-request-v1 acquisition hook of flow.eval.
func (f *flow) webValue(n *sitter.Node) (value, bool) {
	if f.web == nil || n == nil {
		return value{}, false
	}
	src := f.module.src
	switch n.Kind() {
	case "identifier":
		name := n.Utf8Text(src)
		if _, ok := f.env[name]; ok {
			return value{}, false
		}
		kind, _, _ := f.webRecv(n)
		switch kind {
		case "request", "context":
			return value{web: kind}, true
		case "params", "pageSearch":
			return value{web: kind}, true
		}
	case "await_expression":
		if n.NamedChildCount() != 1 {
			return value{}, false
		}
		inner := unwrapTS(n.NamedChild(0))
		if !f.webAwaitable(inner) {
			return value{}, false
		}
		v := f.eval(n.NamedChild(0))
		if v.web == "formDataPromise" {
			v.web = "formData"
		}
		out := f.transfer(v, "await_request_read", n)
		out.web = v.web
		return out, true
	case "member_expression":
		obj, prop := n.ChildByFieldName("object"), n.ChildByFieldName("property")
		if obj == nil || prop == nil {
			return value{}, false
		}
		kind, recv, bound := f.webRecv(obj)
		if kind == "" {
			return value{}, false
		}
		return f.webMember(kind, recv, bound, prop.Utf8Text(src), n, prop)
	case "new_expression":
		if kind, _, _ := f.webRecv(n); kind == "url" {
			return f.webSource(n, "http.url", "URL", "", nil, value{}, false, "url"), true
		}
	case "call_expression":
		fn, args := n.ChildByFieldName("function"), n.ChildByFieldName("arguments")
		if fn == nil {
			return value{}, false
		}
		if fn.Kind() == "identifier" {
			if kind, _, _ := f.webRecv(n); kind == "headers" || kind == "cookies" {
				return value{web: kind}, true
			}
			return value{}, false
		}
		if fn.Kind() != "member_expression" {
			return value{}, false
		}
		prop := fn.ChildByFieldName("property")
		kind, recv, bound := f.webRecv(fn.ChildByFieldName("object"))
		if kind == "" || prop == nil {
			return value{}, false
		}
		method := prop.Utf8Text(src)
		keyNode, key, literal := keyFragment(args, src)
		switch kind {
		case "searchParams", "headers", "cookies", "formData":
			origin := webKindOrigin[kind]
			switch method {
			case "get", "getAll":
				typ := "string | null"
				next := ""
				switch kind {
				case "cookies":
					typ, next = "RequestCookie | undefined", "cookie"
				case "formData":
					typ, next = "string | File | null", "formEntry"
				}
				if method == "getAll" {
					typ = "string[]"
				}
				if kind == "headers" {
					key = strings.ToLower(key)
				}
				if !literal {
					v := f.webSource(n, origin, "unknown", "", nil, recv, bound, "")
					v.gaps = append(v.gaps, f.gap("input_key_unresolved", "request read key is not a literal", n))
					return v, true
				}
				return f.webSource(n, origin, typ, key, keyNode, recv, bound, next), true
			case "has":
				return value{}, true
			case "keys", "values", "entries", "toString", "forEach", "getSetCookie":
				return f.webSource(n, origin, "iterable", "", nil, recv, bound, ""), true
			}
		case "request":
			switch method {
			case "json":
				return f.webSource(n, "http.body", "unknown", "", nil, recv, bound, ""), true
			case "text":
				return f.webSource(n, "http.body", "string", "", nil, recv, bound, ""), true
			case "arrayBuffer", "blob", "bytes":
				return f.webSource(n, "http.body", "binary", "", nil, recv, bound, ""), true
			case "formData":
				return value{web: "formDataPromise"}, true
			case "clone":
				return value{web: "request"}, true
			}
		case "fetchedResponse":
			// Reading the body of a fetched response keeps its content.
			switch method {
			case "text", "json", "arrayBuffer", "blob", "bytes":
				v := f.transfer(recv, "response_body", n)
				v.web = ""
				return v, true
			}
		case "formEntry":
			switch method {
			case "arrayBuffer", "text", "stream", "bytes", "slice":
				return f.webSource(n, "http.upload_content", "binary", "", nil, value{}, false, ""), true
			}
		}
	}
	return value{}, false
}

// webAwaitable reports an awaited expression whose promise web-request-v1
// models: request body readers, formData, params, page searchParams,
// next/headers calls and uploaded-file readers.
func (f *flow) webAwaitable(n *sitter.Node) bool {
	if kind, _, _ := f.webRecv(n); kind != "" {
		return true
	}
	if n == nil || n.Kind() != "call_expression" {
		return false
	}
	// Awaiting a resolved local async function is its analyzed return value.
	if f.set != nil {
		if hm, helper := f.set.resolveCall(f.module, n); hm != nil && helper != nil && supportedCallee(helper) && asyncFunction(helper) {
			return true
		}
	}
	fn := n.ChildByFieldName("function")
	if fn == nil || fn.Kind() != "member_expression" {
		return false
	}
	kind, _, _ := f.webRecv(fn.ChildByFieldName("object"))
	prop := fn.ChildByFieldName("property")
	if prop == nil {
		return false
	}
	switch kind + "." + prop.Utf8Text(f.module.src) {
	case "request.json", "request.text", "request.arrayBuffer", "request.blob", "request.bytes", "request.formData",
		"formEntry.arrayBuffer", "formEntry.text", "formEntry.bytes":
		return true
	}
	return false
}

// webProjection binds a destructured property of a web object
// (`const { searchParams } = new URL(request.url)`, `const { id } = await params`).
func (f *flow) webProjection(v value, prop string, binding *sitter.Node) (value, bool) {
	if f.web == nil || v.web == "" {
		return value{}, false
	}
	return f.webMember(v.web, v, len(v.deps) > 0, prop, binding, binding)
}

// nextJSONResponse records `NextResponse.json(x)` / `Response.json(x)` as a JSON
// producer for cross-tier links. JSON is not an HTML sink.
func (f *flow) nextJSONResponse(n, fn *sitter.Node, values []value) bool {
	if f.web == nil || fn == nil || fn.Kind() != "member_expression" || len(values) == 0 {
		return false
	}
	obj, prop := fn.ChildByFieldName("object"), fn.ChildByFieldName("property")
	if obj == nil || prop == nil || obj.Kind() != "identifier" || prop.Utf8Text(f.module.src) != "json" {
		return false
	}
	name := obj.Utf8Text(f.module.src)
	switch name {
	case "NextResponse":
		imp, ok := f.module.imports[name]
		if !ok || imp.module != "next/server" {
			return false
		}
	case "Response":
		if moduleBinds(f.module, name) {
			return false
		}
	default:
		return false
	}
	f.recordProducer(n, values[0])
	return true
}
