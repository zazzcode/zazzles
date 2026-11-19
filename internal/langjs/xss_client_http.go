package langjs

import (
	"fmt"
	"net/url"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
)

func (f *flow) clientHTTPValue(m *sourceModule, call, endpoint *sitter.Node, method string, fields map[string]*sitter.Node) value {
	path := f.set.clientURL(m, endpoint, fields, 0)
	if path == "" {
		path = "<unresolved>"
	}
	if parsed, err := url.Parse(path); err == nil {
		if parsed.Host == "" || parsed.Hostname() == "localhost" || parsed.Hostname() == "127.0.0.1" {
			path = parsed.Path
		}
	}
	evidence := m.evidence("api_response", call)
	v := value{apiPath: strings.Split(path, "?")[0], apiMethod: method, deps: []analysis.Dependency{{Source: evidence, Transfers: []analysis.Evidence{}}}}
	if method == "" {
		v.gaps = append(v.gaps, analysis.Gap{Kind: "response_method_unresolved", Detail: "Browser request method is not established by supported literal options; no producer is guessed.", At: evidence.Span})
	}
	return v
}

func (f *flow) clientServiceCall(call *sitter.Node, object, method string) (value, bool) {
	injection := f.client.injected[strings.TrimPrefix(object, "this.")]
	if !strings.HasPrefix(injection.module, ".") {
		return value{}, false
	}
	m := f.set.importModule(f.module, injection.module)
	if m == nil {
		return value{}, false
	}
	root := m.tree.RootNode()
	for i := uint(0); i < root.NamedChildCount(); i++ {
		n := root.NamedChild(i)
		if n.Kind() == "export_statement" {
			n = n.ChildByFieldName("declaration")
		}
		if n == nil || n.Kind() != "class_declaration" {
			continue
		}
		name := n.ChildByFieldName("name")
		if name == nil || name.Utf8Text(m.src) != injection.name {
			continue
		}
		context := f.set.clientClass(m, n)
		fn := context.methods[method]
		if fn == nil {
			continue
		}
		var result value
		found := false
		walkCalls(fn.ChildByFieldName("body"), func(http *sitter.Node) {
			callee, args := http.ChildByFieldName("function"), http.ChildByFieldName("arguments")
			if callee == nil || callee.Kind() != "member_expression" || args == nil || args.NamedChildCount() == 0 {
				return
			}
			obj, prop := callee.ChildByFieldName("object"), callee.ChildByFieldName("property")
			if obj == nil || prop == nil {
				return
			}
			binding := context.injected[strings.TrimPrefix(obj.Utf8Text(m.src), "this.")]
			verb := strings.ToUpper(prop.Utf8Text(m.src))
			if binding.module != "@angular/common/http" || binding.name != "HttpClient" || (verb != "GET" && verb != "POST" && verb != "PUT" && verb != "DELETE" && verb != "PATCH") {
				return
			}
			response := f.clientHTTPValue(m, http, args.NamedChild(0), verb, context.fields)
			if field := responseProjection(m, fn); field != "" {
				response.responseField = field
				response.deps = fieldDeps(response.deps, field)
			}
			result = combine(result, response)
			f.context = append(f.context, m.evidence("http_client_binding", binding.node), f.module.evidence("http_consumer", call))
			found = true
		})
		return result, found
	}
	return value{}, false
}

// responseProjection reads map((response) => response.field) from a service method.
func responseProjection(m *sourceModule, method *sitter.Node) string {
	field := ""
	walkCalls(method.ChildByFieldName("body"), func(call *sitter.Node) {
		fn, args := call.ChildByFieldName("function"), call.ChildByFieldName("arguments")
		if fn == nil || args == nil || fn.Utf8Text(m.src) != "map" || args.NamedChildCount() != 1 || !isFunction(args.NamedChild(0)) {
			return
		}
		if module := m.imports["map"].module; module != "rxjs" && module != "rxjs/operators" {
			return
		}
		callback := args.NamedChild(0)
		params, ok := functionParameters(callback, m.src)
		body := callback.ChildByFieldName("body")
		if !ok || len(params) != 1 || body == nil || body.Kind() != "member_expression" {
			return
		}
		obj, prop := body.ChildByFieldName("object"), body.ChildByFieldName("property")
		if obj != nil && prop != nil && obj.Utf8Text(m.src) == params[0].name {
			field = prop.Utf8Text(m.src)
		}
	})
	return field
}

func (s *moduleSet) clientURL(m *sourceModule, n *sitter.Node, fields map[string]*sitter.Node, depth int) string {
	if n == nil || depth > 6 {
		return ""
	}
	if literal, ok := stringLiteral(n, m.src); ok {
		return literal
	}
	switch n.Kind() {
	case "identifier":
		if s.nextProjectFor(m.file) != nil && !bindingReassigned(m, n.Utf8Text(m.src)) {
			if init := localInitializer(m, n, n.Utf8Text(m.src)); init != nil && init != n {
				return s.clientURL(m, init, fields, depth+1)
			}
		}
	case "ternary_expression":
		if s.nextProjectFor(m.file) != nil {
			a := s.clientURL(m, n.ChildByFieldName("consequence"), fields, depth+1)
			b := s.clientURL(m, n.ChildByFieldName("alternative"), fields, depth+1)
			if a != "" && b != "" && strings.Split(a, "?")[0] == strings.Split(b, "?")[0] {
				return strings.Split(a, "?")[0]
			}
		}
	case "member_expression":
		obj, prop := n.ChildByFieldName("object"), n.ChildByFieldName("property")
		if obj == nil || prop == nil {
			return ""
		}
		if obj.Kind() == "this" {
			return s.clientURL(m, fields[prop.Utf8Text(m.src)], fields, depth+1)
		}
		if imp, ok := m.imports[obj.Utf8Text(m.src)]; ok {
			if target := s.importModule(m, imp.module); target != nil {
				if value := topVariable(target, imp.name); value != nil {
					return s.clientURL(target, property(value, prop.Utf8Text(m.src), target.src), nil, depth+1)
				}
			}
		}
	case "binary_expression":
		left := s.clientURL(m, n.ChildByFieldName("left"), fields, depth+1)
		right := s.clientURL(m, n.ChildByFieldName("right"), fields, depth+1)
		if left != "" && right == "" {
			right = ":value"
		}
		return left + right
	case "template_string":
		var out strings.Builder
		for i := uint(0); i < n.NamedChildCount(); i++ {
			child := n.NamedChild(i)
			if child.Kind() == "string_fragment" {
				out.WriteString(child.Utf8Text(m.src))
			} else if child.Kind() == "template_substitution" && child.NamedChildCount() == 1 {
				part := s.clientURL(m, child.NamedChild(0), fields, depth+1)
				if part == "" {
					part = ":value"
				}
				out.WriteString(part)
			}
		}
		return out.String()
	}
	return ""
}

// ownAPICall is a server-side helper call whose result is the JSON body of a
// GET fetch to a path of this repository. Its value is resolved after every
// route has run (linkOwnAPIOrigins); fallback is the flow the call had before.
type ownAPICall struct {
	path     string
	fallback value
	precise  bool // fallback is the helper's own modeled result
}

func ownAPIKey(e analysis.Evidence) string {
	return fmt.Sprintf("%s:%d:%d", e.Span.File, e.Span.StartByte, e.Span.EndByte)
}

// ownAPIPending reports an own-API response dependency that linkOwnAPIOrigins
// has yet to resolve. A path operand admits it so the resolved origin, not a
// guess at flow time, decides the claim.
func (s *moduleSet) ownAPIPending(d analysis.Dependency) bool {
	if s == nil || d.Source.Kind != "api_response" {
		return false
	}
	_, ok := s.ownAPI[ownAPIKey(d.Source)]
	return ok
}

// ownAPIValue reports a value whose response dependency is an own-API call.
func (s *moduleSet) ownAPIValue(v value) bool {
	for _, d := range v.deps {
		if _, ok := s.ownAPI[ownAPIKey(d.Source)]; ok && d.Source.Kind == "api_response" {
			return true
		}
	}
	return false
}

// ownAPIHelperCall recognises, on the server, a call to an in-repository helper
// whose only fetch is a GET of a same-origin path and whose non-null returns are
// that response's json(). The call yields the response body; the arguments
// that built the URL are recorded as selector context, not as the value. The
// helper body has already run, so records inside it are kept; ret is its
// result, which stays the fallback when no route resolves the field.
func (f *flow) ownAPIHelperCall(n *sitter.Node, values []value, ret value, precise bool) (value, bool) {
	if f.client != nil || f.set == nil {
		return value{}, false
	}
	hm, helper := f.set.resolveCall(f.module, n)
	if helper == nil {
		return value{}, false
	}
	body := helper.ChildByFieldName("body")
	if body == nil || body.Kind() != "statement_block" {
		return value{}, false
	}
	var fetches []*sitter.Node
	walkCalls(body, func(c *sitter.Node) {
		if fn := c.ChildByFieldName("function"); fn != nil && fn.Kind() == "identifier" && fn.Utf8Text(hm.src) == "fetch" && !shadowed(c, "fetch", hm.src) {
			fetches = append(fetches, c)
		}
	})
	if len(fetches) != 1 {
		return value{}, false
	}
	call := fetches[0]
	args := call.ChildByFieldName("arguments")
	if args == nil || args.NamedChildCount() == 0 || fetchMethod(hm, args) != "GET" {
		return value{}, false
	}
	binding := call.Parent()
	if binding != nil && binding.Kind() == "await_expression" {
		binding = binding.Parent()
	}
	if binding == nil || binding.Kind() != "variable_declarator" {
		return value{}, false
	}
	name := binding.ChildByFieldName("name")
	if name == nil || name.Kind() != "identifier" || bindingReassigned(hm, name.Utf8Text(hm.src)) || !jsonReturns(hm, body, name.Utf8Text(hm.src)) {
		return value{}, false
	}
	path := f.set.clientURL(hm, args.NamedChild(0), nil, 0)
	// A leading substitution followed by a slash is the origin (a base URL).
	path = strings.TrimPrefix(path, ":value")
	if parsed, err := url.Parse(path); err == nil && (parsed.Hostname() == "localhost" || parsed.Hostname() == "127.0.0.1") {
		path = parsed.Path
	}
	path = strings.Split(path, "?")[0]
	if !strings.HasPrefix(path, "/") || strings.Contains(path, "<") {
		return value{}, false
	}
	fallback := ret
	if !precise {
		fallback = value{}
		for _, a := range values {
			fallback = combine(fallback, a)
		}
	}
	response := f.module.evidence("api_response", n)
	if f.set.ownAPI == nil {
		f.set.ownAPI = map[string]ownAPICall{}
	}
	f.set.ownAPI[ownAPIKey(response)] = ownAPICall{path: path, fallback: fallback, precise: precise}
	f.context = append(f.context, hm.evidence("helper_definition", helper), hm.evidence("http_consumer", call))
	for _, d := range fallback.deps {
		selector := d.Source
		selector.Kind = "api_selector"
		f.context = append(f.context, selector)
	}
	return value{apiPath: path, apiMethod: "GET", deps: []analysis.Dependency{{Source: response, Transfers: []analysis.Evidence{}}}}, true
}

// fetchMethod is the literal method option of a fetch call, GET by default; ""
// when the option is not a literal.
func fetchMethod(m *sourceModule, args *sitter.Node) string {
	if args.NamedChildCount() < 2 {
		return "GET"
	}
	options := args.NamedChild(1)
	if options.Kind() != "object" {
		return ""
	}
	for i := uint(0); i < options.NamedChildCount(); i++ {
		pair := options.NamedChild(i)
		if pair.Kind() != "pair" {
			if pair.Kind() == "spread_element" {
				return ""
			}
			continue
		}
		key := pair.ChildByFieldName("key")
		if key == nil || strings.Trim(key.Utf8Text(m.src), `"'`) != "method" {
			continue
		}
		method, ok := stringLiteral(pair.ChildByFieldName("value"), m.src)
		if !ok {
			return ""
		}
		return strings.ToUpper(method)
	}
	return "GET"
}

// jsonReturns reports that every return of body (outside nested functions)
// returns null, nothing, or response.json() of the named binding, and that at
// least one returns the JSON body.
func jsonReturns(m *sourceModule, body *sitter.Node, response string) bool {
	found, other := false, false
	var walk func(*sitter.Node)
	walk = func(n *sitter.Node) {
		if n == nil || n != body && isFunction(n) {
			return
		}
		if n.Kind() == "return_statement" {
			if n.NamedChildCount() == 0 {
				return
			}
			e := unwrapTS(n.NamedChild(0))
			if e.Kind() == "await_expression" && e.NamedChildCount() == 1 {
				e = unwrapTS(e.NamedChild(0))
			}
			if e.Kind() == "null" || e.Kind() == "undefined" {
				return
			}
			fn, args := e.ChildByFieldName("function"), e.ChildByFieldName("arguments")
			if e.Kind() == "call_expression" && fn != nil && fn.Kind() == "member_expression" && args != nil && args.NamedChildCount() == 0 {
				obj, prop := fn.ChildByFieldName("object"), fn.ChildByFieldName("property")
				if obj != nil && prop != nil && obj.Utf8Text(m.src) == response && prop.Utf8Text(m.src) == "json" {
					found = true
					return
				}
			}
			other = true
			return
		}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			walk(n.NamedChild(i))
		}
	}
	walk(body)
	return found && !other
}
