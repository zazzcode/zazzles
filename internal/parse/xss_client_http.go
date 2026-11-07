package parse

import (
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
