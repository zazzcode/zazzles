package parse

import (
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
)

func (f *flow) clientCall(n, fn, args *sitter.Node) (value, bool) {
	if args == nil {
		return value{}, false
	}
	if fn.Kind() == "identifier" {
		name := fn.Utf8Text(f.module.src)
		if binding, ok := f.module.browserGlobals[name]; ok && browserGlobal(f.module, n, name) && !bindingReassigned(f.module, name) {
			f.context = append(f.context, binding)
			return value{domNode: true, jqueryNode: true}, true
		}

		if imp, ok := f.module.imports[name]; ok && imp.module == "jquery" && !shadowed(n, name, f.module.src) {
			f.context = append(f.context, f.module.evidence("render_binding", imp.declaration))
			return value{domNode: true, jqueryNode: true}, true
		}
		if (name == "setTimeout" || name == "setInterval" || name == "eval") && browserGlobal(f.module, n, name) && args.NamedChildCount() > 0 && !isFunction(args.NamedChild(0)) {
			v := f.eval(args.NamedChild(0))
			f.clientRecord(n, v, "script", false, f.clientClassEvidence(fn))
			return value{}, true
		}
		if v, ok := f.tokenClaimCall(n, fn); ok {
			return v, true
		}
		if name == "fetch" && browserGlobal(f.module, n, name) {
			return f.clientHTTPValue(f.module, n, args.NamedChild(0), f.browserFetchMethod(args), nil), true
		}
		return value{}, false
	}
	if fn.Kind() != "member_expression" {
		return value{}, false
	}
	obj, prop := fn.ChildByFieldName("object"), fn.ChildByFieldName("property")
	if obj == nil || prop == nil {
		return value{}, false
	}
	object, method := obj.Utf8Text(f.module.src), prop.Utf8Text(f.module.src)
	if object == "this" {
		if v, ok := f.clientMethod(n, method, args); ok {
			return v, true
		}
	}
	if object == "document" && browserGlobal(f.module, n, "document") {
		switch method {
		case "getElementById", "querySelector", "createElement", "createRange":
			f.context = append(f.context, f.module.evidence("render_binding", n))
			return value{domNode: true}, true
		case "write", "writeln":
			if args.NamedChildCount() > 0 {
				f.clientRecord(n, f.eval(args.NamedChild(0)), "html_text", false, f.clientClassEvidence(fn))
			}
			return value{}, true
		}
	}
	if strings.HasPrefix(object, "this.") {
		field := strings.TrimPrefix(object, "this.")
		injection := f.client.injected[field]
		if injection.module == "@angular/platform-browser" && injection.name == "DomSanitizer" && args.NamedChildCount() == 1 {
			context := ""
			switch method {
			case "bypassSecurityTrustHtml":
				context = "html_text"
			case "bypassSecurityTrustScript":
				context = "script"
			case "bypassSecurityTrustUrl", "bypassSecurityTrustResourceUrl":
				context = "url"
			case "bypassSecurityTrustStyle":
				context = "style"
			}
			if context != "" {
				v := f.eval(args.NamedChild(0))
				if len(v.deps) == 0 {
					v.deps = []analysis.Dependency{{Source: f.module.evidence("unresolved_source", args.NamedChild(0))}}
				}
				v = f.transfer(v, "trust_bypass", n)
				v.trustedContext = context
				before := len(f.uses)
				f.clientRecord(n, v, "unknown", false, f.clientClassEvidence(injection.node))
				if len(f.uses) > before {
					f.uses[len(f.uses)-1].Sink.Kind = "trust_bypass"
				}
				return v, true
			}
		}
		if v, ok := f.clientServiceCall(n, object, method); ok {
			return v, true
		}
		if object == "this" {
			if v, ok := f.clientMethod(n, method, args); ok {
				return v, true
			}
		}
	}

	if method == "find" || method == "closest" || method == "val" || method == "ready" || method == "each" || method == "submit" || method == "click" {
		receiver := f.eval(obj)
		if receiver.jqueryNode {
			switch method {
			case "find", "closest":
				return value{domNode: true, jqueryNode: true}, true
			case "val":
				if args.NamedChildCount() == 0 {
					return f.browserSource(n), true
				}
				return value{}, true
			default:
				if args.NamedChildCount() > 0 && isFunction(args.NamedChild(0)) {
					f.clientCallback(args.NamedChild(0), value{})
					return value{}, true
				}
			}
		}
	}
	if method == "subscribe" || method == "then" || method == "pipe" || method == "get" || method == "trim" || method == "json" || method == "addEventListener" || method == "insertAdjacentHTML" || method == "createContextualFragment" || method == "html" || method == "append" {
		receiver := f.eval(obj)
		switch method {
		case "get":
			if receiver.urlParams {
				return f.transfer(receiver, "browser_parameter", n), true
			}
		case "trim":
			if len(receiver.deps) > 0 && args.NamedChildCount() == 0 {
				return f.transfer(receiver, "string_operation", n), true
			}
		case "json", "pipe":
			if receiver.apiPath != "" {
				return receiver, true
			}
		case "subscribe", "then":
			if args.NamedChildCount() > 0 {
				callback := args.NamedChild(0)
				if callback.Kind() == "object" {
					callback = property(callback, "next", f.module.src)
				}
				if isFunction(callback) {
					if len(receiver.deps) == 0 {
						receiver.deps = []analysis.Dependency{{Source: f.module.evidence("unresolved_source", n)}}
					}
					f.clientCallback(callback, receiver)
					return receiver, true
				}
			}
		case "addEventListener":
			f.browserEvent(n, obj, args, receiver)
			return value{}, true
		case "insertAdjacentHTML", "createContextualFragment", "html", "append":
			if receiver.domNode && ((method != "append" && method != "html") || receiver.jqueryNode) {
				index := uint(0)
				if method == "insertAdjacentHTML" {
					index = 1
				}
				if args.NamedChildCount() > index {
					f.clientRecord(n, f.eval(args.NamedChild(index)), "html_text", false, f.clientClassEvidence(obj))
				}
				return value{}, true
			}
		}
	}
	return value{}, false
}

func (f *flow) clientCallback(callback *sitter.Node, v value) {
	if !isFunction(callback) || f.depth >= 4 {
		return
	}
	child := *f
	child.env, child.uses = copyValues(f.env), nil
	child.depth++
	if params, ok := functionParameters(callback, f.module.src); ok && len(params) > 0 {
		child.env[params[0].name] = v
	}
	child.statements(callback.ChildByFieldName("body"))
	f.uses = append(f.uses, child.uses...)
	for key, v := range child.env {
		if strings.HasPrefix(key, "this.") {
			f.env[key] = v
		}
	}
}

func (f *flow) clientMethod(call *sitter.Node, method string, args *sitter.Node) (value, bool) {
	fn := f.client.methods[method]
	if fn == nil || f.depth >= 3 {
		return value{}, false
	}
	params, ok := functionParameters(fn, f.module.src)
	if !ok {
		return value{}, false
	}
	child := *f
	child.env, child.uses, child.returns = copyValues(f.env), nil, nil
	child.depth++
	for i, parameter := range params {
		child.env[parameter.name] = value{}
		if args.NamedChildCount() > uint(i) {
			child.env[parameter.name] = f.eval(args.NamedChild(uint(i)))
		}
	}
	child.statements(fn.ChildByFieldName("body"))
	f.uses = append(f.uses, child.uses...)
	var out value
	for _, v := range child.returns {
		out = combine(out, v)
	}
	for name, v := range child.env {
		if strings.HasPrefix(name, "this.") {
			f.env[name] = v
		}
	}
	return out, true
}

// browserFetchMethod accepts only a direct literal options object. Object spreads,
// computed keys, duplicate properties and aliases can override method and remain
// unresolved. No JavaScript is evaluated to guess a request's producer.
func (f *flow) browserFetchMethod(args *sitter.Node) string {
	if args.NamedChildCount() == 0 || f.set.clientURL(f.module, args.NamedChild(0), nil, 0) == "" {
		return ""
	}
	if args.NamedChildCount() == 1 {
		return "GET"
	}
	if args.NamedChildCount() != 2 {
		return ""
	}
	options := args.NamedChild(1)
	if options.Utf8Text(f.module.src) == "undefined" && (options.Kind() == "undefined" || options.Kind() == "identifier") && browserGlobal(f.module, options, "undefined") {
		return "GET"
	}
	if options.Kind() != "object" {
		return ""
	}
	method := "GET"
	seen := map[string]bool{}
	for i := uint(0); i < options.NamedChildCount(); i++ {
		pair := options.NamedChild(i)
		if pair.Kind() != "pair" {
			return ""
		}
		key := pair.ChildByFieldName("key")
		if key == nil {
			return ""
		}
		name := ""
		if key.Kind() == "property_identifier" {
			name = key.Utf8Text(f.module.src)
		} else if key.Kind() == "string" {
			name, _ = stringLiteral(key, f.module.src)
		} else {
			return ""
		}
		if name == "" || seen[name] {
			return ""
		}
		seen[name] = true
		if name == "method" {
			literal, ok := stringLiteral(pair.ChildByFieldName("value"), f.module.src)
			if !ok || literal == "" {
				return ""
			}
			// An HTTP token is literal provenance, not an allow-list of methods. Unknown
			// literal verbs cannot match an unrelated GET route.
			for _, c := range literal {
				if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", c)) {
					return ""
				}
			}
			method = strings.ToUpper(literal)
		}
	}
	return method
}
