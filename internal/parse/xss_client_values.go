package parse

import (
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
)

func browserGlobal(m *sourceModule, node *sitter.Node, name string) bool {
	for scope := node.Parent(); scope != nil; scope = scope.Parent() {
		if param := scope.ChildByFieldName("parameter"); param != nil && param.Kind() == "identifier" && param.Utf8Text(m.src) == name {
			return false
		}
	}
	return !moduleBinds(m, name) && !shadowed(node, name, m.src)
}

func (f *flow) browserSource(node *sitter.Node) value {
	return value{deps: []analysis.Dependency{{Source: f.module.evidence("browser_source", node), Transfers: []analysis.Evidence{}}}}
}

func (f *flow) clientValue(n *sitter.Node) (value, bool) {
	if n.Kind() != "member_expression" && n.Kind() != "subscript_expression" && n.Kind() != "identifier" {
		return value{}, false
	}
	text := n.Utf8Text(f.module.src)
	if v, ok := f.env[clientKey(text)]; ok {
		if f.client.entry.Browser.Category == "event" && len(v.deps) > 0 && v.deps[0].Source.Kind == "event_input_binding" {
			v.deps = []analysis.Dependency{{Source: f.module.evidence("browser_event_source", n), Transfers: []analysis.Evidence{v.deps[0].Source}}}
		}
		return v, true
	}
	root := strings.Split(strings.Split(text, ".")[0], "[")[0]
	if (root == "location" || root == "window" || root == "document") && browserGlobal(f.module, n, root) {
		if root == "location" || (text == "window.location" || strings.HasPrefix(text, "window.location.") || strings.HasPrefix(text, "window.location[")) || text == "window.name" || text == "document.URL" || text == "document.documentURI" || text == "document.referrer" {
			return f.browserSource(n), true
		}
		if root == "document" && (text == "document.body" || text == "document.documentElement") {
			return value{domNode: true}, true
		}
	}
	if strings.HasPrefix(text, "this.") {
		parts := strings.Split(text, ".")
		if len(parts) >= 3 {
			injection := f.client.injected[parts[1]]
			if injection.module == "@angular/router" && injection.name == "ActivatedRoute" && (strings.Contains(text, ".queryParams") || strings.Contains(text, ".queryParamMap") || strings.Contains(text, ".params") || strings.Contains(text, ".paramMap")) {
				return f.browserSource(n), true
			}
		}
	}
	if n.Kind() == "member_expression" {
		obj, prop := n.ChildByFieldName("object"), n.ChildByFieldName("property")
		if obj != nil && prop != nil && prop.Utf8Text(f.module.src) == "value" {
			if v, ok := f.env[clientKey(obj.Utf8Text(f.module.src))]; ok && v.domNode {
				return f.browserSource(n), true
			}
		}
	}
	return value{}, false
}

func (f *flow) clientConstructor(n *sitter.Node) (value, bool) {
	ctor, args := n.ChildByFieldName("constructor"), n.ChildByFieldName("arguments")
	if ctor == nil || args == nil {
		return value{}, false
	}
	name := ctor.Utf8Text(f.module.src)
	if !browserGlobal(f.module, n, name) {
		return value{}, false
	}
	if name == "URLSearchParams" && args.NamedChildCount() == 1 {
		v := f.eval(args.NamedChild(0))
		v.urlParams = true
		return v, true
	}
	if name == "Range" {
		return value{domNode: true}, true
	}
	if name == "Function" && args.NamedChildCount() > 0 {
		f.clientRecord(n, f.eval(args.NamedChild(args.NamedChildCount()-1)), "script", false, f.clientClassEvidence(ctor))
		return value{}, true
	}
	return value{}, false
}

func (f *flow) clientAssignment(n, left *sitter.Node, v value) bool {
	if left == nil || left.Kind() != "member_expression" {
		return false
	}
	obj, prop := left.ChildByFieldName("object"), left.ChildByFieldName("property")
	if obj == nil || prop == nil {
		return false
	}
	text, method := obj.Utf8Text(f.module.src), prop.Utf8Text(f.module.src)
	bound := f.eval(obj)
	isLocation := (text == "location" || text == "window.location") && browserGlobal(f.module, n, strings.Split(text, ".")[0])
	if bound.domNode || isLocation {
		context, escaped := "", false
		switch method {
		case "innerHTML", "outerHTML":
			context = "html_text"
		case "textContent", "innerText":
			context, escaped = "html_text", true
		case "href", "src":
			context = "url"
		}
		if context != "" {
			f.clientRecord(n, v, context, escaped, f.clientClassEvidence(obj))
		}
	}
	f.noteTrustedField(method, v)
	// Exact source properties are tracked for component/template linkage. Array
	// indexes are normalized only within the same named collection; aliasing stays bounded.
	f.env[clientKey(left.Utf8Text(f.module.src))] = v
	return true
}
