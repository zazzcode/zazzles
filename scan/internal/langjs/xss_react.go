package langjs

import (
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
)

func (f *flow) clientJSX(n *sitter.Node) (value, bool) {
	if !f.client.react {
		return value{}, false
	}
	if n.Kind() == "jsx_attribute" {
		name, expression := n.ChildByFieldName("name"), n.ChildByFieldName("value")
		if name == nil && n.NamedChildCount() > 1 {
			name, expression = n.NamedChild(0), n.NamedChild(1)
		}
		if name == nil || expression == nil || expression.NamedChildCount() != 1 {
			return value{}, false
		}
		attribute := name.Utf8Text(f.module.src)
		parent := n.Parent()
		if parent == nil {
			return value{}, false
		}
		tag := parent.ChildByFieldName("name")
		if tag == nil || tag.Utf8Text(f.module.src) == "" || strings.ToLower(tag.Utf8Text(f.module.src)[:1]) != tag.Utf8Text(f.module.src)[:1] {
			return value{}, false
		}
		arg := expression.NamedChild(0)
		if attribute == "dangerouslySetInnerHTML" && arg.Kind() == "object" {
			v := f.eval(property(arg, "__html", f.module.src))
			f.clientRecord(n, v, "html_text", false, f.clientClassEvidence(name))
			return v, true
		}
	}
	if n.Kind() == "jsx_expression" && n.NamedChildCount() == 1 && n.Parent() != nil && n.Parent().Kind() == "jsx_element" {
		v := f.eval(n.NamedChild(0))
		f.clientRecord(n, v, "html_text", true, f.clientClassEvidence(n.Parent().ChildByFieldName("open_tag")))
		return v, true
	}
	return value{}, false
}
