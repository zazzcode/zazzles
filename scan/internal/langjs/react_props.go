package langjs

import (
	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"strings"
)

// componentProps follows one imported component hop. The child's invocation
// receives only the explicit JSX props; its locals never leak into the parent.
func (f *flow) componentProps(n *sitter.Node) (value, bool) {
	if f.set == nil || f.jsxDepth >= 1 || (f.web == nil && f.client == nil) || (n.Kind() != "jsx_opening_element" && n.Kind() != "jsx_self_closing_element") {
		return value{}, false
	}
	name := n.ChildByFieldName("name")
	if name == nil {
		return value{}, false
	}
	tag := name.Utf8Text(f.module.src)
	if tag == "" || strings.ToUpper(tag[:1]) != tag[:1] {
		return value{}, false
	}
	imp, ok := f.module.imports[tag]
	if !ok || !strings.HasPrefix(imp.module, ".") && len(f.set.aliasBases(f.module.file, imp.module)) == 0 {
		return value{}, false
	}
	target := f.set.importModule(f.module, imp.module)
	if target == nil || target == f.module {
		return value{}, false
	}
	var component *sitter.Node
	for _, e := range f.set.nextExports(target, 0) {
		if e.name == imp.name {
			component = e.value
			break
		}
	}
	if component == nil {
		return value{}, false
	}
	res := f.set.nextHandler(target, component, 0)
	if res.fn == nil {
		return value{}, false
	}
	props := value{fields: map[string]value{}}
	for i := uint(0); i < n.NamedChildCount(); i++ {
		attr := n.NamedChild(i)
		if attr.Kind() != "jsx_attribute" {
			continue
		}
		if attr.NamedChildCount() < 2 {
			continue
		}
		key, arg := attr.NamedChild(0), attr.NamedChild(1)
		if arg.Kind() == "jsx_expression" && arg.NamedChildCount() == 1 {
			arg = arg.NamedChild(0)
		}
		props.fields[key.Utf8Text(f.module.src)] = f.transfer(f.eval(arg), "component_prop", attr)
	}
	child := *f
	child.jsxDepth++
	child.module = res.module
	child.env = map[string]value{}
	child.uses = nil
	child.returns = nil
	child.context = append(append([]analysis.Evidence{}, f.context...), res.module.evidence("handler", res.fn.ChildByFieldName("body")))
	if moduleDirective(res.module) == "use client" {
		f.noteNextBoundary("client_props", n, props)
		child.client = &clientContext{entry: browserEntry(res.module, res.module.evidence("browser_source_slice", res.fn), res.module.file, "component"), react: true, state: map[string]value{}, setters: map[string]string{}, events: f.set.browserEventsFor(f.report, res.module)}
	}
	bindComponentProps(&child, res.fn, props)
	child.statements(res.fn.ChildByFieldName("body"))
	if child.client != nil && f.report != nil {
		addClientUses(f.report, child.client, child.uses)
	} else {
		f.uses = append(f.uses, child.uses...)
	}
	return props, true
}

func bindComponentProps(f *flow, fn *sitter.Node, props value) {
	params := nextParams(fn, f.module.src)
	if len(params) == 0 {
		return
	}
	if params[0].name != "" {
		f.env[params[0].name] = props
		return
	}
	for key, local := range params[0].fields {
		f.env[local] = props.fields[key]
	}
}

// pageEffect follows browser callbacks over the props of a Pages render. It
// records browser execution on code facts while retaining the source invocation
// that established those props.
func (f *flow) pageEffect(call, fn, args *sitter.Node) bool {
	if f.web == nil || f.web.surface != "page" || f.client != nil || args == nil || args.NamedChildCount() == 0 || !isFunction(args.NamedChild(0)) {
		return false
	}
	hook := reactHook(f.module, fn, "useEffect", "useLayoutEffect", "useCallback")
	if hook == "" {
		return false
	}
	child := *f
	child.uses = nil
	child.returns = nil
	child.env = copyValues(f.env)
	child.client = &clientContext{events: f.set.browserEventsFor(f.report, f.module), entry: browserEntry(f.module, f.module.evidence("browser_source_slice", call), f.module.file, "component"), react: true, state: map[string]value{}, setters: map[string]string{}}
	child.context = append(append([]analysis.Evidence{}, f.context...), f.module.evidence("handler", args.NamedChild(0).ChildByFieldName("body")))
	child.statements(args.NamedChild(0).ChildByFieldName("body"))
	if child.client != nil && f.report != nil {
		addClientUses(f.report, child.client, child.uses)
	} else {
		f.uses = append(f.uses, child.uses...)
	}
	return true
}
