package langjs

import (
	"regexp"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/parse"
)

var ejsCode = regexp.MustCompile(`<%([=-]?)([\s\S]*?)%>`)

func (f *flow) templateModule(file analysis.Evidence, extension string) *sourceModule {
	if cached := f.set.modules[file.Span.File]; cached != nil {
		return cached
	}
	skeleton := []byte(file.Text)
	for i, ch := range skeleton {
		if ch != '\n' && ch != '\r' {
			skeleton[i] = ' '
		}
	}
	pattern := ejsCode
	if extension == "hbs" || extension == "handlebars" {
		pattern = handlebarsOutput
	} else if extension == "pug" || extension == "jade" {
		pattern = pugOutput
	}
	for _, match := range pattern.FindAllStringSubmatchIndex(file.Text, -1) {
		start, end := match[4], match[5]
		expression := strings.TrimSpace(file.Text[start:end])
		if expression == "else" || strings.HasPrefix(expression, "#") || strings.HasPrefix(expression, "/") {
			continue
		}
		for end > start && (file.Text[end-1] == '-' || file.Text[end-1] == '_') {
			end--
		}
		copy(skeleton[start:end], file.Text[start:end])
		if end < len(skeleton) {
			skeleton[end] = ';'
		}
	}
	tree := f.set.parsers.forPath("template.js").Parse(skeleton, nil)
	if tree == nil || tree.RootNode().HasError() {
		if tree != nil {
			tree.Close()
		}
		return nil
	}
	m := &sourceModule{file: file.Span.File, src: []byte(file.Text), hash: file.SHA256, tree: tree,
		funcs: map[string]*sitter.Node{}, exports: map[string]*sitter.Node{}, imports: map[string]importBinding{}, express: map[string]bool{}, receivers: map[string]bool{}}
	f.set.modules[m.file] = m
	return m
}

func (f *flow) templateLocals(m *sourceModule, locals *sitter.Node) (map[string]value, []analysis.Evidence) {
	env := map[string]value{}
	var bindings []analysis.Evidence
	if locals.Kind() == "object" {
		for i := uint(0); i < locals.NamedChildCount(); i++ {
			pair := locals.NamedChild(i)
			key, expression := pair.ChildByFieldName("key"), pair.ChildByFieldName("value")
			if key != nil && expression != nil {
				env[key.Utf8Text(f.module.src)] = f.eval(expression)
			} else if pair.Kind() == "shorthand_property_identifier" {
				env[pair.Utf8Text(f.module.src)] = f.eval(pair)
			}
		}
	}
	registration := f.registration
	if registration != nil {
		var visit func(*sitter.Node)
		visit = func(n *sitter.Node) {
			if n.Kind() == "assignment_expression" {
				left, right := n.ChildByFieldName("left"), n.ChildByFieldName("right")
				if left != nil && right != nil && left.Kind() == "member_expression" && right.Kind() == "identifier" {
					obj, prop := left.ChildByFieldName("object"), left.ChildByFieldName("property")
					if obj != nil && prop != nil && obj.Kind() == "member_expression" {
						app, locals := obj.ChildByFieldName("object"), obj.ChildByFieldName("property")
						imp, ok := registration.imports[right.Utf8Text(registration.src)]
						if app != nil && locals != nil && registration.receivers[app.Utf8Text(registration.src)] && locals.Utf8Text(registration.src) == "locals" && ok {
							m.imports[prop.Utf8Text(registration.src)] = imp
							bindings = append(bindings, registration.evidence("template_local_binding", n))
						}
					}
				}
			}
			for i := uint(0); i < n.NamedChildCount(); i++ {
				visit(n.NamedChild(i))
			}
		}
		visit(registration.tree.RootNode())
	}
	return env, bindings
}

func (f *flow) templateExpression(m *sourceModule, locals *sitter.Node, expression *sitter.Node, env map[string]value) value {
	child := *f
	child.module, child.request, child.response = m, "", ""
	child.env = copyValues(env)
	child.uses = nil
	// Bind lexical iterator parameters to their verified collection read. The
	// alias comes from the template AST, never from a singularized variable name.
	var ancestors []*sitter.Node
	for p := expression.Parent(); p != nil; p = p.Parent() {
		if isFunction(p) {
			ancestors = append(ancestors, p)
		}
	}
	for i := len(ancestors) - 1; i >= 0; i-- {
		fn := ancestors[i]
		params, ok := functionParameters(fn, m.src)
		parent := fn.Parent()
		if !ok || len(params) == 0 || parent == nil || parent.Parent() == nil {
			continue
		}
		call := parent.Parent()
		callee := call.ChildByFieldName("function")
		if callee == nil || callee.Kind() != "member_expression" {
			continue
		}
		obj, prop := callee.ChildByFieldName("object"), callee.ChildByFieldName("property")
		if obj != nil && prop != nil && (prop.Utf8Text(m.src) == "forEach" || prop.Utf8Text(m.src) == "map") {
			child.env[params[0].name] = child.eval(obj)
		}
	}
	if locals.Kind() != "object" {
		whole := f.eval(locals)
		if len(whole.deps) > 0 {
			// Request-object locals project a field into the expression's binding.
			text := expression.Utf8Text(m.src)
			if parse.SimpleTemplateField.MatchString(text) {
				child.env[strings.Split(text, ".")[0]] = whole
			}
		}
	}
	return child.eval(expression)
}
