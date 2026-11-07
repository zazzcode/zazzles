package parse

import (
	"path/filepath"
	"regexp"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
)

// returnsHTML reports a view whose returned string is an HTML response body.
func (f *pythonFlow) returnsHTML() bool {
	switch f.route.route.Framework {
	case "quart", "bottle":
		return true
	}
	return f.route.html
}

var wsgiHTMLHeader = regexp.MustCompile(`(?i)\(\s*["']content-type["']\s*,\s*["']text/html`)

// wsgiHTML reports a WSGI callable that sends a literal HTML content type.
func (f *pythonFlow) wsgiHTML() bool {
	return wsgiHTMLHeader.MatchString(pyText(f.route.module, f.route.fn))
}

// wsgiDispatchBranch reports that a call sits under `if selected is module.function`
// naming the callable this path-selected route dispatches to. Without that test the
// append would be attributed to every route of the registry.
func (f *pythonFlow) wsgiDispatchBranch(n *sitter.Node) bool {
	bound := f.route.dispatch
	if bound == nil || bound.fn == nil {
		return false
	}
	name := pyText(bound.module, bound.fn.ChildByFieldName("name"))
	for p := n.Parent(); p != nil; p = p.Parent() {
		if p.Kind() != "if_statement" {
			continue
		}
		c := pyField(p, "condition")
		if c == nil || c.Kind() != "comparison_operator" || c.NamedChildCount() != 2 || !strings.Contains(pyText(f.module, c), " is ") {
			continue
		}
		target := c.NamedChild(1)
		if target.Kind() != "attribute" || pyText(f.module, pyField(target, "attribute")) != name {
			continue
		}
		module := pyText(f.module, pyField(target, "object"))
		if strings.TrimSuffix(filepath.Base(bound.module.file), ".py") == module {
			return true
		}
	}
	return false
}

// falconBody records `resp.text = value`. Falcon's default media type is JSON, so
// the enclosing function must also set a literal HTML content type on that response.
func (f *pythonFlow) falconBody(n *sitter.Node) {
	left := pyField(n, "left")
	if left == nil || left.Kind() != "attribute" || pyText(f.module, pyField(left, "attribute")) != "text" {
		return
	}
	object := pyField(left, "object")
	if object == nil || object.Kind() != "identifier" || f.env[pyText(f.module, object)].binding != "falcon_response" {
		return
	}
	scope := n
	for scope != nil && scope.Kind() != "function_definition" {
		scope = scope.Parent()
	}
	if scope == nil {
		return
	}
	html := false
	pyWalk(scope, func(c *sitter.Node) {
		if c.Kind() != "assignment" || pyText(f.module, pyField(c, "left")) != pyText(f.module, object)+".content_type" {
			return
		}
		literal, ok := pyLiteral(f.module, pyField(c, "right"))
		html = html || (ok && strings.HasPrefix(literal, "text/html"))
	})
	if html {
		f.recordXSS(f.module.evidence("html_response", n), f.eval(pyField(n, "right")), "html_text", nil)
	}
}

// jinjaFileTemplate resolves env.get_template("name") for a module-level
// jinja2.Environment with a statically located FileSystemLoader.
func (f *pythonFlow) jinjaFileTemplate(object, name *sitter.Node) (pythonValue, bool) {
	literal, ok := pyLiteral(f.module, name)
	if !ok || object == nil || object.Kind() != "identifier" {
		return pythonValue{}, false
	}
	var environment *sitter.Node
	pyWalk(f.module.tree.RootNode(), func(c *sitter.Node) {
		if c.Kind() == "assignment" && pyText(f.module, pyField(c, "left")) == pyText(f.module, object) {
			if right := pyField(c, "right"); right != nil && right.Kind() == "call" && f.qualified(pyText(f.module, pyField(right, "function"))) == "jinja2.Environment" {
				environment = right
			}
		}
	})
	if environment == nil {
		return pythonValue{}, false
	}
	escape := "raw" // jinja2.Environment does not autoescape unless asked.
	if option := pyKeywordIn(f.module, environment, "autoescape"); option != nil {
		switch pyText(f.module, option) {
		case "True":
			escape = "encoded"
		case "False":
		default:
			escape = "unknown"
		}
	}
	loader := pyKeywordIn(f.module, environment, "loader")
	if loader != nil && loader.Kind() == "identifier" {
		name := pyText(f.module, loader)
		pyWalk(f.module.tree.RootNode(), func(c *sitter.Node) {
			if c.Kind() == "assignment" && pyText(f.module, pyField(c, "left")) == name {
				loader = pyField(c, "right")
			}
		})
	}
	if loader == nil || loader.Kind() != "call" || f.qualified(pyText(f.module, pyField(loader, "function"))) != "jinja2.FileSystemLoader" || len(pyArgs(loader)) != 1 {
		return pythonValue{}, false
	}
	folder, ok := f.moduleRelativePath(pyArgs(loader)[0])
	if !ok {
		return pythonValue{}, false
	}
	return pythonValue{binding: "jinja_file", literal: filepath.ToSlash(filepath.Join(folder, literal)), templateEscape: escape}, true
}

// moduleRelativePath evaluates Path(__file__).parent / "a" / "b".
func (f *pythonFlow) moduleRelativePath(n *sitter.Node) (string, bool) {
	if n == nil {
		return "", false
	}
	if n.Kind() == "binary_operator" && pyText(f.module, pyField(n, "operator")) == "/" {
		base, ok := f.moduleRelativePath(pyField(n, "left"))
		part, literal := pyLiteral(f.module, pyField(n, "right"))
		return filepath.Join(base, part), ok && literal
	}
	if pyText(f.module, n) == "Path(__file__).parent" && f.qualified("Path") == "pathlib.Path" {
		return filepath.Dir(f.module.file), true
	}
	return "", false
}

func (f *pythonFlow) renderJinjaFile(n *sitter.Node, template pythonValue) {
	file, ok := f.set.text.readText(template.literal)
	if !ok {
		v := f.evalChildren(pyField(n, "arguments"))
		v.gaps = append(v.gaps, f.gap("template_parse_unresolved", "template could not be read inside target", n))
		f.recordXSS(f.module.evidence("template_render", n), pyProtect(v, "unknown"), "unknown", nil)
		return
	}
	locals := f.templateLocals(n)
	if template.templateEscape == "unknown" {
		for key, v := range locals {
			locals[key] = pyProtect(v, "unknown")
		}
	}
	f.templateOutputs(n, file, locals, template.templateEscape == "encoded")
}
