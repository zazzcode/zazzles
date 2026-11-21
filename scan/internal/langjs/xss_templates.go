package langjs

import (
	"path/filepath"
	"regexp"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/parse"
)

var ejsOutput = regexp.MustCompile(`<%([=-])\s*([\s\S]*?)\s*[-_]?%>`)
var handlebarsOutput = regexp.MustCompile(`\{\{(\{?)([^{}]+)\}\}\}?`)
var pugOutput = regexp.MustCompile(`([!#])\{([^}]+)\}`)

func (s *moduleSet) readText(file string) (analysis.Evidence, bool) {
	return s.texts().Read(file)
}

func (s *moduleSet) readBounded(file string, limit int64) (analysis.Evidence, bool) {
	return s.texts().ReadBounded(file, limit)
}

// texts returns the set's text sources, created on first use.
func (s *moduleSet) texts() *parse.TextSources {
	if s.text == nil {
		s.text = parse.NewTextSources(s.root)
	}
	return s.text
}

func (f *flow) renderSettings() (string, string, []analysis.Evidence) {
	engine, views := "", "views"
	var evidence []analysis.Evidence
	m := f.registration
	if m == nil {
		return "", "", nil
	}
	walkCalls(m.tree.RootNode(), func(call *sitter.Node) {
		fn, args := call.ChildByFieldName("function"), call.ChildByFieldName("arguments")
		if fn == nil || fn.Kind() != "member_expression" || args == nil || args.NamedChildCount() < 2 {
			return
		}
		obj, prop := fn.ChildByFieldName("object"), fn.ChildByFieldName("property")
		if obj == nil || prop == nil || !m.receivers[obj.Utf8Text(m.src)] || prop.Utf8Text(m.src) != "set" {
			return
		}
		key, _ := stringLiteral(args.NamedChild(0), m.src)
		switch key {
		case "view engine":
			engine, _ = stringLiteral(args.NamedChild(1), m.src)
			evidence = append(evidence, m.evidence("template_configuration", call))
		case "views":
			if path, ok := stringLiteral(args.NamedChild(1), m.src); ok {
				views = path
			} else if path, ok := staticPath(m, args.NamedChild(1)); ok {
				views = path
			} else {
				views = ""
			}
			evidence = append(evidence, m.evidence("template_configuration", call))
		}
	})
	return engine, views, evidence
}

func staticPath(m *sourceModule, n *sitter.Node) (string, bool) {
	if n == nil || n.Kind() != "call_expression" {
		return "", false
	}
	fn, args := n.ChildByFieldName("function"), n.ChildByFieldName("arguments")
	if fn == nil || fn.Kind() != "member_expression" || args == nil {
		return "", false
	}
	obj, prop := fn.ChildByFieldName("object"), fn.ChildByFieldName("property")
	if obj == nil || prop == nil || prop.Utf8Text(m.src) != "join" {
		return "", false
	}
	imp, ok := m.imports[obj.Utf8Text(m.src)]
	if !ok || (imp.module != "path" && imp.module != "node:path") || shadowed(n, obj.Utf8Text(m.src), m.src) {
		return "", false
	}
	parts := []string{}
	for i := uint(0); i < args.NamedChildCount(); i++ {
		arg := args.NamedChild(i)
		if arg.Utf8Text(m.src) == "__dirname" && !topLevelBinding(m, "__dirname") {
			parts = append(parts, filepath.Dir(m.file))
		} else if part, ok := stringLiteral(arg, m.src); ok {
			parts = append(parts, part)
		} else {
			return "", false
		}
	}
	return filepath.ToSlash(filepath.Join(parts...)), len(parts) > 0
}

func (f *flow) renderTemplate(call, args *sitter.Node) {
	if args == nil || args.NamedChildCount() < 2 {
		return
	}
	name, ok := stringLiteral(args.NamedChild(0), f.module.src)
	engine, views, config := f.renderSettings()
	if !ok || views == "" {
		f.recordXSS(f.module.evidence("template_render", call), f.eval(args.NamedChild(1)), "unknown", "text/html", false, config)
		return
	}
	ext := strings.TrimPrefix(filepath.Ext(name), ".")
	if ext == "" {
		ext = engine
		name += "." + ext
	}
	file, found := f.set.readText(filepath.ToSlash(filepath.Join(views, name)))
	if !found {
		f.recordXSS(f.module.evidence("template_render", call), f.eval(args.NamedChild(1)), "unknown", "text/html", false, config)
		return
	}
	if !f.verifiedTemplateEngine(ext) {
		f.recordXSS(f.module.evidence("template_render", call), f.eval(args.NamedChild(1)), "unknown", "text/html", false, config)
		return
	}
	pattern := ejsOutput
	switch ext {
	case "ejs":
	case "hbs", "handlebars":
		pattern = handlebarsOutput
	case "pug", "jade":
		pattern = pugOutput
	default:
		return
	}
	m := f.templateModule(file, ext)
	if m == nil {
		f.gaps = append(f.gaps, f.gap("template_parse_unresolved", "template expressions could not be parsed", call))
		f.recordXSS(f.module.evidence("template_render", call), f.eval(args.NamedChild(1)), "unknown", "text/html", false, config)
		return
	}
	env, bindings := f.templateLocals(m, args.NamedChild(1))
	config = append(config, bindings...)
	for _, match := range pattern.FindAllStringSubmatchIndex(file.Text, -1) {
		mode := file.Text[match[2]:match[3]]
		raw := file.Text[match[4]:match[5]]
		expression := strings.TrimSpace(raw)
		if expression == "else" || strings.HasPrefix(expression, "#") || strings.HasPrefix(expression, "/") {
			continue
		}
		start := match[4] + len(raw) - len(strings.TrimLeft(raw, " \t\r\n"))
		end := start + len(expression)
		node := parse.NodeAt(m.tree.RootNode(), start, end)
		if node == nil {
			f.gaps = append(f.gaps, f.gap("template_expression_unresolved", "template output expression is not resolved", call))
			continue
		}
		v := f.templateExpression(m, args.NamedChild(1), node, env)
		escaped := (ext == "ejs" && mode == "=") || ((ext == "hbs" || ext == "handlebars") && mode == "") || ((ext == "pug" || ext == "jade") && mode == "#")
		context := parse.HTMLOutputContext(file.Text[:match[0]])
		if ext == "pug" || ext == "jade" {
			context = pugOutputContext(file.Text[:match[0]])
		}
		sink := parse.TextRange(file, match[0], match[1], "template_output")
		extra := append(append([]analysis.Evidence{}, config...), f.module.evidence("template_render", call))
		extra = append(extra, parse.RenderMarkup(file, match[0], match[1]))
		before := len(f.uses)
		f.recordXSS(sink, v, context, "text/html", escaped, extra)
		if len(f.uses) > before && escaped && requestRenderOptions(f, args.NamedChild(1)) {
			u := &f.uses[len(f.uses)-1]
			u.XSS.Protection = "unknown"
			u.XSS.ProtectionReason = "Escaped field syntax is observed, but the complete request object also controls render locals/options. Template selection and option effects are unresolved."
			u.Gaps = append(u.Gaps, f.gap("render_options_unresolved", "Request-controlled whole-object render locals can also supply template-engine options.", call))
		}
	}
}

func requestRenderOptions(f *flow, locals *sitter.Node) bool {
	if locals.Kind() == "object" {
		for i := uint(0); i < locals.NamedChildCount(); i++ {
			if locals.NamedChild(i).Kind() == "spread_element" {
				return len(f.eval(locals.NamedChild(i)).deps) > 0
			}
		}
		return false
	}
	for _, dependency := range f.eval(locals).deps {
		if dependency.Source.Kind == "input_source" {
			return true
		}
	}
	return false
}

func pugOutputContext(prefix string) string {
	lines := strings.Split(prefix, "\n")
	current := lines[len(lines)-1]
	if open := strings.LastIndex(current, "("); open >= 0 {
		return parse.HTMLOutputContext("<x " + current[open+1:])
	}
	indent := len(current) - len(strings.TrimLeft(current, " \t"))
	for i := len(lines) - 2; i >= 0; i-- {
		line := lines[i]
		level := len(line) - len(strings.TrimLeft(line, " \t"))
		if strings.TrimSpace(line) == "" || level >= indent {
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(line), "script") {
			return "script"
		}
		if strings.HasPrefix(strings.TrimSpace(line), "style") {
			return "style"
		}
		break
	}
	if strings.HasPrefix(strings.TrimSpace(current), "script ") {
		return "script"
	}
	return "html_text"
}

func (f *flow) verifiedTemplateEngine(extension string) bool {
	verified := true
	m := f.registration
	if m == nil {
		return false
	}
	walkCalls(m.tree.RootNode(), func(call *sitter.Node) {
		fn, args := call.ChildByFieldName("function"), call.ChildByFieldName("arguments")
		if fn == nil || fn.Kind() != "member_expression" || args == nil || args.NamedChildCount() < 2 {
			return
		}
		obj, prop := fn.ChildByFieldName("object"), fn.ChildByFieldName("property")
		if obj == nil || prop == nil || !m.receivers[obj.Utf8Text(m.src)] || prop.Utf8Text(m.src) != "engine" {
			return
		}
		ext, _ := stringLiteral(args.NamedChild(0), m.src)
		if ext != extension {
			return
		}
		engine := args.NamedChild(1)
		name := strings.Split(engine.Utf8Text(m.src), ".")[0]
		imp, ok := m.imports[name]
		method := ""
		if engine.Kind() == "member_expression" {
			if prop := engine.ChildByFieldName("property"); prop != nil {
				method = prop.Utf8Text(m.src)
			}
		}
		verified = ok && !bindingReassigned(m, name) && !shadowed(call, name, m.src) &&
			((extension == "ejs" && ((imp.module == "ejs-locals" && engine.Kind() == "identifier") || (imp.module == "ejs" && (method == "__express" || method == "renderFile")))) ||
				(extension == "hbs" && imp.module == "hbs" && method == "__express") || (extension == "pug" && imp.module == "pug" && method == "renderFile"))
	})
	return verified
}
