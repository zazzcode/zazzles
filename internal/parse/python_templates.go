package parse

import (
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
)

var pythonJinjaOutput = regexp.MustCompile(`(?s)\{\{\s*(.*?)\s*\}\}`)
var pythonJinjaTag = regexp.MustCompile(`(?s)\{%\s*(.*?)\s*%\}`)

func (f *pythonFlow) recordXSS(sink analysis.Evidence, v pythonValue, context string, extra []analysis.Evidence) {
	if len(v.deps) == 0 {
		return
	}
	if context == "html_text" {
		context = f.expressionContext(v, context)
	}
	v.gaps = append(v.gaps, f.guardGaps(v)...)
	deps := []analysis.Dependency{}
	paths := []analysis.XSSPath{}
	hasRaw, hasUnknown := false, false
	stored := false
	for _, d := range v.deps {
		p := d.protection
		if p == "text_encoded" {
			if context == "html_text" {
				p = "encoded"
			} else {
				p = "unknown"
			}
		}
		if p == "numeric" || p == "non_content" {
			p = "encoded"
		}
		if (p == "encoded" || p == "sanitized") && context != "html_text" && context != "html_attribute" {
			p = "unknown"
		}
		if p == "" {
			p = "raw"
		}
		hasRaw = hasRaw || p == "raw"
		hasUnknown = hasUnknown || p == "unknown"
		stored = stored || d.dep.StorageKey != ""
		deps = append(deps, d.dep)
		paths = append(paths, analysis.XSSPath{Dependency: len(deps) - 1, Protection: p})
	}
	p, reason := "encoded", "Every modeled source path is HTML-escaped in HTML text or a quoted non-active attribute."
	if hasUnknown {
		p, reason = "unknown", "A source transformation, renderer contract or output context remains unresolved."
	}
	if hasRaw {
		p, reason = "raw", "A supported source path reaches HTML without context-appropriate escaping; unknown siblings remain explicit."
	}
	for _, g := range append(append([]analysis.Gap{}, f.gaps...), v.gaps...) {
		switch g.Kind {
		case "python_decorator_unresolved", "route_mount_unresolved", "render_configuration_unresolved", "template_parse_unresolved", "python_loop_unresolved", "dependency_limit", "transfer_limit", "work_limit", "input_helper_unresolved", "python_finally_unresolved":
			p, reason = "unknown", "A relevant Python control, registration or renderer contract is unresolved."
		}
	}
	if v.unknown && !hasRaw {
		p = "unknown"
		reason = "A value definition or output alternative is unresolved; source availability does not establish a complete value path."
	}
	if context == "mixed" || context == "unknown" {
		p = "unknown"
	}
	kind := "reflected"
	if stored {
		kind = "stored"
	}
	u := analysis.CandidateUse{ID: "use:" + f.invocation.ID + ":" + sink.Span.File + ":" + fmtInt(sink.Span.StartByte) + ":xss", EntryID: f.invocation.EntryID, InvocationContextID: f.invocation.ID, Kind: "xss_candidate", Sink: sink, Dependencies: deps, Context: append(append([]analysis.Evidence{}, f.context...), extra...), Gaps: append(append([]analysis.Gap{}, f.gaps...), v.gaps...), Assessment: analysis.Assessment{Status: "not_run"}, XSS: &analysis.XSSFacts{Type: kind, EntryKind: "server", OutputContext: context, ContentType: "text/html", Protection: p, ProtectionReason: reason, OriginResolved: !stored, Paths: paths}, APIModel: analysispacks.XSSContract("python-html-output-v1", f.route.route.Framework)}
	u.Context = append(u.Context, f.route.module.evidence("render_binding", f.route.decorator))
	f.report.Uses = append(f.report.Uses, u)
}
func fmtInt(n int) string { return strconv.Itoa(n) }
func (f *pythonFlow) renderTemplate(n *sitter.Node) {
	args := pyArgs(n)
	if len(args) == 0 {
		return
	}
	name, ok := pyLiteral(f.module, args[0])
	folder := f.route.receiver.templates
	if !ok || folder == "" {
		v := f.evalChildren(n.ChildByFieldName("arguments"))
		v.gaps = append(v.gaps, f.gap("template_parse_unresolved", "template path/configuration is not statically resolved", n))
		f.recordXSS(f.module.evidence("template_render", n), pyProtect(v, "unknown"), "unknown", nil)
		return
	}
	file, found := f.set.text.Read(filepath.ToSlash(filepath.Join(folder, name)))
	if !found {
		v := f.evalChildren(n.ChildByFieldName("arguments"))
		v.gaps = append(v.gaps, f.gap("template_parse_unresolved", "template could not be read inside target", n))
		f.recordXSS(f.module.evidence("template_render", n), pyProtect(v, "unknown"), "unknown", nil)
		return
	}
	locals := f.templateLocals(n)
	auto := false
	switch strings.ToLower(filepath.Ext(name)) {
	case ".html", ".htm", ".xml", ".xhtml", ".svg":
		auto = true
	}
	f.templateOutputs(n, file, locals, auto)
}
func (f *pythonFlow) templateLocals(n *sitter.Node) map[string]pythonValue {
	locals := map[string]pythonValue{}
	args := n.ChildByFieldName("arguments")
	for i := uint(0); args != nil && i < args.NamedChildCount(); i++ {
		a := args.NamedChild(i)
		if a.Kind() == "keyword_argument" {
			locals[pyText(f.module, a.ChildByFieldName("name"))] = f.eval(a.ChildByFieldName("value"))
		}
	}
	return locals
}
func (f *pythonFlow) renderInline(n *sitter.Node, text string) {
	args := pyArgs(n)
	if len(args) == 0 {
		return
	}
	file := f.module.evidence("inline_template", args[0])
	file.Text = text
	f.templateOutputs(n, file, f.templateLocals(n), true)
}
func (f *pythonFlow) templateOutputs(call *sitter.Node, file analysis.Evidence, locals map[string]pythonValue, auto bool) {
	matches := pythonJinjaOutput.FindAllStringSubmatchIndex(file.Text, -1)
	configUnknown := f.rendererUnknown()
	for _, match := range matches {
		expr := strings.TrimSpace(file.Text[match[2]:match[3]])
		parts := strings.Split(expr, "|")
		field := strings.TrimSpace(parts[0])
		if !simpleTemplateField.MatchString(field) {
			if !strings.HasPrefix(field, "url_for(") {
				f.report.Gaps = append(f.report.Gaps, analysis.Gap{Kind: "template_output_unresolved", Detail: "Jinja output expression is outside the bounded field subset", At: textRange(file, match[0], match[1], "template_output").Span})
			}
			continue
		}
		keys := strings.Split(field, ".")
		v, ok := locals[keys[0]]
		if !ok {
			f.report.Gaps = append(f.report.Gaps, analysis.Gap{Kind: "template_binding_unresolved", Detail: "No supported render-local/loop/global binding for " + keys[0], At: textRange(file, match[0], match[1], "template_output").Span})
			continue
		}
		for _, key := range keys[1:] {
			v = f.projectValue(v, key, call)
		}
		if len(v.deps) == 0 {
			continue
		}
		escaped := auto
		markedSafe, force := false, false
		for _, d := range v.deps {
			markedSafe = markedSafe || pythonMarkupPath(d.dep)
		}
		stack := []bool{}
		unsupported := false
		for _, tag := range pythonJinjaTag.FindAllStringSubmatch(file.Text[:match[0]], -1) {
			command := strings.TrimSpace(tag[1])
			switch {
			case command == "autoescape false":
				stack = append(stack, escaped)
				escaped = false
			case command == "autoescape true":
				stack = append(stack, escaped)
				escaped = true
			case command == "endautoescape":
				if len(stack) > 0 {
					escaped = stack[len(stack)-1]
					stack = stack[:len(stack)-1]
				}
			case strings.HasPrefix(command, "autoescape "):
				unsupported = true
			case strings.HasPrefix(command, "include ") || strings.HasPrefix(command, "extends ") || strings.HasPrefix(command, "macro ") || strings.HasPrefix(command, "set "):
				unsupported = true
			}
		}
		for _, filter := range parts[1:] {
			switch strings.TrimSpace(filter) {
			case "safe":
				escaped = false
				markedSafe = true

			case "escape", "e":
				escaped = !markedSafe
			case "forceescape":
				escaped = true
				force = true
				markedSafe = false
			default:
				unsupported = true
			}
		}
		if escaped {
			v.deps = append([]pythonDep{}, v.deps...)
			for i := range v.deps {
				if v.deps[i].protection != "unknown" && (force || (!markedSafe && !pythonMarkupPath(v.deps[i].dep))) {
					v.deps[i].protection = "encoded"
				}
			}
		}
		if unsupported || configUnknown {
			v = pyProtect(v, "unknown")
			v.gaps = append(v.gaps, f.gap("render_configuration_unresolved", "custom Jinja settings, tags or filters require review", call))
		}
		markup := renderMarkup(file, match[0], match[1])
		sourceContext := file
		sink := textRange(file, match[0], match[1], "template_output")
		if file.Kind == "inline_template" {
			sink = f.module.evidence("template_output", pyArgs(call)[0])
			markup = f.module.evidence("render_markup_context", pyArgs(call)[0])
			sourceContext = f.module.evidence("inline_template", pyArgs(call)[0])
		}
		f.recordXSS(sink, v, htmlOutputContext(file.Text[:match[0]]), []analysis.Evidence{f.module.evidence("render_binding", call), markup, sourceContext})
	}
}
func pythonMarkupPath(d analysis.Dependency) bool {
	for _, e := range d.Transfers {
		if e.Kind == "trusted_html_wrapper" {
			return true
		}
	}
	return false
}
func (f *pythonFlow) rendererUnknown() bool {
	for _, m := range f.set.modules {
		text := string(m.src)
		if strings.Contains(text, "jinja_env") || strings.Contains(text, "jinja_options") || strings.Contains(text, "select_jinja_autoescape") {
			return true
		}
	}
	return false
}

func pyStaticString(m *pythonModule, n *sitter.Node) (string, bool) {
	if text, ok := pyLiteral(m, n); ok {
		return text, true
	}
	if n != nil && n.Kind() == "binary_operator" && pyText(m, n.ChildByFieldName("operator")) == "+" {
		a, aok := pyStaticString(m, n.ChildByFieldName("left"))
		b, bok := pyStaticString(m, n.ChildByFieldName("right"))
		return a + b, aok && bok
	}
	return "", false
}
func (f *pythonFlow) expressionContext(v pythonValue, fallback string) string {
	contexts := map[string]bool{}
	for _, d := range v.deps {
		context := fallback
		for _, e := range d.dep.Transfers {
			m := f.set.modules[e.Span.File]
			if m == nil {
				continue
			}
			n := m.tree.RootNode().NamedDescendantForByteRange(uint(e.Span.StartByte), uint(e.Span.EndByte))
			if n == nil {
				continue
			}
			if e.Kind == "string_interpolation" && n.Kind() == "interpolation" {
				for parent := n.Parent(); parent != nil; parent = parent.Parent() {
					if parent.Kind() == "string" {
						prefix := string(m.src[parent.StartByte():n.StartByte()])
						context = htmlOutputContext(prefix)
						break
					}
				}
			}
			if e.Kind == "expression" && n.Kind() == "binary_operator" {
				if prefix, ok := pyStaticString(m, n.ChildByFieldName("left")); ok && strings.Contains(prefix, "<") {
					context = htmlOutputContext(prefix)
				}
			}
		}
		contexts[context] = true
	}
	if len(contexts) > 1 {
		return "mixed"
	}
	for c := range contexts {
		return c
	}
	return fallback
}
