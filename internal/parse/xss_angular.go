package parse

import (
	"path/filepath"
	"regexp"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
)

var angularBinding = regexp.MustCompile(`(?i)\[(innerHTML|href|src)\]\s*=\s*(["'])([^"']+)["']`)

func (s *moduleSet) clientClass(m *sourceModule, class *sitter.Node) *clientContext {
	name := class.ChildByFieldName("name")
	context := &clientContext{entry: browserEntry(m, m.evidence("browser_source_slice", class), name.Utf8Text(m.src), "component"),
		injected: map[string]clientInjection{}, methods: map[string]*sitter.Node{}, fields: map[string]*sitter.Node{}}
	body := class.ChildByFieldName("body")
	if body == nil {
		return context
	}
	for i := uint(0); i < body.NamedChildCount(); i++ {
		n := body.NamedChild(i)
		key := n.ChildByFieldName("name")
		if key == nil {
			continue
		}
		field := key.Utf8Text(m.src)
		if n.Kind() == "method_definition" {
			context.methods[field] = n
			if field == "constructor" {
				params := n.ChildByFieldName("parameters")
				if params != nil {
					for j := uint(0); j < params.NamedChildCount(); j++ {
						p := params.NamedChild(j)
						id, typ := p.ChildByFieldName("pattern"), p.ChildByFieldName("type")
						if id != nil && typ != nil {
							label := strings.TrimSpace(strings.TrimPrefix(typ.Utf8Text(m.src), ":"))
							if imp, ok := m.imports[label]; ok {
								context.injected[id.Utf8Text(m.src)] = clientInjection{imp.module, imp.name, p}
							}
						}
					}
				}
			}
			continue
		}
		v := n.ChildByFieldName("value")
		if v == nil {
			continue
		}
		context.fields[field] = v
		if v.Kind() != "call_expression" {
			continue
		}
		fn, args := v.ChildByFieldName("function"), v.ChildByFieldName("arguments")
		if fn == nil || args == nil || args.NamedChildCount() != 1 {
			continue
		}
		factory := m.imports[fn.Utf8Text(m.src)]
		if factory.module != "@angular/core" || factory.name != "inject" {
			continue
		}
		if imp, ok := m.imports[args.NamedChild(0).Utf8Text(m.src)]; ok {
			context.injected[field] = clientInjection{imp.module, imp.name, n}
			context.bindings = append(context.bindings, m.evidence("render_binding", n), m.evidence("render_binding", imp.declaration))
		}
	}
	walkCalls(m.tree.RootNode(), func(call *sitter.Node) {
		fn, args := call.ChildByFieldName("function"), call.ChildByFieldName("arguments")
		if fn == nil || args == nil || args.NamedChildCount() != 1 || call.Parent() == nil || call.Parent().Kind() != "decorator" || call.EndByte() > body.StartByte() {
			return
		}
		imp := m.imports[fn.Utf8Text(m.src)]
		if imp.module != "@angular/core" || imp.name != "Component" {
			return
		}
		config := args.NamedChild(0)
		path, ok := stringLiteral(property(config, "templateUrl", m.src), m.src)
		if !ok {
			return
		}
		if template, ok := s.readText(filepath.ToSlash(filepath.Join(filepath.Dir(m.file), path))); ok {
			context.template = &template
			context.angular, context.entry.Browser.Framework = true, "angular"
			context.bindings = append(context.bindings, m.evidence("render_binding", call), m.evidence("render_binding", imp.declaration))
		}
	})
	return context
}

func (s *moduleSet) angularOutputs(f *flow) {
	if f.client == nil || f.client.template == nil || !f.client.angular {
		return
	}
	file := *f.client.template
	matchedBypass := map[string]bool{}
	for _, match := range angularBinding.FindAllStringSubmatchIndex(file.Text, -1) {
		if htmlCommentAt(file.Text, match[0]) {
			continue
		}
		kind, expression := file.Text[match[2]:match[3]], strings.TrimSpace(file.Text[match[6]:match[7]])
		expression = strings.ReplaceAll(expression, "?.", ".")
		if !simpleTemplateField.MatchString(expression) {
			continue
		}
		v, ok := f.env[clientKey("this."+expression)]
		if !ok {
			v, ok = f.client.iterationField(file.Text, expression)
		}
		if !ok || len(v.deps) == 0 {
			continue
		}
		context := "html_text"
		if !strings.EqualFold(kind, "innerHTML") {
			context = "url"
		}
		f.angularRecord(textRange(file, match[0], match[1], "angular_output"), v, context, f.client.bindings, matchedBypass)
	}
	var uses []analysis.CandidateUse
	for _, u := range f.uses {
		if u.Sink.Kind != "trust_bypass" || !matchedBypass[u.Sink.Span.File+":"+u.Sink.Text] {
			uses = append(uses, u)
		}
	}
	f.uses = uses
}

// angularRecord records a template output and notes the trust bypasses it consumed.
func (f *flow) angularRecord(sink analysis.Evidence, v value, context string, bindings []analysis.Evidence, matched map[string]bool) {
	before := len(f.uses)
	f.recordXSS(sink, v, context, "text/html", v.trustedContext == "", bindings)
	if len(f.uses) == before {
		return
	}
	u := &f.uses[len(f.uses)-1]
	u.XSS.Protection, u.XSS.ProtectionReason, u.XSS.Paths = f.angularPathProtection(v, context)
	if v.apiPath != "" {
		u.XSS.Type, u.XSS.OriginResolved = "cross_tier", false
		u.XSS.ResponsePath, u.XSS.ResponseMethod, u.XSS.ResponseField = v.apiPath, v.apiMethod, v.responseField
	}
	for _, d := range v.deps {
		for _, e := range d.Transfers {
			if e.Kind == "trust_bypass" {
				matched[e.Span.File+":"+e.Text] = true
			}
		}
	}
}

// angularPathProtection classifies each path to a one-way Angular binding. A
// matching trust bypass is unsafe unless verified sanitization precedes it; a
// plain path gets default sanitization; any other transformation is unknown.
func (f *flow) angularPathProtection(v value, context string) (string, string, []analysis.XSSPath) {
	paths := make([]string, len(v.deps))
	unsafe, unknown, mismatch := false, false, false
	for i, d := range v.deps {
		bypass := ""
		for _, e := range d.Transfers {
			if e.Kind == "trust_bypass" {
				bypass = trustBypassContext(e.Text)
			}
		}
		switch {
		case d.Source.Kind == "unresolved_source":
			paths[i] = "unknown"
		case bypass != "" && bypass != context:
			paths[i], mismatch = "unknown", true
		case bypass != "":
			paths[i] = f.dependencyProtection(d, context)
		case plainFrameworkInput(value{deps: []analysis.Dependency{d}}):
			paths[i] = "sanitized"
		default:
			paths[i] = "unknown"
		}
		switch paths[i] {
		case "raw", "ineffective":
			unsafe = true
		case "unknown":
			unknown = true
		}
	}
	switch {
	case unsafe:
		return "raw", "A verified Angular trust bypass for this context reaches the binding on a source path without modeled sanitization; other paths remain in the evidence.", xssPaths(paths, nil)
	case mismatch:
		return "unknown", "The trust bypass and rendering context do not match.", xssPaths(paths, nil)
	case unknown:
		return "unknown", "Default Angular sanitization is expected for plain values, but the return type/transformations of this value are not established; a trusted wrapper cannot be excluded.", xssPaths(paths, nil)
	}
	return "sanitized", "A plain browser/request value reaches Angular's one-way binding with no unknown transformation or trust bypass; its default sanitization applies.", nil
}

func trustBypassContext(text string) string {
	switch {
	case strings.Contains(text, "bypassSecurityTrustHtml"):
		return "html_text"
	case strings.Contains(text, "bypassSecurityTrustScript"):
		return "script"
	case strings.Contains(text, "bypassSecurityTrustStyle"):
		return "style"
	case strings.Contains(text, "bypassSecurityTrustUrl"), strings.Contains(text, "bypassSecurityTrustResourceUrl"):
		return "url"
	}
	return ""
}

func plainFrameworkInput(v value) bool {
	if len(v.deps) == 0 {
		return false
	}
	for _, dep := range v.deps {
		if dep.Source.Kind != "browser_source" && dep.Source.Kind != "input_source" {
			return false
		}
		for _, transfer := range dep.Transfers {
			if transfer.Kind == "call_argument_dependency" || transfer.Kind == "trust_bypass" {
				return false
			}
		}
	}
	return true
}
