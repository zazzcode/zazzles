package parse

import (
	"fmt"
	"sort"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
)

// templateString evaluates a template literal. A substitution after markup takes its
// HTML context from that literal prefix, so the context survives local wrappers such
// as layout(title, body). An enclosing template only confirms an inner html_text
// value when it is also html_text; anything else leaves that value's context mixed.
func (f *flow) templateString(n *sitter.Node) value {
	var out value
	for i := uint(0); i < n.NamedChildCount(); i++ {
		child := n.NamedChild(i)
		if child.Kind() != "template_substitution" {
			continue
		}
		v := f.children(child)
		prefix := string(f.module.src[n.StartByte():child.StartByte()])
		if strings.Contains(prefix, "<") {
			v.deps = tagOutputContext(v.deps, htmlOutputContext(prefix))
		}
		out = combine(out, f.transfer(v, "expression", child))
	}
	if literalMarkup(n, f.module.src) {
		out.outputHTML = true
	}
	return f.transfer(out, "expression", n)
}

func tagOutputContext(deps []analysis.Dependency, context string) []analysis.Dependency {
	out := append([]analysis.Dependency{}, deps...)
	for i := range out {
		switch out[i].OutputContext {
		case "":
			out[i].OutputContext = context
		case "html_text":
			if context != "html_text" {
				out[i].OutputContext = "mixed"
			}
		}
	}
	return out
}

// literalMarkup reports a template whose literal text opens an HTML element.
func literalMarkup(n *sitter.Node, src []byte) bool {
	for i := uint(0); i < n.NamedChildCount(); i++ {
		child := n.NamedChild(i)
		if child.Kind() != "string_fragment" {
			continue
		}
		text := child.Utf8Text(src)
		for at := strings.IndexByte(text, '<'); at >= 0 && at+1 < len(text); {
			c := text[at+1]
			if c == '!' || c == '/' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' {
				return true
			}
			next := strings.IndexByte(text[at+1:], '<')
			if next < 0 {
				break
			}
			at += next + 1
		}
	}
	return false
}

type outputGroup struct {
	context string
	value   value
}

// outputGroups splits one response into a value per output context, so a raw HTML
// text path and a raw attribute path are separate claims rather than "mixed".
func outputGroups(v value, fallback string) []outputGroup {
	byContext := map[string][]analysis.Dependency{}
	for _, d := range v.deps {
		context := d.OutputContext
		if context == "" {
			context = fallback
		}
		byContext[context] = append(byContext[context], d)
	}
	var names []string
	for name := range byContext {
		names = append(names, name)
	}
	sort.Strings(names)
	var out []outputGroup
	for _, name := range names {
		group := v
		group.deps = byContext[name]
		out = append(out, outputGroup{name, group})
	}
	return out
}

// fieldDeps extends the field path of browser API and token values.
func fieldDeps(deps []analysis.Dependency, segment string) []analysis.Dependency {
	out := append([]analysis.Dependency{}, deps...)
	for i := range out {
		if k := out[i].Source.Kind; k == "api_response" || k == "token_claim" {
			out[i].ResponseField = joinField(out[i].ResponseField, segment)
		}
	}
	return out
}

func uniqueGaps(gaps []analysis.Gap) []analysis.Gap {
	seen := map[string]bool{}
	out := make([]analysis.Gap, 0, len(gaps))
	for _, g := range gaps {
		key := fmt.Sprintf("%s|%s|%s|%d|%d", g.Kind, g.Detail, g.At.File, g.At.StartByte, g.At.EndByte)
		if !seen[key] {
			seen[key] = true
			out = append(out, g)
		}
	}
	return out
}

// respondsInCallback reports an inline callback that writes the handler's response,
// such as the body of http.get(url, cb) or stream.on("end", cb).
func (f *flow) respondsInCallback(fn *sitter.Node) bool {
	if f.response == "" {
		return false
	}
	found := false
	walkCalls(fn, func(call *sitter.Node) {
		callee := call.ChildByFieldName("function")
		if callee == nil || callee.Kind() != "member_expression" || !f.isResponse(callee.ChildByFieldName("object")) {
			return
		}
		if prop := callee.ChildByFieldName("property"); prop != nil {
			switch prop.Utf8Text(f.module.src) {
			case "send", "write", "end", "render":
				found = true
			}
		}
	})
	return found
}

// hasModelRows reports a JSON value that returns storage rows without request deps.
func hasModelRows(v value, depth int) bool {
	if v.model != "" && v.read != nil {
		return true
	}
	if depth > 4 {
		return false
	}
	for _, field := range v.fields {
		if hasModelRows(field, depth+1) {
			return true
		}
	}
	return false
}
