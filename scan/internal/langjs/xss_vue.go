package langjs

import (
	"regexp"
	"strings"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/parse"
)

var vueScript = regexp.MustCompile(`(?is)<script\b[^>]*>(.*?)</script\s*>`)
var vueTemplate = regexp.MustCompile(`(?is)<template\b[^>]*>(.*?)</template\s*>`)
var vueHTML = regexp.MustCompile(`\bv-html\s*=\s*["']([^"']+)["']`)

func vueScriptSource(source []byte) []byte {
	out := make([]byte, len(source))
	for i, ch := range source {
		out[i] = ' '
		if ch == '\n' || ch == '\r' {
			out[i] = ch
		}
	}
	for _, match := range vueScript.FindAllSubmatchIndex(source, -1) {
		copy(out[match[2]:match[3]], source[match[2]:match[3]])
	}
	return out
}

func (s *moduleSet) vueOutputs(f *flow) {
	if !strings.HasSuffix(f.module.file, ".vue") {
		return
	}
	source := string(f.module.src)
	match := vueTemplate.FindStringSubmatchIndex(source)
	if len(match) == 0 {
		return
	}
	file := analysis.Evidence{Kind: "template", Text: source, SHA256: f.module.hash, Span: parse.Span(f.module.file, f.module.tree.RootNode())}
	markup := source[match[2]:match[3]]
	for _, binding := range vueHTML.FindAllStringSubmatchIndex(markup, -1) {
		start, end := match[2]+binding[0], match[2]+binding[1]
		if htmlCommentAt(source, start) {
			continue
		}
		expression := strings.TrimSpace(markup[binding[2]:binding[3]])
		v, ok := f.env[expression]
		if !ok {
			v = f.env["this."+expression]
		}
		sink := parse.TextRange(file, start, end, "vue_output")
		f.recordXSS(sink, v, "html_text", "text/html", false, []analysis.Evidence{{Kind: "render_binding", Text: "Vue single-file template v-html", Span: sink.Span, SHA256: file.SHA256}})
	}
	for _, binding := range handlebarsOutput.FindAllStringSubmatchIndex(markup, -1) {
		start, end := match[2]+binding[0], match[2]+binding[1]
		if htmlCommentAt(source, start) || parse.HTMLOutputContext(source[:start]) != "html_text" {
			continue
		}
		name := strings.TrimSpace(markup[binding[4]:binding[5]])
		v := f.env[name]
		sink := parse.TextRange(file, start, end, "vue_text_output")
		f.recordXSS(sink, v, "html_text", "text/html", true, []analysis.Evidence{{Kind: "render_binding", Text: "Vue escaped text interpolation", Span: sink.Span, SHA256: file.SHA256}})
	}
}

func htmlCommentAt(source string, offset int) bool {
	return strings.LastIndex(source[:offset], "<!--") > strings.LastIndex(source[:offset], "-->")
}
