package parse

import (
	"fmt"
	"regexp"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
)

var htmlAttribute = regexp.MustCompile(`(?i)([a-z_:][a-z0-9_:.-]*)\s*=\s*(["']?)[^"']*$`)

func htmlOutputContext(prefix string) string {
	lower := strings.ToLower(prefix)
	if strings.LastIndex(lower, "<script") > strings.LastIndex(lower, "</script") && strings.LastIndex(lower, ">") > strings.LastIndex(lower, "<script") {
		return "script"
	}
	if strings.LastIndex(lower, "<style") > strings.LastIndex(lower, "</style") && strings.LastIndex(lower, ">") > strings.LastIndex(lower, "<style") {
		return "style"
	}
	open := strings.LastIndex(prefix, "<")
	if open > strings.LastIndex(prefix, ">") {
		match := htmlAttribute.FindStringSubmatch(prefix[open:])
		if len(match) == 0 {
			return "html_tag"
		}
		attribute := strings.ToLower(match[1])
		if strings.HasPrefix(attribute, "on") || attribute == "srcdoc" || attribute == "style" {
			return "active_attribute"
		}
		if attribute == "href" || attribute == "src" || attribute == "action" || attribute == "formaction" {
			return "url"
		}
		if match[2] == "" {
			return "unquoted_attribute"
		}
		return "html_attribute"
	}
	return "html_text"
}

func (f *flow) xssProtection(v value, context string, escaped bool) (string, string) {
	protection, reason, _ := f.xssPathProtection(v, context, escaped)
	return protection, reason
}

// xssPathProtection also returns each dependency's own protection, in dependency
// order. A path is classified by itself; a protected sibling never protects it.
func (f *flow) xssPathProtection(v value, context string, escaped bool) (string, string, []string) {
	if escaped {
		if context == "html_text" || context == "html_attribute" {
			return "encoded", "The template HTML-escapes this value in HTML text or a quoted non-active attribute.", nil
		}
		return "unknown", "Template HTML escaping does not establish protection in this output context.", nil
	}
	paths := make([]string, len(v.deps))
	allProtected := len(v.deps) > 0
	hasRaw, hasUnknown, hasIneffective := false, false, false
	for i, dependency := range v.deps {
		paths[i] = f.dependencyProtection(dependency, context)
		switch paths[i] {
		case "encoded", "sanitized":
		case "unknown":
			allProtected, hasUnknown = false, true
		default:
			allProtected, hasRaw = false, true
			hasIneffective = hasIneffective || paths[i] == "ineffective"
		}
	}
	if allProtected {
		return "sanitized", "Every modeled source path passes through a verified encoder or sanitizer appropriate to this output context.", paths
	}
	if hasRaw {
		if hasIneffective {
			return "ineffective", "A source path reaches output through a transformation with an established bypass: marked 0.3.5's sanitize option (upstream marked PR 592), sanitize-html before 1.4.3, which is not applied recursively (CVE-2016-1000237), or single-pass tag stripping.", paths
		}
		return "raw", "A source path reaches raw output without modeled context-appropriate encoding or sanitization; unresolved sibling paths remain in the evidence.", paths
	}
	if hasUnknown {
		return "unknown", "A transformation or its adequacy for this context is unresolved; no protection is assumed.", paths
	}
	return "unknown", "No complete source-to-output path was established.", paths
}

// dependencyProtection classifies one path by its call transfers in order. A later
// transformation of unknown effect leaves the path unknown even after an encoder.
func (f *flow) dependencyProtection(dependency analysis.Dependency, context string) string {
	protection := "raw"
	for _, transfer := range dependency.Transfers {
		if transfer.Kind != "call_argument_dependency" {
			continue
		}
		m := f.set.modules[transfer.Span.File]
		if m == nil {
			protection = "unknown"
			continue
		}
		call := nodeAt(m.tree.RootNode(), transfer.Span.StartByte, transfer.Span.EndByte)
		mode := verifiedOutputProtection(m, call)
		if mode == "" {
			mode = regexReplaceMode(m, call)
		}
		if mode == "" && neutralStringCall(m, call) {
			mode = "neutral"
		}
		if mode == "neutral" {
			continue
		}
		if mode == "markdown" && f.set.packageVersion("marked") == "0.3.5" {
			mode = "ineffective"
		}
		if mode == "sanitize_html" {
			mode = "sanitize"
			if versionBefore(f.set.packageVersion("sanitize-html"), 1, 4, 3) {
				mode = "ineffective"
			}
		}
		if mode == "strip_tags" {
			mode = "ineffective"
		}
		if mode == "sanitize_dom" {
			mode = ""
			if f.client != nil {
				mode = "sanitize"
			}
		}
		switch mode {
		case "encode":
			protection = "unknown"
			if context == "html_text" || context == "html_attribute" {
				protection = "encoded"
			}
		case "sanitize":
			protection = "unknown"
			if context == "html_text" {
				protection = "sanitized"
			}
		case "allowlist":
			// The output holds only allow-listed characters, none HTML/URL significant.
			protection = "unknown"
			switch context {
			case "html_text", "html_attribute", "unquoted_attribute", "url":
				protection = "sanitized"
			}
		case "ineffective":
			// Bypassable rich-HTML conversion does not resolve an earlier unknown step.
			if protection != "unknown" {
				protection = "ineffective"
			}
		default:
			protection = "unknown"
		}
	}
	return protection
}

// xssPaths reports per-path protection only when paths differ. entries, when
// present, has one writing entry per dependency.
func xssPaths(protections, entries []string) []analysis.XSSPath {
	distinct := map[string]bool{}
	for _, p := range protections {
		distinct[p] = true
	}
	if len(distinct) < 2 {
		return nil
	}
	paths := make([]analysis.XSSPath, len(protections))
	for i, p := range protections {
		paths[i] = analysis.XSSPath{Dependency: i, Protection: p}
		if i < len(entries) {
			paths[i].Entry = entries[i]
		}
	}
	return paths
}

func verifiedOutputProtection(m *sourceModule, call *sitter.Node) string {
	if call == nil || call.Kind() != "call_expression" {
		return ""
	}
	fn, args := call.ChildByFieldName("function"), call.ChildByFieldName("arguments")
	if fn == nil || args == nil || args.NamedChildCount() != 1 {
		return ""
	}
	parts := strings.Split(fn.Utf8Text(m.src), ".")
	if shadowed(call, parts[0], m.src) || bindingReassigned(m, parts[0]) {
		return ""
	}
	imp, ok := m.imports[parts[0]]
	if !ok {
		return ""
	}
	method := imp.name
	if len(parts) == 2 && (imp.name == "default" || imp.name == "*") {
		method = parts[1]
	}
	switch imp.module {
	case "marked":
		if len(parts) == 1 || method == "parse" {
			return "markdown"
		}
	case "entities", "he":
		if method == "encode" || method == "encodeHTML" || method == "escapeHTML" {
			return "encode"
		}
	case "escape-html":
		if len(parts) == 1 {
			return "encode"
		}
	case "sanitize-html":
		if len(parts) == 1 {
			return "sanitize_html"
		}
	case "dompurify":
		// Without a DOM window (for example in Node) DOMPurify returns its input.
		if method == "sanitize" {
			return "sanitize_dom"
		}
	case "isomorphic-dompurify":
		if method == "sanitize" {
			return "sanitize"
		}
	}
	return ""
}

// neutralStringCall reports a call that keeps its string content: join, toString, trim.
func neutralStringCall(m *sourceModule, call *sitter.Node) bool {
	if call == nil || call.Kind() != "call_expression" {
		return false
	}
	fn := call.ChildByFieldName("function")
	if fn == nil || fn.Kind() != "member_expression" {
		return false
	}
	prop := fn.ChildByFieldName("property")
	if prop == nil {
		return false
	}
	switch prop.Utf8Text(m.src) {
	case "join", "toString", "trim":
		return true
	}
	return false
}

// versionBefore compares an exact x.y.z version; a range establishes nothing.
func versionBefore(version string, major, minor, patch int) bool {
	var a, b, c int
	if n, err := fmt.Sscanf(version, "%d.%d.%d", &a, &b, &c); n != 3 || err != nil || fmt.Sprintf("%d.%d.%d", a, b, c) != version {
		return false
	}
	if a != major {
		return a < major
	}
	if b != minor {
		return b < minor
	}
	return c < patch
}

// handlebarsSafeString reports a verified Handlebars SafeString construction on a
// path. Handlebars emits SafeString content without escaping, even in {{...}}.
func (f *flow) handlebarsSafeString(dependency analysis.Dependency) bool {
	for _, transfer := range dependency.Transfers {
		m := f.set.modules[transfer.Span.File]
		if m == nil || !strings.HasPrefix(transfer.Text, "new ") {
			continue
		}
		n := nodeAt(m.tree.RootNode(), transfer.Span.StartByte, transfer.Span.EndByte)
		if n == nil || n.Kind() != "new_expression" {
			continue
		}
		parts := strings.Split(n.ChildByFieldName("constructor").Utf8Text(m.src), ".")
		if len(parts) < 2 || parts[len(parts)-1] != "SafeString" || shadowed(n, parts[0], m.src) || bindingReassigned(m, parts[0]) {
			continue
		}
		imp, ok := m.imports[parts[0]]
		if ok && ((imp.module == "handlebars" && len(parts) == 2) || (imp.module == "hbs" && len(parts) == 3 && parts[1] == "handlebars")) {
			return true
		}
	}
	return false
}

// regexReplaceMode classifies x.replace(/re/g, literal). "allowlist": a global
// negated class whose kept characters are only word characters, digits, underscores or
// hyphens, removing everything else. "neutral": the pattern can match only line
// breaks/tabs and the replacement adds nothing HTML-significant, so markup is
// preserved unchanged. Anything else is not modeled ("").
func regexReplaceMode(m *sourceModule, call *sitter.Node) string {
	if call == nil || call.Kind() != "call_expression" {
		return ""
	}
	fn, args := call.ChildByFieldName("function"), call.ChildByFieldName("arguments")
	if fn == nil || fn.Kind() != "member_expression" || args == nil || args.NamedChildCount() != 2 {
		return ""
	}
	if prop := fn.ChildByFieldName("property"); prop == nil || (prop.Utf8Text(m.src) != "replace" && prop.Utf8Text(m.src) != "replaceAll") {
		return ""
	}
	re, repl := args.NamedChild(0), args.NamedChild(1)
	replacement, ok := stringLiteral(repl, m.src)
	if re.Kind() != "regex" || !ok || strings.ContainsAny(replacement, htmlSignificant) {
		return ""
	}
	pattern, flags := "", ""
	if p := re.ChildByFieldName("pattern"); p != nil {
		pattern = p.Utf8Text(m.src)
	}
	if fl := re.ChildByFieldName("flags"); fl != nil {
		flags = fl.Utf8Text(m.src)
	}
	if !strings.Contains(flags, "g") {
		return ""
	}
	if allowlistPattern.MatchString(pattern) && replacement == "" {
		return "allowlist"
	}
	// Deleting matched tag fragments once can reassemble a tag from what remains.
	if strings.HasPrefix(pattern, "<") && len(pattern) > 1 && replacement == "" {
		return "strip_tags"
	}
	if lineBreakPattern.MatchString(pattern) {
		return "neutral"
	}
	return ""
}

var (
	allowlistPattern = regexp.MustCompile(`^\[\^(?:\\w|\\d|a-z|A-Z|0-9|_|-)+\][+*]?$`)
	lineBreakPattern = regexp.MustCompile(`^(?:[()|+*?]|\?:|\\[rntfv]|\[(?:\\[rntfv])+\])+$`)
)
