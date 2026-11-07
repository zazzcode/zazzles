package parse

import (
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
			mode = replacementMode(m, call)
		}
		if mode == "" && neutralStringCall(m, call) {
			mode = "neutral"
		}
		if mode == "neutral" {
			continue
		}
		if mode == "markdown" {
			if _, ok := f.set.bypassAdvisory("marked"); ok {
				mode = "ineffective"
			}
		}
		if mode == "sanitize_html" {
			mode = "sanitize"
			if _, ok := f.set.bypassAdvisory("sanitize-html"); ok {
				mode = "ineffective"
			}
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
		case "strip_tags":
			// Deleting tag fragments cannot reopen text that was already encoded.
			if protection == "raw" {
				protection = "ineffective"
			}
		case "delete_angles", "delete_angles_quotes":
			// Every < removed or encoded: no element can open in HTML text.
			switch {
			case context == "html_text", context == "html_attribute" && mode == "delete_angles_quotes":
				if protection == "raw" {
					protection = "sanitized"
				}
			default:
				protection = "unknown"
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

// replacementMode classifies x.replace / x.replaceAll by what the replacement removes:
//
//   - "allowlist": a global negated class keeping only word characters or hyphens.
//   - "neutral": only line breaks or tabs are matched.
//   - "delete_angles": every < is removed (or replaced by &lt;), so no element can
//     open in HTML text; "delete_angles_quotes" also removes both quote characters.
//   - "strip_tags": a deletion that can match a tag fragment but not every <. One pass
//     can reassemble a tag from what remains, as can a non-global deletion of any kind.
//
// A replacement that is not an empty or &lt; literal, or a pattern not understood
// here, is unknown (""): no protection is assumed and no bypass is claimed.
func replacementMode(m *sourceModule, call *sitter.Node) string {
	if call == nil || call.Kind() != "call_expression" {
		return ""
	}
	fn, args := call.ChildByFieldName("function"), call.ChildByFieldName("arguments")
	if fn == nil || fn.Kind() != "member_expression" || args == nil || args.NamedChildCount() != 2 {
		return ""
	}
	method := ""
	if prop := fn.ChildByFieldName("property"); prop != nil {
		method = prop.Utf8Text(m.src)
	}
	if method != "replace" && method != "replaceAll" {
		return ""
	}
	target, repl := args.NamedChild(0), args.NamedChild(1)
	replacement, ok := stringLiteral(repl, m.src)
	if !ok {
		return ""
	}
	encodesAngle := replacement == "&lt;"
	if replacement != "" && !encodesAngle {
		if strings.ContainsAny(replacement, htmlSignificant) {
			return ""
		}
		if target.Kind() == "regex" && lineBreakPattern.MatchString(regexPart(m, target, "pattern")) && strings.Contains(regexPart(m, target, "flags"), "g") {
			return "neutral"
		}
		return ""
	}
	global := method == "replaceAll"
	var removed charSet
	tagFragment := false
	if literal, ok := stringLiteral(target, m.src); ok {
		removed, ok = literalChars(literal)
		tagFragment = !ok && strings.Contains(literal, "<")
	} else if target.Kind() == "regex" {
		pattern, flags := regexPart(m, target, "pattern"), regexPart(m, target, "flags")
		global = global || strings.Contains(flags, "g")
		if global && replacement == "" && allowlistPattern.MatchString(pattern) {
			return "allowlist"
		}
		if global && replacement == "" && lineBreakPattern.MatchString(pattern) {
			return "neutral"
		}
		removed, ok = classChars(pattern)
		tagFragment = !ok && canStartWithAngle(pattern)
	} else {
		return ""
	}
	switch {
	case removed.lt && global && removed.dq && removed.sq && !encodesAngle:
		return "delete_angles_quotes"
	case removed.lt && global:
		return "delete_angles"
	case removed.lt || tagFragment:
		return "strip_tags"
	}
	return ""
}

type charSet struct{ lt, dq, sq bool }

func regexPart(m *sourceModule, re *sitter.Node, field string) string {
	if p := re.ChildByFieldName(field); p != nil {
		return p.Utf8Text(m.src)
	}
	return ""
}

// literalChars reads a literal of one character, which a global deletion removes entirely.
func literalChars(literal string) (charSet, bool) {
	if literal != "<" {
		return charSet{}, false
	}
	return charSet{lt: true}, true
}

// classChars reads a pattern that is a single character, or a non-negated class,
// optionally repeated: [<>"']+ or <.
func classChars(pattern string) (charSet, bool) {
	body := strings.TrimRight(pattern, "+*")
	if body == "<" || body == `\<` {
		return charSet{lt: true}, true
	}
	if len(body) < 3 || body[0] != '[' || body[len(body)-1] != ']' || body[1] == '^' {
		return charSet{}, false
	}
	inner := body[1 : len(body)-1]
	var set charSet
	for i := 0; i < len(inner); i++ {
		c := inner[i]
		if c == '\\' && i+1 < len(inner) {
			i++
			c = inner[i]
		} else if i+2 < len(inner) && inner[i+1] == '-' {
			return charSet{}, false // ranges are not interpreted
		}
		switch c {
		case '<':
			set.lt = true
		case '"':
			set.dq = true
		case '\'':
			set.sq = true
		}
	}
	return set, true
}

// canStartWithAngle reports a pattern with a top-level alternative that begins with
// a literal <, after leading anchors and group openers.
func canStartWithAngle(pattern string) bool {
	depth, start := 0, 0
	alternatives := []string{}
	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '\\':
			i++
		case '(':
			depth++
		case ')':
			depth--
		case '|':
			if depth <= 1 {
				alternatives = append(alternatives, pattern[start:i])
				start = i + 1
			}
		}
	}
	alternatives = append(alternatives, pattern[start:])
	for _, alt := range alternatives {
		for {
			trimmed := strings.TrimLeft(alt, "^(")
			trimmed = strings.TrimPrefix(trimmed, "?:")
			if trimmed == alt {
				break
			}
			alt = trimmed
		}
		if strings.HasPrefix(alt, "<") || strings.HasPrefix(alt, `\<`) || strings.HasPrefix(alt, `\x3c`) || strings.HasPrefix(alt, `\u003c`) {
			return true
		}
	}
	return false
}

var (
	allowlistPattern = regexp.MustCompile(`^\[\^(?:\\w|\\d|a-z|A-Z|0-9|_|-)+\][+*]?$`)
	lineBreakPattern = regexp.MustCompile(`^(?:[()|+*?]|\?:|\\[rntfv]|\[(?:\\[rntfv])+\])+$`)
)
