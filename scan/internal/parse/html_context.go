package parse

import (
	"regexp"
	"strings"
)

var htmlAttribute = regexp.MustCompile(`(?i)([a-z_:][a-z0-9_:.-]*)\s*=\s*(["']?)[^"']*$`)

// HTMLOutputContext classifies the HTML output context that follows prefix.
func HTMLOutputContext(prefix string) string {
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

var (
	htmlAttributeValue = regexp.MustCompile(`(?i)([a-z_:][a-z0-9_:.-]*)\s*=\s*(["']?)([^"']*)$`)
	htmlTagName        = regexp.MustCompile(`^<\s*([A-Za-z][A-Za-z0-9-]*)`)
)

// HTMLAttributeValue describes the attribute value that prefix ends inside:
// its element, attribute name, quote character and the literal text the value
// already holds. ok is false outside a tag's attribute value.
func HTMLAttributeValue(prefix string) (tag, attribute, quote, value string, ok bool) {
	open := strings.LastIndex(prefix, "<")
	if open < 0 || open < strings.LastIndex(prefix, ">") {
		return "", "", "", "", false
	}
	match := htmlAttributeValue.FindStringSubmatch(prefix[open:])
	name := htmlTagName.FindStringSubmatch(prefix[open:])
	if len(match) == 0 || len(name) == 0 {
		return "", "", "", "", false
	}
	return strings.ToLower(name[1]), strings.ToLower(match[1]), match[2], match[3], true
}
