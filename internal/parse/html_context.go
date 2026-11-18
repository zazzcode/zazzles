package parse

import (
	"regexp"
	"strings"
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
