package parse

import (
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"strings"
)

// RenderMarkup supplies the actual surrounding markup, not just the interpolated
// expression. Bounds limit context size without claiming the slice is a full DOM.
func RenderMarkup(file analysis.Evidence, start, end int) analysis.Evidence {
	before := file.Text[:start]
	left := strings.LastIndex(before, "\n") + 1
	tag, closed := strings.LastIndex(before, "<"), strings.LastIndex(before, ">")
	if tag > closed && tag < left {
		left = tag
	}
	right := len(file.Text)
	if newline := strings.Index(file.Text[end:], "\n"); newline >= 0 {
		right = end + newline
	}
	if left < start-1024 {
		left = start - 1024
	}
	if right > end+1024 {
		right = end + 1024
	}
	return TextRange(file, left, right, "render_markup_context")
}
