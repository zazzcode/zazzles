package parse

import (
	"regexp"
	"strings"

	"github.com/zazzcode/zazzles/internal/analysis"
)

var simpleTemplateField = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*$`)

func textRange(e analysis.Evidence, start, end int, kind string) analysis.Evidence {
	before, part := e.Text[:start], e.Text[start:end]
	e.Kind = kind
	e.Span.StartByte, e.Span.EndByte = start, end
	e.Span.StartLine = strings.Count(before, "\n") + 1
	e.Span.EndLine = e.Span.StartLine + strings.Count(part, "\n")
	e.Text = part
	return e
}
