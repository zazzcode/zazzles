package parse

import (
	"regexp"
	"strings"

	"github.com/zazzcode/zazzles/internal/analysis"
)

var pythonScript = regexp.MustCompile(`(?is)<script\b([^>]*)>(.*?)</script\s*>`)
var pythonJQueryCDN = regexp.MustCompile(`(?i)\bsrc\s*=\s*["']https://code\.jquery\.com/jquery-[0-9]+\.[0-9]+\.[0-9]+(?:\.min)?\.js["']`)

// browserTemplates hands literal inline JavaScript to the browser adapter.
// Masking preserves the original file offsets, lines and snapshot hash.
func (s *pythonSet) browserTemplates(out *analysis.AnalysisReport) error {
	var scripts []InlineScript
	for _, file := range s.text.Files() {
		snapshot, _ := s.text.Get(file)
		matches := pythonScript.FindAllStringSubmatchIndex(snapshot.Text, -1)
		if len(matches) == 0 {
			continue
		}
		original := []byte(snapshot.Text)
		masked := make([]byte, len(original))
		for i, b := range original {
			masked[i] = ' '
			if b == '\n' || b == '\r' {
				masked[i] = b
			}
		}
		globals := map[string]analysis.Evidence{}
		hasScript := false
		firstInline := false
		for _, match := range matches {
			tag := snapshot.Text[match[2]:match[3]]
			if pythonJQueryCDN.MatchString(tag) && !firstInline {
				binding := textRange(snapshot, match[0], match[4], "render_binding")
				globals["$"] = binding
				globals["jQuery"] = binding
				continue
			}
			if strings.Contains(strings.ToLower(tag), "src=") || strings.Contains(strings.ToLower(tag), "src =") {
				continue
			}
			if strings.Contains(strings.ToLower(tag), "application/json") {
				continue
			}
			firstInline = true
			copy(masked[match[4]:match[5]], original[match[4]:match[5]])
			hasScript = true
		}
		if !hasScript {
			continue
		}
		scripts = append(scripts, InlineScript{File: file, Masked: masked, Globals: globals})
	}
	return AnalyzeInlineScripts(s.text, scripts, out)
}
