package guidelines

import (
	"embed"
	"fmt"
	"strings"

	"github.com/zazzcode/zazzles/scan/internal/lang"
)

// The SSRF documents are embedded separately and are not part of the default
// language pack, so adding the family changes no existing request.
//
//go:embed ssrf_javascript.md ssrf_python.md ssrf_php.md
var ssrfFiles embed.FS

// ssrfSections are required, exactly once, in every SSRF document.
var ssrfSections = []string{"Posture", "Operations", "Destination control", "Restriction", "Protection coverage", "Do not claim"}

// SSRFBody returns the validated server-side request forgery guidance for one language.
func SSRFBody(language lang.Language) (AnalysisGuidelines, error) {
	name := "ssrf_javascript.md"
	switch language {
	case lang.JavaScript, lang.TypeScript:
	case lang.Python:
		name = "ssrf_python.md"
	case lang.PHP:
		name = "ssrf_php.md"
	default:
		return AnalysisGuidelines{}, fmt.Errorf("no SSRF guidelines for %s", language)
	}
	raw, err := ssrfFiles.ReadFile(name)
	if err != nil {
		return AnalysisGuidelines{}, err
	}
	item, err := parse(string(raw))
	if err != nil {
		return AnalysisGuidelines{}, fmt.Errorf("%s: %w", name, err)
	}
	counts := map[string]int{}
	for _, section := range strings.Split(item.Body, "\n## ")[1:] {
		title, _, _ := strings.Cut(section, "\n")
		counts[title]++
	}
	for _, want := range ssrfSections {
		if counts[want] != 1 {
			return AnalysisGuidelines{}, fmt.Errorf("%s: required SSRF guidance section %q appears %d times", name, want, counts[want])
		}
	}
	return item, nil
}
