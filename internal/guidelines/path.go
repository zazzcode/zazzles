package guidelines

import (
	"embed"
	"fmt"
	"strings"

	"github.com/zazzcode/zazzles/internal/lang"
)

// The path documents are embedded separately and are deliberately not part of
// the default language pack, so adding the family changes no existing request.
//
//go:embed path_javascript.md path_python.md
var pathFiles embed.FS

// pathSections are required, exactly once, in every path document.
var pathSections = []string{"Posture", "Operations", "Containment", "Symbolic links and platform", "Protection coverage", "Do not claim"}

// PathBody returns the validated path-traversal guidance for one language.
func PathBody(language lang.Language) (AnalysisGuidelines, error) {
	name := "path_javascript.md"
	switch language {
	case lang.JavaScript, lang.TypeScript:
	case lang.Python:
		name = "path_python.md"
	default:
		return AnalysisGuidelines{}, fmt.Errorf("no path guidelines for %s", language)
	}
	raw, err := pathFiles.ReadFile(name)
	if err != nil {
		return AnalysisGuidelines{}, err
	}
	item, err := parse(string(raw))
	if err != nil {
		return AnalysisGuidelines{}, fmt.Errorf("%s: %w", name, err)
	}
	if err := validatePathSections(item.Body); err != nil {
		return AnalysisGuidelines{}, fmt.Errorf("%s: %w", name, err)
	}
	return item, nil
}

// validatePathSections rejects a missing or duplicated required section.
func validatePathSections(body string) error {
	counts := map[string]int{}
	for _, section := range strings.Split(body, "\n## ")[1:] {
		title, _, _ := strings.Cut(section, "\n")
		counts[title]++
	}
	for _, want := range pathSections {
		if counts[want] != 1 {
			return fmt.Errorf("required path guidance section %q appears %d times", want, counts[want])
		}
	}
	return nil
}
