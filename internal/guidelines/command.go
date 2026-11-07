package guidelines

import (
	"embed"
	"fmt"
	"strings"

	"github.com/zazzcode/zazzles/internal/lang"
)

// The command documents are embedded separately and are deliberately not part of
// the default language pack, so adding the family changes no existing request.
//
//go:embed command_javascript.md command_python.md
var commandFiles embed.FS

// commandSections are required, exactly once, in every command document.
var commandSections = []string{"Posture", "Shell syntax", "Executable", "Arguments", "Protection coverage", "Do not claim"}

// CommandBody returns the validated command guidance for one language.
func CommandBody(language lang.Language) (AnalysisGuidelines, error) {
	name := "command_javascript.md"
	switch language {
	case lang.JavaScript, lang.TypeScript:
	case lang.Python:
		name = "command_python.md"
	default:
		return AnalysisGuidelines{}, fmt.Errorf("no command guidelines for %s", language)
	}
	raw, err := commandFiles.ReadFile(name)
	if err != nil {
		return AnalysisGuidelines{}, err
	}
	item, err := parse(string(raw))
	if err != nil {
		return AnalysisGuidelines{}, fmt.Errorf("%s: %w", name, err)
	}
	if err := validateCommandSections(item.Body); err != nil {
		return AnalysisGuidelines{}, fmt.Errorf("%s: %w", name, err)
	}
	return item, nil
}

// validateCommandSections rejects a missing or duplicated required section.
func validateCommandSections(body string) error {
	counts := map[string]int{}
	for _, section := range strings.Split(body, "\n## ")[1:] {
		title, _, _ := strings.Cut(section, "\n")
		counts[title]++
	}
	for _, want := range commandSections {
		if counts[want] != 1 {
			return fmt.Errorf("required command guidance section %q appears %d times", want, counts[want])
		}
	}
	return nil
}
