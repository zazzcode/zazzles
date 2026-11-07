package guidelines

import (
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/internal/lang"
)

func TestCommandGuidanceIdentityAndSections(t *testing.T) {
	for language, id := range map[lang.Language]string{lang.JavaScript: "zazzles.command.javascript", lang.TypeScript: "zazzles.command.javascript", lang.Python: "zazzles.command.python"} {
		g, err := CommandBody(language)
		if err != nil || g.ID != id || g.Version != "1" {
			t.Fatalf("%s: %+v %v", language, g, err)
		}
	}
	// Command guidance must not enter the default language selection.
	for _, language := range []lang.Language{lang.JavaScript, lang.Python} {
		g, _ := ForLanguage(language)
		if strings.HasPrefix(g.ID, "zazzles.command") {
			t.Fatalf("command document leaked into default selection: %s", g.ID)
		}
	}
}

func TestCommandGuidanceRejectsMissingOrDuplicateSection(t *testing.T) {
	g, _ := CommandBody(lang.Python)
	if err := validateCommandSections(strings.Replace(g.Body, "\n## Executable", "\n## Renamed", 1)); err == nil {
		t.Fatal("missing section accepted")
	}
	if err := validateCommandSections(g.Body + "\n## Posture\nagain"); err == nil {
		t.Fatal("duplicate section accepted")
	}
}
