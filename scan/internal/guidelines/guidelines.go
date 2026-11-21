// Package guidelines embeds versioned language analysis guidelines supplied to the semantic judge.
// The files are embedded in the binary. .zazz standards are the SDLC for this
// repo and are not consulted here.
package guidelines

import (
	"embed"
	"fmt"
	"sort"
	"strings"

	"github.com/zazzcode/zazzles/scan/internal/lang"
)

//go:embed javascript.md python.md php.md go.md
var files embed.FS

// AnalysisGuidelines contains secure coding guidance and instructions for interpreting source evidence.
type AnalysisGuidelines struct {
	ID        string   `json:"id"`
	Version   string   `json:"version"`
	Languages []string `json:"languages"`
	Body      string   `json:"body"`
}

var pack []AnalysisGuidelines

func init() {
	names := []string{"javascript.md", "python.md", "php.md", "go.md"}
	for _, name := range names {
		raw, err := files.ReadFile(name)
		if err != nil {
			panic(err)
		}
		item, err := parse(string(raw))
		if err != nil {
			panic(name + ": " + err.Error())
		}
		pack = append(pack, item)
	}
}

func parse(raw string) (AnalysisGuidelines, error) {
	item := AnalysisGuidelines{Body: raw}
	for _, line := range strings.Split(raw, "\n") {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			break
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		switch key {
		case "id":
			item.ID = value
		case "version":
			item.Version = value
		case "languages":
			for _, part := range strings.Split(value, ",") {
				part = strings.TrimSpace(part)
				if part != "" {
					item.Languages = append(item.Languages, part)
				}
			}
		default:
			return item, nil
		}
	}
	if item.ID == "" || item.Version == "" || len(item.Languages) == 0 {
		return AnalysisGuidelines{}, fmt.Errorf("analysis guidelines file needs id, version, and languages")
	}
	return item, nil
}

// ForLanguage returns the analysis guidelines for a detected source language.
func ForLanguage(language lang.Language) (AnalysisGuidelines, bool) {
	for _, item := range pack {
		for _, name := range item.Languages {
			if name == string(language) {
				return item, true
			}
		}
	}
	return AnalysisGuidelines{}, false
}

// ForPaths returns each applicable guidelines document once, ordered by id.
func ForPaths(paths []string) []AnalysisGuidelines {
	seen := map[string]AnalysisGuidelines{}
	for _, path := range paths {
		language, ok := lang.Detect(path)
		if !ok {
			continue
		}
		item, ok := ForLanguage(language)
		if !ok {
			continue
		}
		seen[item.ID] = item
	}
	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]AnalysisGuidelines, 0, len(ids))
	for _, id := range ids {
		item := seen[id]
		item.Body = ""
		out = append(out, item)
	}
	return out
}

// Body returns the full guidelines document for a language, for the decision request.
func Body(language lang.Language) (AnalysisGuidelines, bool) {
	return ForLanguage(language)
}
