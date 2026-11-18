package langphp

import (
	"encoding/json"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/zazzcode/zazzles/internal/analysis"
)

// phpProjectInputs is a source-only subset of Composer and service wiring.
// Unsupported configuration is retained as an explicit resolution reason.
type phpProjectInputs struct {
	composerSpan analysis.Span
	psr4         map[string][]string
	services     map[string]phpServiceInput
	resources    []phpResourceInput
	invalid      string
}
type phpServiceInput struct {
	class, alias string
	at           analysis.Span
}
type phpResourceInput struct {
	prefix, dir string
	at          analysis.Span
}
type yamlScalar struct {
	value string
	line  int
}
type yamlBlock struct {
	key    string
	line   int
	values map[string]yamlScalar
}

// serviceBlocks intentionally accepts only block maps of scalar values. A
// rejected file contributes no guessed mappings, even from its valid prefix.
func serviceBlocks(src []byte) ([]yamlBlock, bool) {
	var blocks []yamlBlock
	inServices := false
	for i, line := range strings.Split(string(src), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.ContainsAny(line, "\t{}[]&*!|>") {
			return nil, false
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		colon := strings.Index(trimmed, ":")
		if colon < 0 {
			return nil, false
		}
		// A quoted service ID may itself contain a colon.
		if trimmed[0] == '\'' || trimmed[0] == '"' {
			end := strings.IndexByte(trimmed[1:], trimmed[0])
			if end < 0 {
				return nil, false
			}
			colon = end + 2
			if colon >= len(trimmed) || trimmed[colon] != ':' {
				return nil, false
			}
		}
		key, ok := yamlText(strings.TrimSpace(trimmed[:colon]))
		if !ok {
			return nil, false
		}
		value := strings.TrimSpace(trimmed[colon+1:])
		if indent == 0 {
			if key != "services" || value != "" {
				return nil, false
			}
			if inServices {
				return nil, false
			}
			inServices = true
			continue
		}
		if !inServices {
			return nil, false
		}
		if indent == 2 {
			if value != "" {
				return nil, false
			}
			for _, b := range blocks {
				if b.key == key {
					return nil, false
				}
			}
			blocks = append(blocks, yamlBlock{key: key, line: i + 1, values: map[string]yamlScalar{}})
			continue
		}
		if indent != 4 || len(blocks) == 0 || value == "" {
			return nil, false
		}
		value, ok = yamlText(value)
		if !ok {
			return nil, false
		}
		b := &blocks[len(blocks)-1]
		if _, exists := b.values[key]; exists {
			return nil, false
		}
		b.values[key] = yamlScalar{value, i + 1}
	}
	return blocks, inServices
}
func yamlText(s string) (string, bool) {
	if s == "" {
		return "", false
	}
	if s[0] == '\'' || s[0] == '"' {
		if len(s) < 2 || s[len(s)-1] != s[0] {
			return "", false
		}
		// Backslashes in single quotes are literal, as used by PHP service IDs.
		if s[0] == '"' && strings.Contains(s, "\\") {
			return "", false
		}
		return s[1 : len(s)-1], true
	}
	if strings.ContainsAny(s, "#'\"") {
		return "", false
	}
	return s, true
}
func safePHPPath(p string) bool {
	return p != "" && !path.IsAbs(p) && !strings.Contains(p, "\\") && path.Clean(p) != ".." && !strings.HasPrefix(path.Clean(p), "../")
}
func (s *phpSet) projectInputs() *phpProjectInputs {
	if s.project != nil {
		return s.project
	}
	p := &phpProjectInputs{psr4: map[string][]string{}, services: map[string]phpServiceInput{}}
	s.project = p
	composerPath := filepath.Join(s.root, "composer.json")
	if info, err := os.Lstat(composerPath); err == nil && !info.Mode().IsRegular() {
		p.invalid = "unsafe_composer"
		return p
	}
	src, err := os.ReadFile(composerPath)
	if err == nil {
		p.composerSpan = analysis.Span{File: "composer.json", StartLine: 1, EndLine: strings.Count(string(src), "\n") + 1, EndByte: len(src)}
		var composer struct {
			Autoload struct {
				PSR4 map[string]json.RawMessage `json:"psr-4"`
			} `json:"autoload"`
		}
		if len(src) > 1<<20 || json.Unmarshal(src, &composer) != nil {
			p.invalid = "invalid_composer"
		} else {
			for prefix, raw := range composer.Autoload.PSR4 {
				var dirs []string
				var dir string
				if json.Unmarshal(raw, &dir) == nil {
					dirs = []string{dir}
				} else if json.Unmarshal(raw, &dirs) != nil {
					p.invalid = "invalid_psr4"
					continue
				}
				for _, d := range dirs {
					if !safePHPPath(d) {
						p.invalid = "unsafe_path"
					}
				}
				if prefix != "" && !strings.HasSuffix(prefix, "\\") {
					p.invalid = "invalid_psr4"
				}
				p.psr4[prefix] = dirs
			}
		}
	} else if !os.IsNotExist(err) {
		p.invalid = "unreadable_composer"
	}
	// Service files are inventory inputs, never executed. Skip dependency/cache
	// trees, and never follow symlinks outside the scan root.
	var files []string
	filepath.WalkDir(s.root, func(file string, d os.DirEntry, err error) error {
		if err != nil {
			p.invalid = "unreadable_config"
			return nil
		}
		if d.IsDir() {
			if file != s.root && (strings.HasPrefix(d.Name(), ".") || d.Name() == "vendor" || d.Name() == "node_modules" || d.Name() == "var") {
				return filepath.SkipDir
			}
			return nil
		}
		rel, _ := filepath.Rel(s.root, file)
		rel = filepath.ToSlash(rel)
		if rel == "services.yaml" || rel == "config/services.yaml" || strings.HasSuffix(rel, ".services.yml") {
			files = append(files, rel)
		}
		return nil
	})
	sort.Strings(files)
	for _, file := range files {
		info, err := os.Lstat(filepath.Join(s.root, filepath.FromSlash(file)))
		if err != nil || !info.Mode().IsRegular() {
			p.invalid = "unsafe_config"
			continue
		}
		src, err := os.ReadFile(filepath.Join(s.root, filepath.FromSlash(file)))
		if err != nil || len(src) > 1<<20 {
			p.invalid = "unreadable_config"
			continue
		}
		blocks, ok := serviceBlocks(src)
		if !ok {
			p.invalid = "unsupported_yaml"
			continue
		}
		autowire := false
		for _, b := range blocks {
			if b.key == "_defaults" {
				for k, v := range b.values {
					if k != "autowire" || v.value != "true" {
						p.invalid = "unsupported_yaml"
					} else {
						autowire = true
					}
				}
			}
		}
		for _, b := range blocks {
			if b.key == "_defaults" {
				continue
			}
			at := analysis.Span{File: file, StartLine: b.line, EndLine: b.line}
			entry := phpServiceInput{at: at}
			for k, v := range b.values {
				switch k {
				case "class":
					entry.class = strings.TrimPrefix(v.value, "\\")
				case "alias":
					entry.alias = strings.TrimPrefix(v.value, "@")
				case "resource":
					dir := path.Join(path.Dir(file), v.value)
					if path.IsAbs(v.value) || strings.Contains(v.value, "\\\\") || !autowire || !safePHPPath(dir) || !strings.HasSuffix(b.key, "\\") {
						p.invalid = "unsupported_resource"
					} else {
						p.resources = append(p.resources, phpResourceInput{b.key, dir, at})
					}
				case "autowire":
					if v.value != "true" {
						p.invalid = "unsupported_yaml"
					}
				default:
					p.invalid = "unsupported_yaml"
				}
			}
			if entry.class != "" && entry.alias != "" {
				p.invalid = "conflicting_service"
			}
			if entry.class == "" && entry.alias == "" {
				continue
			}
			if _, exists := p.services[b.key]; exists {
				p.invalid = "ambiguous_service"
			} else {
				p.services[b.key] = entry
			}
		}
	}
	return p
}
