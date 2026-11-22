package langphp

import (
	"encoding/json"
	"path"
	"strings"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"gopkg.in/yaml.v3"
)

type symfonyProject struct {
	root, docRoot string
	configs       map[string]symfonyConfig
	psr4          map[string][]string
	composerSpan  analysis.Span
	legacyInputs  *phpProjectInputs
}

type symfonyConfig struct {
	source analysis.Evidence
	value  *yaml.Node
}

func (s *phpSet) loadSymfonyProjects(files []string) {
	s.composers = map[string]*symfonyProject{}
	for _, file := range files {
		if path.Base(file) != "composer.json" {
			continue
		}
		base := path.Dir(file)
		s.composers[base] = nil
		evidence, ok := readSymfonyConfig(s.root, file)
		if !ok {
			continue
		}
		var manifest struct {
			Require map[string]json.RawMessage `json:"require"`
			Extra   struct {
				PublicDir string `json:"public-dir"`
			} `json:"extra"`
			Autoload struct {
				PSR4 map[string]json.RawMessage `json:"psr-4"`
			} `json:"autoload"`
		}
		if json.Unmarshal([]byte(evidence.Text), &manifest) != nil {
			continue
		}
		if _, ok := manifest.Require["symfony/framework-bundle"]; !ok {
			continue
		}
		project := &symfonyProject{root: base, docRoot: path.Join(base, "public"), configs: map[string]symfonyConfig{}, psr4: map[string][]string{}, composerSpan: evidence.Span}
		if dir := manifest.Extra.PublicDir; dir != "" && safePHPPath(dir) {
			project.docRoot = path.Join(base, dir)
		}
		for prefix, raw := range manifest.Autoload.PSR4 {
			var one string
			var dirs []string
			if json.Unmarshal(raw, &one) == nil {
				dirs = []string{one}
			} else if json.Unmarshal(raw, &dirs) != nil {
				continue
			}
			for _, dir := range dirs {
				if safePHPPath(dir) {
					project.psr4[prefix] = append(project.psr4[prefix], path.Join(base, dir))
				}
			}
		}
		s.composers[base] = project
		s.symfony = append(s.symfony, project)
	}
	for _, file := range files {
		project := s.symfonyProjectOf(file)
		if project == nil || path.Ext(file) != ".yaml" {
			continue
		}
		source, read := readSymfonyConfig(s.root, file)
		if read {
			if value, parsed := symfonyYAML(source.Text); parsed {
				project.configs[file] = symfonyConfig{source: source, value: value}
				continue
			}
		}
		s.gaps = append(s.gaps, analysis.Gap{Kind: "symfony_config_unread", Detail: "Symfony configuration is unsafe, oversized, or invalid", At: analysis.Span{File: file, StartLine: 1}})
	}
}

func (s *phpSet) symfonyProjectOf(file string) *symfonyProject {
	for dir := path.Dir(file); ; dir = path.Dir(dir) {
		if p, ok := s.composers[dir]; ok {
			return p
		}
		if dir == "." {
			return nil
		}
	}
}

func (s *phpSet) symfonyCacheFile(file string) bool {
	for _, p := range s.symfony {
		if strings.HasPrefix(file, path.Join(p.root, "var")+"/") {
			return true
		}
	}
	return false
}

func (s *phpSet) fileMapped(file string) bool {
	p := s.symfonyProjectOf(file)
	return p == nil || p.docRoot == "." || strings.HasPrefix(file, p.docRoot+"/")
}

type symfonyParam struct {
	literal       string
	configuration bool
	at            analysis.Span
}

func (p *symfonyProject) parameter(name string) (symfonyParam, bool) {
	config, found := p.configs[path.Join(p.root, "config/services.yaml")]
	if !found || config.value.Kind != yaml.MappingNode {
		return symfonyParam{}, false
	}
	base := symfonyYAMLValue(symfonyYAMLValue(config.value, "parameters"), name)
	for i := 0; i+1 < len(config.value.Content); i += 2 {
		key, value := config.value.Content[i], config.value.Content[i+1]
		if !strings.HasPrefix(key.Value, "when@") {
			continue
		}
		alternate := symfonyYAMLValue(symfonyYAMLValue(value, "parameters"), name)
		if alternate != nil && (base == nil || base.Value != alternate.Value || base.Tag != alternate.Tag || base.Kind != alternate.Kind) {
			return symfonyParam{configuration: true, at: symfonyYAMLOrigin(config.source, alternate).Span}, true
		}
	}
	if base == nil || base.ShortTag() != "!!str" || base.Kind != yaml.ScalarNode {
		return symfonyParam{}, false
	}
	at := symfonyYAMLOrigin(config.source, base).Span
	value := base.Value
	if strings.Contains(value, "%env(") {
		return symfonyParam{configuration: true, at: at}, true
	}
	const projectDir = "%kernel.project_dir%"
	if value == projectDir || strings.HasPrefix(value, projectDir+"/") {
		value = path.Join("/", p.root, strings.TrimPrefix(value, projectDir))
	}
	return symfonyParam{literal: value, at: at}, true
}

func (p *symfonyProject) servedPath(value string) bool {
	if !path.IsAbs(value) {
		return false
	}
	root := path.Join("/", p.docRoot)
	value = path.Clean(value)
	return value == root || root == "/" || strings.HasPrefix(value, root+"/")
}
