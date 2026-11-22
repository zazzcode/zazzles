package langphp

import (
	"path"
	"sort"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"gopkg.in/yaml.v3"
)

// symfonyUserProvider is one entity user provider of security.yaml: the
// entity class and the property that identifies a user (Symfony user
// providers, https://symfony.com/doc/6.4/security/user_providers.html).
type symfonyUserProvider struct {
	class, property string
	at              analysis.Evidence
}

// symfonySecurity is what the bounded YAML reader established from
// config/packages/security.yaml.
type symfonySecurity struct {
	providers map[string]symfonyUserProvider // name -> entity class and property
	read      bool
	unread    []analysis.Gap
	// doc is the parsed security.yaml mapping, exposed for the access reader.
	// The provider walk below is unchanged.
	doc    *yaml.Node
	source analysis.Evidence
	access *symfonyAccessConfig
}

// security reads the entity user providers once per project.
func (p *symfonyProject) security(s *phpSet) *symfonySecurity {
	if s.securityConfig == nil {
		s.securityConfig = map[*symfonyProject]*symfonySecurity{}
	}
	if cached := s.securityConfig[p]; cached != nil {
		return cached
	}
	out := &symfonySecurity{providers: map[string]symfonyUserProvider{}}
	file := path.Join(p.root, "config/packages/security.yaml")
	for _, g := range s.gaps {
		if g.Kind == "symfony_config_unread" && g.At.File == file {
			out.unread = append(out.unread, g)
		}
	}
	if config, ok := p.configs[file]; ok {
		out.read = true
		out.doc = config.value
		out.source = config.source
		providers := symfonyYAMLValue(symfonyYAMLValue(config.value, "security"), "providers")
		if providers != nil {
			for i := 0; i+1 < len(providers.Content); i += 2 {
				name := providers.Content[i].Value
				entity := symfonyYAMLValue(providers.Content[i+1], "entity")
				class, property := symfonyYAMLValue(entity, "class"), symfonyYAMLValue(entity, "property")
				if symfonyYAMLString(class) == "" || symfonyYAMLString(property) == "" {
					continue
				}
				at := symfonyYAMLOrigin(config.source, property)
				at.Kind = "user_provider_property"
				out.providers[name] = symfonyUserProvider{class: symfonyYAMLString(class), property: symfonyYAMLString(property), at: at}
			}
		}
	}
	s.securityConfig[p] = out
	return out
}

// sortedProviders returns provider names in stable order.
func (c *symfonySecurity) sortedProviders() []string {
	names := make([]string, 0, len(c.providers))
	for name := range c.providers {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
