package langphp

import (
	"path"
	"sort"
	"strings"

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

// symfonyPasswordHasherConfig is one entry of security.password_hashers: a
// fixed algorithm or a hasher service id, with the line that sets it
// (https://symfony.com/doc/6.4/security/passwords.html).
type symfonyPasswordHasherConfig struct {
	algorithm, id string
	at            analysis.Evidence
}

// passwordHashers reads security.password_hashers in file order. A scalar
// value is the algorithm.
func (c *symfonySecurity) passwordHashers() []symfonyPasswordHasherConfig {
	var out []symfonyPasswordHasherConfig
	hashers := symfonyYAMLValue(symfonyYAMLValue(c.doc, "security"), "password_hashers")
	if hashers == nil || hashers.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(hashers.Content); i += 2 {
		value := hashers.Content[i+1]
		node, h := value, symfonyPasswordHasherConfig{}
		switch value.Kind {
		case yaml.ScalarNode:
			h.algorithm = strings.ToLower(value.Value)
		case yaml.MappingNode:
			if a := symfonyYAMLValue(value, "algorithm"); symfonyYAMLString(a) != "" {
				node, h.algorithm = a, strings.ToLower(symfonyYAMLString(a))
			} else if id := symfonyYAMLValue(value, "id"); symfonyYAMLString(id) != "" {
				node, h.id = id, symfonyYAMLString(id)
			}
		}
		if h.algorithm == "" && h.id == "" {
			continue
		}
		h.at = symfonyYAMLOrigin(c.source, node)
		h.at.Kind = "password_hasher_config"
		out = append(out, h)
	}
	return out
}

// loginRoute is the route a firewall's form_login or json_login checks:
// check_path, else login_path, of the first firewall in file order.
func (c *symfonySecurity) loginRoute() string {
	firewalls := symfonyYAMLValue(symfonyYAMLValue(c.doc, "security"), "firewalls")
	if firewalls == nil || firewalls.Kind != yaml.MappingNode {
		return ""
	}
	for i := 0; i+1 < len(firewalls.Content); i += 2 {
		for _, key := range []string{"form_login", "json_login"} {
			login := symfonyYAMLValue(firewalls.Content[i+1], key)
			if login == nil {
				continue
			}
			if check := symfonyYAMLString(symfonyYAMLValue(login, "check_path")); check != "" {
				return check
			}
			if path := symfonyYAMLString(symfonyYAMLValue(login, "login_path")); path != "" {
				return path
			}
		}
	}
	return ""
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
