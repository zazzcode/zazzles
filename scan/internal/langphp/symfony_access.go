package langphp

import (
	"path"
	"strings"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"gopkg.in/yaml.v3"
)

// accessRule is one security.access_control item, in file order.
type accessRule struct {
	routeName      string
	pattern        *accessPattern
	roles, methods []string
	unmodeled      []string
	at             analysis.Evidence
}

type accessPattern struct {
	alts          []string
	anchored, end bool
}

type accessFirewall struct {
	open           bool
	pattern        *accessPattern
	at             analysis.Evidence
	authenticators []analysis.Evidence
}

type symfonyAccessConfig struct {
	rules         []accessRule
	firewalls     []accessFirewall
	roleMentions  map[string]bool
	roleHierarchy analysis.Evidence
}

// accessFor evaluates access_control the way Symfony does: first match wins.
// Attributes are applied by applyAccessAttributes.
func (p *symfonyProject) accessFor(s *phpSet, r symfonyRoute, method string) analysis.EntryAccess {
	sec := p.security(s)
	if !sec.read {
		gap := analysis.Gap{Kind: "symfony_config_unread", Detail: "security.yaml is absent or unreadable", At: analysis.Span{File: p.securityFile(), StartLine: 1}}
		if len(sec.unread) > 0 {
			gap = sec.unread[0]
		}
		return analysis.EntryAccess{Authentication: analysis.AccessUnresolved, Gaps: []analysis.Gap{gap}, Sources: []analysis.Evidence{}}
	}
	config := sec.accessConfig()
	prefix, placeholder := routeStaticPrefix(r.path)
	if fw, matched, decided := config.matchOpenFirewall(prefix, placeholder); !decided {
		return analysis.EntryAccess{Authentication: analysis.AccessUnresolved, Gaps: []analysis.Gap{{Kind: "access_rule_unresolved", Detail: "Firewall pattern is not in the supported expression subset", At: fw.Span}}, Sources: []analysis.Evidence{fw}}
	} else if matched {
		return analysis.EntryAccess{Authentication: analysis.AccessNone, Sources: []analysis.Evidence{fw}}
	}
	base := config.matchAccessRules(sec.source, r, method, prefix, placeholder)
	base = config.attachFirewallEvidence(base, prefix, placeholder)
	base = config.attachRoleHierarchy(base)
	return base
}

func (p *symfonyProject) securityFile() string {
	return path.Join(p.root, "config/packages/security.yaml")
}

func (c *symfonyAccessConfig) matchAccessRules(source analysis.Evidence, r symfonyRoute, method, prefix string, placeholder bool) analysis.EntryAccess {
	for _, rule := range c.rules {
		match, decided := rule.matches(r.name, prefix, placeholder)
		if !decided {
			return analysis.EntryAccess{Authentication: analysis.AccessUnresolved, Gaps: []analysis.Gap{{Kind: "access_rule_unresolved", Detail: "Access rule path is not in the supported expression subset", At: rule.at.Span}}, Sources: []analysis.Evidence{rule.at}}
		}
		if !match {
			continue
		}
		if len(rule.unmodeled) > 0 {
			return analysis.EntryAccess{Authentication: analysis.AccessUnresolved, Gaps: []analysis.Gap{{Kind: "access_rule_condition_unmodeled", Detail: "Access rule condition is not modeled: " + strings.Join(rule.unmodeled, ", "), At: rule.at.Span}}, Sources: []analysis.Evidence{rule.at}}
		}
		if !accessMethodsMatch(rule.methods, method) {
			continue
		}
		return accessFromRoles(rule.roles, rule.at)
	}
	at := source
	at.Kind = "access_rule"
	at.Text = "no rule matched"
	return analysis.EntryAccess{Authentication: analysis.AccessNone, Sources: []analysis.Evidence{at}}
}

func accessFromRoles(roles []string, at analysis.Evidence) analysis.EntryAccess {
	var listed []string
	public := true
	for _, role := range roles {
		if role == "PUBLIC_ACCESS" || role == "IS_AUTHENTICATED_ANONYMOUSLY" {
			continue
		}
		public = false
		listed = append(listed, role)
	}
	at.Kind = "access_rule"
	if public {
		return analysis.EntryAccess{Authentication: analysis.AccessNone, Sources: []analysis.Evidence{at}}
	}
	return analysis.EntryAccess{Authentication: analysis.AccessRequired, Roles: listed, Sources: []analysis.Evidence{at}}
}

func (rule accessRule) matches(routeName, prefix string, placeholder bool) (bool, bool) {
	if rule.routeName != "" && rule.routeName != routeName {
		return false, true
	}
	if rule.pattern == nil {
		match := rule.routeName != ""
		return match, match
	}
	return rule.pattern.matches(prefix, placeholder)
}

func accessMethodsMatch(methods []string, entry string) bool {
	if len(methods) == 0 || entry == "" {
		return true
	}
	for _, m := range methods {
		if strings.EqualFold(m, entry) {
			return true
		}
	}
	return false
}

func (sec *symfonySecurity) accessConfig() *symfonyAccessConfig {
	if sec.access == nil {
		root := symfonyYAMLValue(sec.doc, "security")
		config := &symfonyAccessConfig{
			rules:     readAccessRules(root, sec.source),
			firewalls: readAccessFirewalls(root, sec.source),
		}
		if node := symfonyYAMLValue(root, "role_hierarchy"); node != nil && node.Kind == yaml.MappingNode {
			config.roleHierarchy = symfonyYAMLOrigin(sec.source, node)
			config.roleHierarchy.Kind = "role_hierarchy"
			config.roleMentions = map[string]bool{}
			for i := 0; i+1 < len(node.Content); i += 2 {
				config.roleMentions[node.Content[i].Value] = true
				for _, role := range symfonyYAMLStrings(node.Content[i+1]) {
					config.roleMentions[role] = true
				}
			}
		}
		sec.access = config
	}
	return sec.access
}

func readAccessRules(root *yaml.Node, source analysis.Evidence) []accessRule {
	list := symfonyYAMLValue(root, "access_control")
	if list == nil || list.Kind != yaml.SequenceNode {
		return nil
	}
	var out []accessRule
	for _, item := range list.Content {
		rule := accessRule{at: symfonyYAMLOrigin(source, item)}
		if pathNode := symfonyYAMLValue(item, "path"); pathNode != nil {
			if expr := symfonyYAMLString(pathNode); expr != "" {
				rule.pattern = compileAccessPattern(expr)
			}
			rule.at = symfonyYAMLOrigin(source, pathNode)
		}
		if routeNode := symfonyYAMLValue(item, "route"); routeNode != nil {
			rule.routeName = symfonyYAMLString(routeNode)
		}
		rule.roles = symfonyYAMLStrings(symfonyYAMLValue(item, "roles"))
		rule.methods = symfonyYAMLStrings(symfonyYAMLValue(item, "methods"))
		for _, key := range []string{"ips", "host", "port", "allow_if", "requires_channel", "request_matcher", "attributes"} {
			if symfonyYAMLValue(item, key) != nil {
				rule.unmodeled = append(rule.unmodeled, key)
			}
		}
		out = append(out, rule)
	}
	return out
}

func symfonyYAMLStrings(node *yaml.Node) []string {
	if node == nil {
		return nil
	}
	if node.Kind == yaml.ScalarNode {
		if node.Value == "" {
			return nil
		}
		return []string{node.Value}
	}
	if node.Kind != yaml.SequenceNode {
		return nil
	}
	var out []string
	for _, item := range node.Content {
		if item.Kind == yaml.ScalarNode && item.Value != "" {
			out = append(out, item.Value)
		}
	}
	return out
}

// routeStaticPrefix is the path up to its first placeholder.
func routeStaticPrefix(path string) (string, bool) {
	if i := strings.Index(path, "{"); i >= 0 {
		return path[:i], true
	}
	return path, false
}

func compileAccessPattern(expr string) *accessPattern {
	alts, anchored, end, _ := parseAccessExpr(expr)
	return &accessPattern{alts: alts, anchored: anchored, end: end}
}

// matches reports whether a supported path expression matches the
// route's static prefix. decided is false when the expression is outside the
// subset or the placeholder can change the answer (D-1).
func (p *accessPattern) matches(staticPrefix string, hasPlaceholder bool) (match, decided bool) {
	if p == nil {
		return true, true
	}
	if p.alts == nil {
		return false, false
	}
	undecided := false
	for _, alt := range p.alts {
		m, d := matchAccessLiteral(alt, p.anchored, p.end, staticPrefix, hasPlaceholder)
		if !d {
			undecided = true
			continue
		}
		if m {
			return true, true
		}
	}
	if undecided {
		return false, false
	}
	return false, true
}

func matchAccessLiteral(alt string, anchored, end bool, prefix string, hasPlaceholder bool) (bool, bool) {
	if !anchored {
		if hasPlaceholder {
			return false, false
		}
		return strings.Contains(prefix, alt), true
	}
	if !end {
		if strings.HasPrefix(prefix, alt) {
			return true, true
		}
		if strings.HasPrefix(alt, prefix) && prefix != alt && hasPlaceholder {
			return false, false
		}
		return false, true
	}
	if !hasPlaceholder {
		return prefix == alt, true
	}
	if strings.HasPrefix(alt, prefix) && len(alt) > len(prefix) {
		return false, false
	}
	return false, true
}

// parseAccessExpr accepts ^, literals, escapes, groups of literal alternatives
// (nested groups included when they too are only literals), and an optional $.
// Quantifiers, character classes and lookaheads are not decided.
func parseAccessExpr(expr string) (alts []string, anchored, end, ok bool) {
	if expr == "" {
		return nil, false, false, false
	}
	i := 0
	if expr[0] == '^' {
		anchored = true
		i = 1
	}
	if strings.HasSuffix(expr, "$") && !strings.HasSuffix(expr, `\$`) {
		end = true
		expr = expr[:len(expr)-1]
	}
	alts, pos, ok := parseAccessBody(expr, i)
	if !ok || pos != len(expr) {
		return nil, false, false, false
	}
	return alts, anchored, end, true
}

func parseAccessBody(expr string, i int) ([]string, int, bool) {
	alts := []string{""}
	for i < len(expr) {
		switch expr[i] {
		case '\\':
			if i+1 >= len(expr) {
				return nil, i, false
			}
			alts = appendLiteral(alts, expr[i+1])
			i += 2
		case '(':
			parts, next, ok := parseAccessGroup(expr, i+1)
			if !ok {
				return nil, i, false
			}
			alts = crossAccess(alts, parts)
			i = next
		case '.', '*', '+', '?', '[', ']', '{', '}', '|', '^', '$':
			return nil, i, false
		default:
			alts = appendLiteral(alts, expr[i])
			i++
		}
	}
	return alts, i, true
}

func parseAccessGroup(expr string, i int) ([]string, int, bool) {
	var parts []string
	current := []string{""}
	for i < len(expr) {
		switch expr[i] {
		case ')':
			parts = append(parts, current...)
			if len(parts) < 2 {
				return nil, i, false
			}
			return parts, i + 1, true
		case '|':
			parts = append(parts, current...)
			current = []string{""}
			i++
		case '(':
			nested, next, ok := parseAccessGroup(expr, i+1)
			if !ok {
				return nil, i, false
			}
			current = crossAccess(current, nested)
			i = next
		case '\\':
			if i+1 >= len(expr) {
				return nil, i, false
			}
			current = appendLiteral(current, expr[i+1])
			i += 2
		case '.', '*', '+', '?', '[', ']', '{', '}', '^', '$':
			return nil, i, false
		default:
			current = appendLiteral(current, expr[i])
			i++
		}
	}
	return nil, i, false
}

func crossAccess(base, extra []string) []string {
	var out []string
	for _, a := range base {
		for _, b := range extra {
			out = append(out, a+b)
		}
	}
	return out
}

func appendLiteral(alts []string, c byte) []string {
	for i := range alts {
		alts[i] += string(c)
	}
	return alts
}

func readAccessFirewalls(root *yaml.Node, source analysis.Evidence) []accessFirewall {
	firewalls := symfonyYAMLValue(root, "firewalls")
	if firewalls == nil || firewalls.Kind != yaml.MappingNode {
		return nil
	}
	var out []accessFirewall
	for i := 0; i+1 < len(firewalls.Content); i += 2 {
		node := firewalls.Content[i+1]
		fw := accessFirewall{open: symfonyYAMLString(symfonyYAMLValue(node, "security")) == "false"}
		origin := node
		if pattern := symfonyYAMLValue(node, "pattern"); pattern != nil {
			fw.pattern = compileAccessPattern(symfonyYAMLString(pattern))
			origin = pattern
		}
		if fw.open {
			fw.at = symfonyYAMLOrigin(source, origin)
			fw.at.Kind = "firewall"
		} else {
			for _, key := range []string{"form_login", "http_basic", "json_login", "custom_authenticators"} {
				if auth := symfonyYAMLValue(node, key); auth != nil {
					at := symfonyYAMLOrigin(source, auth)
					at.Kind, at.Text = "firewall_authenticator", key
					fw.authenticators = append(fw.authenticators, at)
				}
			}
		}
		out = append(out, fw)
	}
	return out
}

func (c *symfonyAccessConfig) matchOpenFirewall(prefix string, placeholder bool) (analysis.Evidence, bool, bool) {
	for _, fw := range c.firewalls {
		if !fw.open {
			continue
		}
		if match, decided := fw.pattern.matches(prefix, placeholder); !decided || match {
			return fw.at, match, decided
		}
	}
	return analysis.Evidence{}, false, true
}

func (c *symfonyAccessConfig) attachFirewallEvidence(base analysis.EntryAccess, prefix string, placeholder bool) analysis.EntryAccess {
	if base.Authentication == analysis.AccessUnresolved {
		return base
	}
	for _, fw := range c.firewalls {
		if fw.open {
			continue
		}
		if match, decided := fw.pattern.matches(prefix, placeholder); !decided || !match {
			continue
		}
		for _, at := range fw.authenticators {
			base.Sources = append(base.Sources, at)
			if at.Text == "custom_authenticators" {
				base.Authentication = analysis.AccessUnresolved
				base.Gaps = append(base.Gaps, analysis.Gap{Kind: "authenticator_unmodeled", Detail: "Custom authenticators are not modeled", At: at.Span})
			}
		}
		break
	}
	return base
}

func (c *symfonyAccessConfig) attachRoleHierarchy(base analysis.EntryAccess) analysis.EntryAccess {
	if base.Authentication != analysis.AccessRequired {
		return base
	}
	for _, role := range base.Roles {
		if c.roleMentions[role] {
			base.Sources = append(base.Sources, c.roleHierarchy)
			break
		}
	}
	return base
}
