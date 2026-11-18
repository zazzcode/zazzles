package langjs

import (
	sitter "github.com/tree-sitter/go-tree-sitter"
	"strings"
)

// practiceConfigMember applies object properties in execution order. Unknown
// spreads invalidate earlier values; a later explicit property restores them.
func practiceConfigMember(m *sourceModule, n *sitter.Node, key string, depth int) (*sitter.Node, bool) {
	if depth > 6 {
		return nil, false
	}
	n = practiceLiteral(m, n, 0)
	if n == nil || n.Kind() != "object" {
		return nil, false
	}
	var value *sitter.Node
	known := true
	for i := uint(0); i < n.NamedChildCount(); i++ {
		p := n.NamedChild(i)
		if p.Kind() == "spread_element" && p.NamedChildCount() == 1 {
			v, ok := practiceConfigMember(m, p.NamedChild(0), key, depth+1)
			if !ok {
				value, known = nil, false
			} else if v != nil {
				value, known = v, true
			}
			continue
		}
		k := p.ChildByFieldName("key")
		name := ""
		if k != nil {
			name = k.Utf8Text(m.src)
			if literal, ok := stringLiteral(k, m.src); ok {
				name = literal
			}
		}
		if k != nil && k.Kind() == "computed_property_name" {
			value, known = nil, false
			continue
		}
		if p.Kind() == "shorthand_property_identifier" {
			name = p.Utf8Text(m.src)
		}
		if name == key {
			value = p.ChildByFieldName("value")
			if p.Kind() == "shorthand_property_identifier" {
				value = p
			}
			known = value != nil
		}
	}
	return value, known
}

func (s *moduleSet) practiceConfigBoundaries(ps *practiceSet, p *nextProject) {
	c := s.nextConfig(p)
	if c == nil || c.object == nil {
		return
	}
	m := c.module
	images, known := practiceConfigMember(m, c.object, "images", 0)
	if !known {
		ps.add("NX-BP-13", "Unresolved image configuration", "review", "image configuration composition is unresolved; optimizer source and SVG policy cannot be established", "", m.evidence("image_configuration", c.object))
	} else if images != nil {
		practiceImageConfig(ps, m, images)
	}
	exp, known := practiceConfigMember(m, c.object, "experimental", 0)
	if !known {
		ps.add("NX-BP-14", "Unresolved Server Action origins", "review", "experimental configuration composition is unresolved; allowed origins cannot be established", "", m.evidence("action_origin", c.object))
		return
	}
	if exp == nil {
		return
	}
	actions, known := practiceConfigMember(m, exp, "serverActions", 0)
	if !known {
		ps.add("NX-BP-14", "Unresolved Server Action origins", "review", "serverActions configuration composition is unresolved; allowed origins cannot be established", "", m.evidence("action_origin", exp))
		return
	}
	if actions == nil {
		return
	}
	origins, known := practiceConfigMember(m, actions, "allowedOrigins", 0)
	if known && origins == nil {
		return
	}
	origins = practiceLiteral(m, origins, 0)
	if !known || origins == nil || origins.Kind() != "array" {
		ps.add("NX-BP-14", "Unresolved Server Action origins", "review", "allowedOrigins composition is unresolved; origin breadth cannot be established", "", m.evidence("action_origin", actions))
		return
	}
	for i := uint(0); i < origins.NamedChildCount(); i++ {
		item := origins.NamedChild(i)
		origin, ok := stringLiteral(practiceLiteral(m, item, 0), m.src)
		if !ok {
			ps.add("NX-BP-14", "Unresolved Server Action origin", "review", "allowedOrigins element is unresolved; origin breadth cannot be established", "", m.evidence("action_origin", item))
		} else if strings.Contains(origin, "*") {
			ps.add("NX-BP-14", "Wildcard Server Action origins", "observed", "serverActions.allowedOrigins contains "+origin, "", m.evidence("action_origin", item))
		}
	}
}

func practiceImageConfig(ps *practiceSet, m *sourceModule, images *sitter.Node) {
	patterns, known := practiceConfigMember(m, images, "remotePatterns", 0)
	if !known || patterns != nil {
		patterns = practiceLiteral(m, patterns, 0)
		if !known || patterns == nil || patterns.Kind() != "array" {
			ps.add("NX-BP-13", "Unresolved image patterns", "review", "remotePatterns composition is unresolved; source breadth cannot be established", "", m.evidence("image_configuration", images))
		} else {
			for i := uint(0); i < patterns.NamedChildCount(); i++ {
				item := patterns.NamedChild(i)
				hostNode, known := practiceConfigMember(m, item, "hostname", 0)
				host, ok := stringLiteral(practiceLiteral(m, hostNode, 0), m.src)
				if !known || !ok {
					ps.add("NX-BP-13", "Unresolved image source", "review", "remotePatterns hostname is unresolved; source breadth cannot be established", "", m.evidence("image_configuration", item))
				} else if strings.Contains(host, "*") {
					ps.add("NX-BP-13", "Broad image optimizer source", "observed", "images.remotePatterns permits wildcard hostname "+host, "", m.evidence("image_configuration", item))
				}
			}
		}
	}
	svg, known := practiceConfigMember(m, images, "dangerouslyAllowSVG", 0)
	if !known {
		ps.add("NX-BP-13", "Unresolved SVG configuration", "review", "SVG optimizer configuration composition is unresolved", "", m.evidence("image_configuration", images))
		return
	}
	svg = practiceLiteral(m, svg, 0)
	if svg != nil && svg.Utf8Text(m.src) == "true" {
		policy, known := practiceConfigMember(m, images, "contentSecurityPolicy", 0)
		if known && policy == nil {
			ps.add("NX-BP-13", "SVG optimizer without content policy", "observed", "dangerouslyAllowSVG is enabled without an images.contentSecurityPolicy", "", m.evidence("image_configuration", images))
		} else if text, ok := stringLiteral(practiceLiteral(m, policy, 0), m.src); !known || !ok || text == "" {
			ps.add("NX-BP-13", "Unresolved SVG content policy", "review", "SVG optimization has no established nonempty literal content policy", "", m.evidence("image_configuration", images))
		}
	}
}
