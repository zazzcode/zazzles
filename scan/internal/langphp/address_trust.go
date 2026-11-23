package langphp

import (
	"slices"
	"strings"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"gopkg.in/yaml.v3"
)

// addressTrustFacts is the value written into an address guard's
// address_trust field. The proxy values ride the evidence text, so the
// field keeps its two members, status and evidence, and the authorization
// protocol does not change.
type addressTrustFacts struct {
	status string
	// unread is set when a file that could state the trust was not read.
	unread bool
	text   string
	at     analysis.Evidence
}

func (f *phpFlow) attachAddressTrust(g *analysis.AuthorizationGuard) {
	facts := f.set.trustFor(f.symfony)
	if facts.unread {
		g.AddressTrust = &analysis.AddressTrust{Status: "unread"}
		g.Gaps = append(g.Gaps, analysis.Gap{
			Kind: "address_trust_configuration_unread", Detail: "framework client IP trust is not read", At: g.Evidence.Span,
		})
		return
	}
	ev := facts.at
	ev.Kind, ev.Text, ev.ModelText = "address_trust", facts.text, facts.text
	g.AddressTrust = &analysis.AddressTrust{Status: facts.status, Evidence: ev}
}

func (s *phpSet) trustFor(p *symfonyProject) *addressTrustFacts {
	root := "."
	if p != nil {
		root = p.root
	}
	if got, ok := s.trustCache[root]; ok {
		return got
	}
	if s.trustCache == nil {
		s.trustCache = map[string]*addressTrustFacts{}
	}
	s.trustCache[root] = s.readTrust(root)
	return s.trustCache[root]
}

// proxyTrust is the proxy evidence of one project, by the place that
// states it.
type proxyTrust struct {
	proxies, headers          string // framework.trusted_proxies and trusted_headers
	remoteIP                  bool   // Apache remoteip module enabled
	remoteHeader, remoteProxy string // RemoteIPHeader and RemoteIPTrustedProxy
	realHeader, realFrom      string // nginx real_ip_header and set_real_ip_from
}

// readTrust reads the framework and web-server proxy settings of a project.
// The value is unread when no file that could state them is on the
// allow-lists, or when one of them could not be read or parsed.
func (s *phpSet) readTrust(root string) *addressTrustFacts {
	fw := joinRoot(root, "config/packages/framework.yaml")
	listed := slices.Contains(s.configFiles, fw)
	v := s.deployment(root)
	if slices.Contains(s.unreadFiles, fw) || v.webUnread || (!listed && len(v.web) == 0) {
		return &addressTrustFacts{unread: true}
	}
	var t proxyTrust
	at := analysis.Evidence{Span: analysis.Span{File: fw, StartLine: 1, EndLine: 1}}
	if listed {
		ev, ok := s.fileText(fw)
		doc, parsed := symfonyYAML(ev.Text)
		if !ok || !parsed {
			return &addressTrustFacts{unread: true}
		}
		at = s.lineEvidence(fw, "address_trust", "", 1)
		if n := effectiveSettings(doc, "framework", "trusted_proxies"); len(n) > 0 {
			t.proxies = yamlScalarList(n[0].node)
		}
		if n := effectiveSettings(doc, "framework", "trusted_headers"); len(n) > 0 {
			t.headers = yamlScalarList(n[0].node)
		}
	}
	t.readServer(v)
	return &addressTrustFacts{status: t.status(), text: t.text(), at: at}
}

// readServer reads the Apache and nginx directives and the enabled modules.
func (t *proxyTrust) readServer(v *deployView) {
	for _, conf := range v.web {
		for _, d := range conf.directives {
			switch strings.ToLower(d.Name) {
			case "remoteipheader":
				t.remoteHeader = d.Values[0]
			case "remoteiptrustedproxy":
				t.remoteProxy = d.Values[0]
			case "real_ip_header":
				t.realHeader = d.Values[0]
			case "set_real_ip_from":
				t.realFrom = d.Values[0]
			}
		}
	}
	for _, img := range v.images {
		for _, m := range img.Modules {
			t.remoteIP = t.remoteIP || m.Values[0] == "remoteip"
		}
	}
}

func (t proxyTrust) text() string {
	var parts []string
	add := func(name, value string) {
		if value != "" {
			parts = append(parts, name+"="+value)
		}
	}
	add("trusted_proxies", t.proxies)
	add("trusted_headers", t.headers)
	if t.remoteIP {
		parts = append(parts, "remoteip=enabled")
	}
	add("RemoteIPHeader", t.remoteHeader)
	add("RemoteIPTrustedProxy", t.remoteProxy)
	add("real_ip_header", t.realHeader)
	add("set_real_ip_from", t.realFrom)
	return strings.Join(parts, "; ")
}

// status is configured when one mechanism names both the header and the
// proxies it trusts, partial when a mechanism is half stated or a proxy
// module is enabled without its header, and not_configured otherwise.
func (t proxyTrust) status() string {
	both := func(a, b string) bool { return a != "" && b != "" }
	half := func(a, b string) bool { return (a != "") != (b != "") }
	switch {
	case both(t.proxies, t.headers), both(t.remoteHeader, t.remoteProxy), both(t.realHeader, t.realFrom):
		return "configured"
	case t.remoteIP && t.remoteHeader == "", half(t.proxies, t.headers), half(t.realHeader, t.realFrom), half(t.remoteHeader, t.remoteProxy):
		return "partial"
	}
	return "not_configured"
}

func yamlScalarList(node *yaml.Node) string {
	if node == nil {
		return ""
	}
	if node.Kind == yaml.ScalarNode {
		return node.Value
	}
	var parts []string
	for _, c := range node.Content {
		if c.Kind == yaml.ScalarNode && c.Value != "" {
			parts = append(parts, c.Value)
		}
	}
	return strings.Join(parts, ",")
}
