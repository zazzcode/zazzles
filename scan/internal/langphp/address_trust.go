package langphp

import (
	"strings"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/deployconf"
	"gopkg.in/yaml.v3"
)

// addressTrustFacts is the value branch 4 writes into the branch 2 field.
// Proxy values ride evidence text so the field's JSON shape stays status
// and evidence.
type addressTrustFacts struct {
	status string
	keep   bool
	text   string
	at     analysis.Evidence
}

func (f *phpFlow) attachAddressTrust(g *analysis.AuthorizationGuard) {
	facts := f.set.trustFor(f.symfony)
	if facts == nil || facts.keep {
		g.AddressTrust = &analysis.AddressTrust{Status: "unread"}
		g.Gaps = append(g.Gaps, analysis.Gap{
			Kind: "address_trust_configuration_unread", Detail: "framework client IP trust is not read", At: g.Evidence.Span,
		})
		return
	}
	ev := facts.at
	ev.Kind = "address_trust"
	ev.Text = facts.text
	ev.ModelText = facts.text
	g.AddressTrust = &analysis.AddressTrust{Status: facts.status, Evidence: ev}
}

func (s *phpSet) trustFor(p *symfonyProject) *addressTrustFacts {
	key := "."
	if p != nil {
		key = p.root
	}
	if s.trustCache == nil {
		s.trustCache = map[string]*addressTrustFacts{}
	}
	if got, ok := s.trustCache[key]; ok {
		return got
	}
	got := s.readTrust(p)
	s.trustCache[key] = got
	return got
}

func (s *phpSet) readTrust(p *symfonyProject) *addressTrustFacts {
	root := "."
	if p != nil {
		root = p.root
	}
	fw := joinRoot(root, "config/packages/framework.yaml")
	listed := containsPath(s.configFiles, fw)
	unreadable := containsPath(s.unreadFiles, fw)
	var confs []string
	for _, file := range s.deployFiles {
		if !underRoot(root, file) {
			continue
		}
		if strings.HasSuffix(file, ".conf") || strings.HasSuffix(file, ".htaccess") {
			confs = append(confs, file)
		}
	}
	if !listed && !unreadable && len(confs) == 0 {
		// No trust file was on the allow-list. Leave the branch 2 value.
		return &addressTrustFacts{keep: true}
	}
	if unreadable || (listed && !s.readable(fw)) {
		return &addressTrustFacts{keep: true}
	}
	var parts []string
	proxies, headers := "", ""
	if listed {
		if ev, ok := readSymfonyConfig(s.root, fw); ok {
			if doc, ok := symfonyYAML(ev.Text); ok {
				if node := symfonyYAMLValue(symfonyYAMLValue(doc, "framework"), "trusted_proxies"); node != nil {
					proxies = yamlScalarList(node)
				}
				if node := symfonyYAMLValue(symfonyYAMLValue(doc, "framework"), "trusted_headers"); node != nil {
					headers = yamlScalarList(node)
				}
			} else {
				return &addressTrustFacts{keep: true}
			}
		}
	}
	remoteIP, remoteHeader, remoteProxy := false, "", ""
	realHeader, realFrom := "", ""
	for _, file := range confs {
		raw, ok := s.readAllow(file)
		if !ok {
			return &addressTrustFacts{keep: true}
		}
		apache, _ := deployconf.Apache(file, raw)
		nginx, _ := deployconf.Nginx(file, raw)
		dirs := append(apache, nginx...)
		for _, d := range dirs {
			val := ""
			if len(d.Values) > 0 {
				val = d.Values[0]
			}
			switch strings.ToLower(d.Name) {
			case "remoteipheader":
				remoteHeader = val
			case "remoteiptrustedproxy":
				remoteProxy = val
			case "real_ip_header":
				realHeader = val
			case "set_real_ip_from":
				realFrom = val
			}
		}
	}
	for _, file := range s.deployFiles {
		if !underRoot(root, file) || !dockerFile(file) {
			continue
		}
		raw, ok := s.readAllow(file)
		if !ok {
			continue
		}
		img := deployconf.Dockerfile(file, raw)
		for _, m := range img.Modules {
			if len(m.Values) > 0 && m.Values[0] == "remoteip" {
				remoteIP = true
			}
		}
	}
	if proxies != "" {
		parts = append(parts, "trusted_proxies="+proxies)
	}
	if headers != "" {
		parts = append(parts, "trusted_headers="+headers)
	}
	if remoteIP {
		parts = append(parts, "remoteip=enabled")
	}
	if remoteHeader != "" {
		parts = append(parts, "RemoteIPHeader="+remoteHeader)
	}
	if remoteProxy != "" {
		parts = append(parts, "RemoteIPTrustedProxy="+remoteProxy)
	}
	if realHeader != "" {
		parts = append(parts, "real_ip_header="+realHeader)
	}
	if realFrom != "" {
		parts = append(parts, "set_real_ip_from="+realFrom)
	}
	status := "not_configured"
	switch {
	case proxies != "" && headers != "":
		status = "configured"
	case remoteHeader != "" && remoteProxy != "":
		status = "configured"
	case realHeader != "" && realFrom != "":
		status = "configured"
	case remoteIP && remoteHeader == "":
		status = "partial"
	case (proxies != "") != (headers != "") || (realHeader != "") != (realFrom != "") || (remoteHeader != "") != (remoteProxy != ""):
		status = "partial"
	}
	at := analysis.Evidence{Span: analysis.Span{File: fw, StartLine: 1, EndLine: 1}}
	if listed {
		if ev, ok := readSymfonyConfig(s.root, fw); ok {
			at = ev
			at.Span.StartLine, at.Span.EndLine = 1, 1
		}
	}
	return &addressTrustFacts{status: status, text: strings.Join(parts, "; "), at: at}
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
