package langphp

import (
	"strings"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"gopkg.in/yaml.v3"
)

func (s *phpSet) emitSymfonyChecks(out *analysis.AnalysisReport, p *symfonyProject) {
	s.emitFramework(out, p)
	s.emitProfiler(out, p)
	s.emitIniSets(out, p.root)
}

func (s *phpSet) emitFramework(out *analysis.AnalysisReport, p *symfonyProject) {
	file := joinRoot(p.root, "config/packages/framework.yaml")
	if containsPath(s.unreadFiles, file) {
		out.Gaps = append(out.Gaps, analysis.Gap{Kind: "config_file_unread", Detail: "framework.yaml was not read", At: analysis.Span{File: file, StartLine: 1}})
		return
	}
	if !containsPath(s.configFiles, file) {
		return
	}
	ev, ok := readSymfonyConfig(s.root, file)
	if !ok {
		out.Gaps = append(out.Gaps, analysis.Gap{Kind: "config_file_unread", Detail: "framework.yaml was not read", At: analysis.Span{File: file, StartLine: 1}})
		return
	}
	doc, ok := symfonyYAML(ev.Text)
	if !ok {
		out.Gaps = append(out.Gaps, analysis.Gap{Kind: "config_file_unread", Detail: "framework.yaml was not read", At: analysis.Span{File: file, StartLine: 1}})
		return
	}
	fw := symfonyYAMLValue(skipWhen(doc), "framework")
	if fw == nil {
		return
	}
	if node := symfonyYAMLValue(fw, "csrf_protection"); disabledCSRF(node) {
		facts := &analysis.ConfigurationFacts{
			Check: analysis.CheckCSRFDisabled, Value: "false", Scope: "project",
			Setting: s.lineEvidence(file, "setting", "csrf_protection: false", node.Line),
		}
		if ev, ok := s.projectInstalled(p.root, file, s.projectImages(p.root)); ok {
			facts.Joined = append(facts.Joined, ev)
		}
		for _, e := range s.sessionEntries(out, p.root) {
			facts.Joined = append(facts.Joined, s.lineEvidence(e.Location.Span.File, "state_changing_entry", entryJoin(e), e.Location.Span.StartLine))
		}
		facts.Mitigations = s.csrfMitigations(p.root)
		s.emitConfig(out, p.root, facts, nil)
	}
	session := symfonyYAMLValue(fw, "session")
	if node := symfonyYAMLValue(session, "cookie_httponly"); falseScalar(node) {
		s.emitCookie(out, p.root, analysis.CheckSessionCookieScript, file, "cookie_httponly: false", node.Line)
	}
	if node := symfonyYAMLValue(session, "cookie_secure"); falseScalar(node) {
		s.emitCookie(out, p.root, analysis.CheckSessionCookieTransport, file, "cookie_secure: false", node.Line)
	}
}

func (s *phpSet) emitCookie(out *analysis.AnalysisReport, root, check, file, text string, line int) {
	facts := &analysis.ConfigurationFacts{
		Check: check, Value: "false", Scope: "project", Setting: s.lineEvidence(file, "setting", text, line),
	}
	joined := "session_authenticated: no"
	if s.hasSessionEntry(out, root) {
		joined = "session_authenticated: yes"
	}
	facts.Joined = []analysis.Evidence{s.lineEvidence(file, "session_authenticated", joined, line)}
	if ev, ok := s.projectInstalled(root, file, s.projectImages(root)); ok {
		facts.Joined = append(facts.Joined, ev)
	}
	s.emitConfig(out, root, facts, nil)
}

func (s *phpSet) emitIniSets(out *analysis.AnalysisReport, root string) {
	for _, ev := range s.iniSetCookie(root, "session.cookie_httponly") {
		s.emitCookie(out, root, analysis.CheckSessionCookieScript, ev.Span.File, ev.Text, ev.Span.StartLine)
	}
}

func (s *phpSet) emitProfiler(out *analysis.AnalysisReport, p *symfonyProject) {
	file := joinRoot(p.root, "config/packages/web_profiler.yaml")
	if !containsPath(s.configFiles, file) {
		return
	}
	ev, ok := readSymfonyConfig(s.root, file)
	if !ok {
		out.Gaps = append(out.Gaps, analysis.Gap{Kind: "config_file_unread", Detail: "web_profiler.yaml was not read", At: analysis.Span{File: file, StartLine: 1}})
		return
	}
	doc, ok := symfonyYAML(ev.Text)
	if !ok {
		out.Gaps = append(out.Gaps, analysis.Gap{Kind: "config_file_unread", Detail: "web_profiler.yaml was not read", At: analysis.Span{File: file, StartLine: 1}})
		return
	}
	node := symfonyYAMLValue(symfonyYAMLValue(skipWhen(doc), "web_profiler"), "toolbar")
	if node == nil {
		node = symfonyYAMLValue(symfonyYAMLValue(skipWhen(doc), "web_profiler"), "enabled")
	}
	if !trueScalar(node) {
		return
	}
	facts := &analysis.ConfigurationFacts{
		Check: analysis.CheckDebugEnabled, Value: "true",
		Setting: s.lineEvidence(file, "setting", "web_profiler enabled", node.Line),
		Joined:  []analysis.Evidence{s.lineEvidence(file, "deployed_file", file, node.Line)},
	}
	s.emitConfig(out, p.root, facts, nil)
}

// skipWhen drops when@test and when@dev blocks. Other when@ keys stay.
func skipWhen(doc *yaml.Node) *yaml.Node {
	if doc == nil || doc.Kind != yaml.MappingNode {
		return doc
	}
	out := *doc
	out.Content = nil
	for i := 0; i+1 < len(doc.Content); i += 2 {
		key := doc.Content[i].Value
		if key == "when@test" || key == "when@dev" {
			continue
		}
		out.Content = append(out.Content, doc.Content[i], doc.Content[i+1])
	}
	return &out
}

func disabledCSRF(node *yaml.Node) bool {
	if node == nil {
		return false
	}
	if falseScalar(node) {
		return true
	}
	enabled := symfonyYAMLValue(node, "enabled")
	return falseScalar(enabled)
}

func falseScalar(node *yaml.Node) bool {
	if node == nil || node.Kind != yaml.ScalarNode {
		return false
	}
	switch strings.ToLower(node.Value) {
	case "false", "off", "0":
		return true
	}
	return false
}

func trueScalar(node *yaml.Node) bool {
	if node == nil || node.Kind != yaml.ScalarNode {
		return false
	}
	switch strings.ToLower(node.Value) {
	case "true", "on", "1":
		return true
	}
	return false
}
