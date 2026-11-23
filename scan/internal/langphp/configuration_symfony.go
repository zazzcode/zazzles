package langphp

import (
	"slices"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"gopkg.in/yaml.v3"
)

func (s *phpSet) emitSymfonyChecks(out *analysis.AnalysisReport, p *symfonyProject) {
	s.emitFramework(out, p)
	s.emitProfiler(out, p)
	for _, ev := range s.projectSourceSettings(p.root).iniSets["session.cookie_httponly"] {
		s.emitCookie(out, p, analysis.CheckSessionCookieScript, ev.Span.File, ev.Text, ev.Span.StartLine, s.projectScope(p))
	}
}

// configDocument parses one allow-listed YAML file of a project. A listed
// file that cannot be read or parsed is a gap, and no check runs on it.
func (s *phpSet) configDocument(out *analysis.AnalysisReport, p *symfonyProject, name string) (string, *yaml.Node) {
	file := joinRoot(p.root, "config/packages/"+name)
	if slices.Contains(s.unreadFiles, file) || !slices.Contains(s.configFiles, file) {
		// finishConfiguration already states an unread file.
		return file, nil
	}
	if ev, ok := s.fileText(file); ok {
		if doc, ok := symfonyYAML(ev.Text); ok {
			return file, doc
		}
	}
	out.Gaps = append(out.Gaps, analysis.Gap{Kind: "config_file_unread", Detail: name + " was not read", At: analysis.Span{File: file, StartLine: 1}})
	return file, nil
}

// scopedNode is a setting and the environment block it was written in.
type scopedNode struct {
	node  *yaml.Node
	scope string
	line  int
}

// effectiveSettings returns the value of a key path as the deployed
// application reads it. A when@prod block overrides the top level. Any
// other when@ block except when@dev and when@test is an environment of its
// own and is returned beside it. The development and test blocks are not
// deployed and are not read.
func effectiveSettings(doc *yaml.Node, keys ...string) []scopedNode {
	lookup := func(node *yaml.Node) *yaml.Node {
		for _, key := range keys {
			node = symfonyYAMLValue(node, key)
		}
		return node
	}
	var out []scopedNode
	top := scopedNode{node: lookup(doc), scope: "project"}
	if doc == nil || doc.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(doc.Content); i += 2 {
		key := doc.Content[i].Value
		if !strings.HasPrefix(key, "when@") || key == "when@dev" || key == "when@test" {
			continue
		}
		node := lookup(doc.Content[i+1])
		if node == nil {
			continue
		}
		if key == "when@prod" {
			top = scopedNode{node: node, scope: key, line: doc.Content[i].Line}
			continue
		}
		out = append(out, scopedNode{node: node, scope: key, line: doc.Content[i].Line})
	}
	if top.node != nil {
		out = append([]scopedNode{top}, out...)
	}
	return out
}

// loadedFact states which environments read a YAML setting. Symfony loads
// every file under config/packages in every environment, and a when@ block
// limits its content to the named one.
func (s *phpSet) loadedFact(file string, n scopedNode) analysis.Evidence {
	text := "top level of " + file + ", which Symfony loads in every environment; no when@prod block overrides it"
	if n.line > 0 {
		text = "inside " + n.scope + " of " + file + ", which Symfony loads in that environment"
	}
	return s.lineEvidence(file, "environment", text, n.node.Line)
}

// settingScope is the scope evidence of a YAML setting: the when@ block it
// is in, else the project.
func (s *phpSet) settingScope(p *symfonyProject, file string, n scopedNode) analysis.Evidence {
	if n.line > 0 {
		return s.lineEvidence(file, "scope", n.scope, n.line)
	}
	return s.projectScope(p)
}

func (s *phpSet) emitFramework(out *analysis.AnalysisReport, p *symfonyProject) {
	file, doc := s.configDocument(out, p, "framework.yaml")
	if doc == nil {
		return
	}
	for _, n := range effectiveSettings(doc, "framework", "csrf_protection") {
		if !disabledCSRF(n.node) {
			continue
		}
		facts := &analysis.ConfigurationFacts{
			Check: analysis.CheckCSRFDisabled, Value: "false", Scope: n.scope,
			Setting: s.lineEvidence(file, "setting", "csrf_protection: false", n.node.Line),
		}
		facts.Joined = append(facts.Joined, s.loadedFact(file, n))
		if ev, ok := s.deployment(p.root).shipped(file); ok {
			facts.Joined = append(facts.Joined, ev)
		}
		for _, e := range s.sessionEntries(out, p.root) {
			facts.Joined = append(facts.Joined, s.lineEvidence(e.Location.Span.File, "state_changing_entry", entryJoin(e), e.Location.Span.StartLine))
		}
		facts.Mitigations = s.projectSourceSettings(p.root).csrf
		s.emitConfig(out, p.root, facts, s.settingScope(p, file, n), nil)
	}
	for _, n := range effectiveSettings(doc, "framework", "session", "cookie_httponly") {
		if falseScalar(n.node) {
			s.emitCookie(out, p, analysis.CheckSessionCookieScript, file, "cookie_httponly: false", n.node.Line, s.settingScope(p, file, n), s.loadedFact(file, n))
		}
	}
	for _, n := range effectiveSettings(doc, "framework", "session", "cookie_secure") {
		if falseScalar(n.node) {
			s.emitCookie(out, p, analysis.CheckSessionCookieTransport, file, "cookie_secure: false", n.node.Line, s.settingScope(p, file, n), s.loadedFact(file, n))
		}
	}
}

func (s *phpSet) emitCookie(out *analysis.AnalysisReport, p *symfonyProject, check, file, text string, line int, scope analysis.Evidence, loaded ...analysis.Evidence) {
	facts := &analysis.ConfigurationFacts{
		Check: check, Value: "false", Scope: "project", Setting: s.lineEvidence(file, "setting", text, line),
		Joined: append([]analysis.Evidence{s.sessionJoin(out, p.root, file, line)}, loaded...),
	}
	if ev, ok := s.deployment(p.root).shipped(file); ok {
		facts.Joined = append(facts.Joined, ev)
	}
	s.emitConfig(out, p.root, facts, scope, nil)
}

func (s *phpSet) emitProfiler(out *analysis.AnalysisReport, p *symfonyProject) {
	file, doc := s.configDocument(out, p, "web_profiler.yaml")
	if doc == nil {
		return
	}
	nodes := effectiveSettings(doc, "web_profiler", "toolbar")
	if len(nodes) == 0 {
		nodes = effectiveSettings(doc, "web_profiler", "enabled")
	}
	for _, n := range nodes {
		if !trueScalar(n.node) {
			continue
		}
		facts := &analysis.ConfigurationFacts{
			Check: analysis.CheckDebugEnabled, Value: "true", Scope: n.scope,
			Setting: s.lineEvidence(file, "setting", "web_profiler enabled", n.node.Line),
			Joined:  []analysis.Evidence{s.lineEvidence(file, "deployed_file", file, n.node.Line), s.loadedFact(file, n)},
		}
		s.emitConfig(out, p.root, facts, s.settingScope(p, file, n), nil)
	}
}

func disabledCSRF(node *yaml.Node) bool {
	return falseScalar(node) || falseScalar(symfonyYAMLValue(node, "enabled"))
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

// phpSourceSettings is what one walk of a project's PHP source gives the
// configuration checks.
type phpSourceSettings struct {
	// csrf are the isCsrfTokenValid calls and csrf_token_id form options.
	csrf []analysis.Evidence
	// iniSets are ini_set calls with a literal false value, by directive.
	iniSets map[string][]analysis.Evidence
}

// projectSourceSettings walks each module of a project once.
func (s *phpSet) projectSourceSettings(root string) *phpSourceSettings {
	if got, ok := s.sourceSettings[root]; ok {
		return got
	}
	got := &phpSourceSettings{iniSets: map[string][]analysis.Evidence{}}
	for _, file := range s.files {
		m := s.modules[file]
		if !underRoot(root, file) || m == nil || m.tree == nil {
			continue
		}
		phpWalk(m.tree.RootNode(), func(n *sitter.Node) {
			switch n.Kind() {
			case "member_call_expression", "scoped_call_expression":
				if strings.EqualFold(phpText(m, phpField(n, "name")), "isCsrfTokenValid") {
					got.csrf = append(got.csrf, m.evidence("mitigation", n))
				}
			case "array_element_initializer":
				if n.NamedChildCount() == 0 {
					return
				}
				if key, ok := phpStringLiteral(m, n.NamedChild(0)); ok && key == "csrf_token_id" {
					got.csrf = append(got.csrf, m.evidence("mitigation", n))
				}
			case "function_call_expression":
				if key, ok := falseIniSet(m, n); ok {
					got.iniSets[key] = append(got.iniSets[key], m.evidence("setting", n))
				}
			}
		})
	}
	if s.sourceSettings == nil {
		s.sourceSettings = map[string]*phpSourceSettings{}
	}
	s.sourceSettings[root] = got
	return got
}

// falseIniSet returns the directive of an ini_set call whose value is a
// literal false: '0', 'off', 'false', ”, 0 or false.
func falseIniSet(m *phpModule, n *sitter.Node) (string, bool) {
	if !strings.EqualFold(strings.TrimPrefix(phpText(m, phpField(n, "function")), `\`), "ini_set") {
		return "", false
	}
	args := phpArgs(n)
	if len(args) < 2 {
		return "", false
	}
	name, ok := phpStringLiteral(m, args[0])
	if !ok {
		return "", false
	}
	val, ok := phpStringLiteral(m, args[1])
	if !ok {
		switch text := strings.ToLower(phpText(m, args[1])); text {
		case "false", "0":
			val, ok = text, true
		}
	}
	return name, ok && falseLiteral(val)
}
