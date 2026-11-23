package langphp

import (
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

// sourceCookie is one session cookie flag that PHP code sets to false.
type sourceCookie struct {
	check   string
	value   string // "false" or "false on some path"
	setting analysis.Evidence
	assigns []analysis.Evidence
}

// sourceCookies returns the flags a call sets to false on the session
// cookie: session_set_cookie_params, or setcookie named by session_name().
func sourceCookies(m *phpModule, n *sitter.Node) []sourceCookie {
	args := phpArgs(n)
	var secure, httponly *sitter.Node
	switch strings.ToLower(strings.TrimPrefix(phpText(m, phpField(n, "function")), `\`)) {
	case "session_set_cookie_params":
		if len(args) == 1 && args[0].Kind() == "array_creation_expression" {
			secure, httponly = cookieOptions(m, args[0])
		} else {
			secure, httponly = argAt(args, 3), argAt(args, 4)
		}
	case "setcookie", "setrawcookie":
		if len(args) == 0 || !sessionNameCall(m, args[0]) {
			return nil
		}
		if len(args) > 2 && args[2].Kind() == "array_creation_expression" {
			secure, httponly = cookieOptions(m, args[2])
		} else {
			secure, httponly = argAt(args, 5), argAt(args, 6)
		}
	default:
		return nil
	}
	var out []sourceCookie
	for _, flag := range []struct {
		check string
		node  *sitter.Node
	}{{analysis.CheckSessionCookieTransport, secure}, {analysis.CheckSessionCookieScript, httponly}} {
		if value, assigns, ok := falseFlag(m, flag.node); ok {
			out = append(out, sourceCookie{check: flag.check, value: value, setting: m.evidence("setting", n), assigns: assigns})
		}
	}
	return out
}

func argAt(args []*sitter.Node, i int) *sitter.Node {
	if i < len(args) {
		return args[i]
	}
	return nil
}

func sessionNameCall(m *phpModule, n *sitter.Node) bool {
	return n.Kind() == "function_call_expression" && len(phpArgs(n)) == 0 &&
		strings.EqualFold(strings.TrimPrefix(phpText(m, phpField(n, "function")), `\`), "session_name")
}

// cookieOptions returns the secure and httponly values of an options array.
func cookieOptions(m *phpModule, array *sitter.Node) (secure, httponly *sitter.Node) {
	for i := uint(0); i < array.NamedChildCount(); i++ {
		el := array.NamedChild(i)
		if el == nil || el.Kind() != "array_element_initializer" || el.NamedChildCount() != 2 {
			continue
		}
		key, ok := phpStringLiteral(m, el.NamedChild(0))
		if !ok {
			continue
		}
		switch strings.ToLower(key) {
		case "secure":
			secure = el.NamedChild(1)
		case "httponly":
			httponly = el.NamedChild(1)
		}
	}
	return secure, httponly
}

func falseText(text string) bool {
	text = strings.ToLower(strings.TrimSpace(text))
	return text == "false" || text == "0"
}

// falseFlag reports a flag that is the literal false or 0, or a variable
// that an earlier assignment in the same function or file scope sets to one
// of those. Each such assignment is returned as evidence.
func falseFlag(m *phpModule, n *sitter.Node) (string, []analysis.Evidence, bool) {
	if n == nil {
		return "", nil, false
	}
	if n.Kind() != "variable_name" {
		return "false", nil, falseText(phpText(m, n))
	}
	name, scope := phpText(m, n), plainScope(n)
	var assigns []analysis.Evidence
	other := false
	phpWalk(scope, func(a *sitter.Node) {
		if a.Kind() != "assignment_expression" || a.EndByte() > n.StartByte() {
			return
		}
		if phpText(m, phpField(a, "left")) != name || plainScope(a).Id() != scope.Id() {
			return
		}
		if falseText(phpText(m, phpField(a, "right"))) {
			assigns = append(assigns, m.evidence("value_assignment", a))
		} else {
			other = true
		}
	})
	if len(assigns) == 0 {
		return "", nil, false
	}
	if other {
		return "false on some path", assigns, true
	}
	return "false", assigns, true
}

// emitSourceCookies records the session cookie flags PHP code sets to false.
func (s *phpSet) emitSourceCookies(out *analysis.AnalysisReport, root string, scope func(file string) analysis.Evidence) {
	for _, c := range s.projectSourceSettings(root).cookies {
		file, line := c.setting.Span.File, c.setting.Span.StartLine
		facts := &analysis.ConfigurationFacts{
			Check: c.check, Value: c.value, Scope: "project", Setting: c.setting,
			Joined: append([]analysis.Evidence{s.sessionJoin(out, root, file, line)}, c.assigns...),
		}
		if ev, ok := s.deployment(root).shipped(file); ok {
			facts.Joined = append(facts.Joined, ev)
		}
		s.emitConfig(out, root, facts, scope(file), nil)
	}
}

// sourceScope is the scope evidence of a setting made in plain PHP source.
func (s *phpSet) sourceScope(file string) analysis.Evidence {
	return s.lineEvidence(file, "scope", "application source "+file, 1)
}

// emitPlainSource records the source settings of a project with no
// framework: the literal ini_set form and the session cookie calls.
func (s *phpSet) emitPlainSource(out *analysis.AnalysisReport, root string) {
	for _, ev := range s.projectSourceSettings(root).iniSets["session.cookie_httponly"] {
		file, line := ev.Span.File, ev.Span.StartLine
		facts := &analysis.ConfigurationFacts{
			Check: analysis.CheckSessionCookieScript, Value: "false", Scope: "project", Setting: ev,
			Joined: []analysis.Evidence{s.sessionJoin(out, root, file, line)},
		}
		if shipped, ok := s.deployment(root).shipped(file); ok {
			facts.Joined = append(facts.Joined, shipped)
		}
		s.emitConfig(out, root, facts, s.sourceScope(file), nil)
	}
	s.emitSourceCookies(out, root, s.sourceScope)
}
