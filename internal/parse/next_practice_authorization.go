package parse

import (
	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
	"strings"
)

func (s *moduleSet) practiceClientAuthorization(ps *practiceSet, m *sourceModule, out *analysis.AnalysisReport) {
	var gates []analysis.Evidence
	walkNodes(m.tree.RootNode(), func(n *sitter.Node) {
		if n.Kind() != "if_statement" && n.Kind() != "ternary_expression" {
			return
		}
		c := n.ChildByFieldName("condition")
		if c == nil {
			return
		}
		text := c.Utf8Text(m.src)
		walkIdentifiers(c, func(id *sitter.Node) {
			if def := definitionAt(m, id, id.Utf8Text(m.src)); def != nil {
				text += " " + def.Utf8Text(m.src)
			}
		})
		lower := strings.ToLower(text)
		if (strings.Contains(lower, "admin") || strings.Contains(lower, "role")) && (strings.Contains(text, "localStorage") || strings.Contains(text, "jwtDecode") || strings.Contains(text, "atob(")) {
			gates = append(gates, m.evidence("client_authorization_gate", c))
		}
	})
	if len(gates) == 0 {
		return
	}
	for _, r := range s.next.clientRequests {
		if r.module != m {
			continue
		}
		var relevant []analysis.Evidence
		m.guardLang().Climb(r.call, func(g GuardSite) {
			for _, gate := range gates {
				if g.Cond != nil && gate.Span.StartByte == int(g.Cond.StartByte()) && gate.Span.EndByte == int(g.Cond.EndByte()) {
					relevant = append(relevant, gate)
				}
			}
		})
		// The shared lexical guard engine handles if statements. Direct ternary
		// branches also tie a request to their own role condition.
		for parent := r.call.Parent(); parent != nil; parent = parent.Parent() {
			if isFunction(parent) || parent.Kind() == "function_declaration" {
				break
			}
			if parent.Kind() != "ternary_expression" {
				continue
			}
			condition := parent.ChildByFieldName("condition")
			consequence, alternative := parent.ChildByFieldName("consequence"), parent.ChildByFieldName("alternative")
			inBranch := func(branch *sitter.Node) bool {
				return branch != nil && r.call.StartByte() >= branch.StartByte() && r.call.EndByte() <= branch.EndByte()
			}
			if condition == nil || !inBranch(consequence) && !inBranch(alternative) {
				continue
			}
			for _, gate := range gates {
				if gate.Span.StartByte == int(condition.StartByte()) && gate.Span.EndByte == int(condition.EndByte()) {
					relevant = append(relevant, gate)
				}
			}
		}
		if len(relevant) == 0 {
			continue
		}
		url := s.clientURL(m, r.url, nil, 0)
		if url == "" {
			continue
		}
		matched, authorized := false, true
		for _, entry := range out.Entries {
			if entry.HTTP == nil || s.nextProjectFor(entry.Location.Span.File) != s.nextProjectFor(m.file) || !routePatternMatch(entry.HTTPRoute().PathPattern, url) || !strings.EqualFold(entry.HTTP.Method, r.method) {
				continue
			}
			matched = true
			entryAuthorized := false
			if server := s.modules[entry.Location.Span.File]; server != nil {
				if decl := nodeAt(server.tree.RootNode(), entry.Location.Span.StartByte, entry.Location.Span.EndByte); decl != nil {
					entryAuthorized = practiceServerRoleEnforced(server, decl)
				}
			}
			authorized = authorized && entryAuthorized
		}
		if !matched || !authorized {
			detail := "client-controlled role data gates admin UI and calls " + r.method + " " + url + "; no matching server authorization check is established"
			if !matched {
				detail += " (API entry unresolved)"
			}
			ev := append([]analysis.Evidence{}, relevant...)
			ev = append(ev, m.evidence("client_request", r.call))
			ps.add("NX-BP-22", "Client-only admin authorization", "review", detail, "", ev...)
		}
	}
}
