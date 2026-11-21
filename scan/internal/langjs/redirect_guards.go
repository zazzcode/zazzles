package langjs

import (
	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/parse"
	"net/url"
	"strconv"
	"strings"
)

// redirectRestrictionEvidence identifies raw-string tests only. An includes on
// an array of parsed hosts must never become a substring bypass fact.
func (s *moduleSet) redirectRestrictionEvidence(u *analysis.CandidateUse, c *analysis.Completeness) {
	names := []string{}
	for _, d := range u.Dependencies {
		names = append(names, parse.CommandDepNames(d)...)
	}
	for _, p := range u.CodePaths() {
		for _, index := range p.Controls {
			if index < 0 || index >= len(u.Context) {
				continue
			}
			e := u.Context[index]
			m := s.modules[e.Span.File]
			if m == nil {
				continue
			}
			node := parse.NodeAt(m.tree.RootNode(), e.Span.StartByte, e.Span.EndByte)
			if node == nil {
				continue
			}
			walkCalls(node, func(call *sitter.Node) {
				fn, args := call.ChildByFieldName("function"), call.ChildByFieldName("arguments")
				if fn == nil || args == nil || args.NamedChildCount() == 0 || fn.Kind() != "member_expression" {
					return
				}
				obj, prop := fn.ChildByFieldName("object"), fn.ChildByFieldName("property")
				if obj == nil || prop == nil || obj.Kind() == "array" {
					return
				}
				text := obj.Utf8Text(m.src)
				if !parse.MentionsAny(text, names) || strings.HasSuffix(text, ".hostname") || strings.HasSuffix(text, ".host") || strings.HasSuffix(text, ".origin") {
					return
				}
				method := prop.Utf8Text(m.src)
				if method == "includes" || method == "indexOf" {
					c.Evidence["redirect_raw_substring"] = append(c.Evidence["redirect_raw_substring"], m.evidence("redirect_raw_substring", call))
					role := "redirect_raw_substring_path_" + strconv.Itoa(p.Dependency)
					c.Evidence[role] = append(c.Evidence[role], m.evidence(role, call))
					c.Required = append(c.Required, role)
				}
				if method == "startsWith" {
					prefix, ok := stringLiteral(args.NamedChild(0), m.src)
					if !ok || !strings.HasSuffix(prefix, "/") {
						return
					}
					parsed, err := url.Parse(prefix)
					if err == nil && (parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.Host != "" && parsed.User == nil && parsed.Path != "" {
						c.Evidence["redirect_origin_prefix"] = append(c.Evidence["redirect_origin_prefix"], m.evidence("redirect_origin_prefix", call))
					}
				}
			})
		}
	}
}

// interpreterGuards also exposes an immutable boolean predicate used by an
// enclosing branch. Next's truthiness heuristic must not discard the source
// expression behind `const allowed = predicate(url); if (allowed) redirect(url)`.
func (s *moduleSet) interpreterGuards(u *analysis.CandidateUse) ([]analysis.Evidence, []analysis.Evidence) {
	guards, transforms := s.commandGuards(u)
	m := s.modules[u.Sink.Span.File]
	if m == nil {
		return guards, transforms
	}
	sink := parse.NodeAt(m.tree.RootNode(), u.Sink.Span.StartByte, u.Sink.Span.EndByte)
	if sink == nil {
		return guards, transforms
	}
	names := []string{}
	for _, d := range u.Dependencies {
		names = append(names, parse.CommandDepNames(d)...)
	}
	filtered := guards[:0]
	for _, g := range guards {
		if !parse.PresenceOnlyCondition(g.Text, names) {
			filtered = append(filtered, g)
		}
	}
	guards = filtered
	for parent := sink.Parent(); parent != nil; parent = parent.Parent() {
		if parent.Kind() != "if_statement" {
			continue
		}
		body := parent.ChildByFieldName("consequence")
		if body == nil || sink.StartByte() < body.StartByte() || sink.EndByte() > body.EndByte() {
			continue
		}
		cond := unwrapTS(parent.ChildByFieldName("condition"))
		if cond == nil || cond.Kind() != "identifier" {
			continue
		}
		name := cond.Utf8Text(m.src)
		if bindingReassigned(m, name) {
			continue
		}
		init := unwrapTS(localInitializer(m, cond, name))
		if init == nil || !parse.MentionsAny(init.Utf8Text(m.src), names) {
			continue
		}
		boolean := init.Kind() == "binary_expression" || init.Kind() == "unary_expression"
		if init.Kind() == "call_expression" {
			if fn := init.ChildByFieldName("function"); fn != nil && fn.Kind() == "member_expression" {
				if method := fn.ChildByFieldName("property"); method != nil {
					boolean = containsString([]string{"test", "includes", "startsWith", "endsWith", "has"}, method.Utf8Text(m.src))
				}
			}
		}
		if !boolean {
			continue
		}
		guards = append(guards, m.evidence("enclosing_guard", init))
		u.Context = append(u.Context, m.evidence("predicate_branch", parent.ChildByFieldName("condition")))
	}
	return guards, transforms
}

func (s *moduleSet) redirectHelperRestrictions(u *analysis.CandidateUse, c *analysis.Completeness) {
	m := s.modules[u.Sink.Span.File]
	if m == nil {
		return
	}
	names := []string{}
	for _, d := range u.Dependencies {
		names = append(names, parse.CommandDepNames(d)...)
	}
	for _, p := range u.CodePaths() {
		for _, index := range p.Controls {
			e := u.Context[index]
			owner := s.modules[e.Span.File]
			if owner == nil {
				continue
			}
			guard := parse.NodeAt(owner.tree.RootNode(), e.Span.StartByte, e.Span.EndByte)
			if guard == nil {
				continue
			}
			walkCalls(guard, func(call *sitter.Node) {
				args := call.ChildByFieldName("arguments")
				if args == nil {
					return
				}
				hm, helper := s.resolveCall(owner, call)
				if hm == nil || helper == nil {
					return
				}
				params, ok := functionParameters(helper, hm.src)
				if !ok {
					return
				}
				for i, param := range params {
					if uint(i) >= args.NamedChildCount() || !parse.MentionsAny(args.NamedChild(uint(i)).Utf8Text(owner.src), names) {
						continue
					}
					walkCalls(helper.ChildByFieldName("body"), func(test *sitter.Node) {
						fn := test.ChildByFieldName("function")
						if fn == nil || fn.Kind() != "member_expression" {
							return
						}
						obj, prop := fn.ChildByFieldName("object"), fn.ChildByFieldName("property")
						if obj == nil || prop == nil || obj.Kind() != "identifier" || obj.Utf8Text(hm.src) != param.name {
							return
						}
						method := prop.Utf8Text(hm.src)
						if method != "includes" && method != "indexOf" {
							return
						}
						if writesName(helper.ChildByFieldName("body"), param.name, hm.src) {
							return
						}
						c.Evidence["redirect_raw_substring"] = append(c.Evidence["redirect_raw_substring"], hm.evidence("redirect_raw_substring", test))
						role := "redirect_raw_substring_path_" + strconv.Itoa(p.Dependency)
						c.Evidence[role] = append(c.Evidence[role], hm.evidence(role, test))
						c.Required = append(c.Required, role)
						c.Evidence["guard_definition"] = append(c.Evidence["guard_definition"], hm.evidence("guard_definition", helper))
					})
				}
			})
		}
	}
}
