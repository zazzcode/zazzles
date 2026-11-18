package parse

import (
	"sort"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
)

// commandGuardEvidenceKind names a guard site for the command claim. A
// condition that holds only on the rejecting side of an enclosing `if` (its
// else branch) is a false-branch fact, never an enforced one.
func commandGuardEvidenceKind(site GuardSite) string {
	if site.Kind == enclosingGuardKind && site.Polarity == guardRejectsWhenTrue {
		return "branch_false_precondition"
	}
	return site.Kind
}

// commandGuardScan finds the controls around one process call for either
// language: the call's own dominating and enclosing controls and, for a call
// inside a local helper, the controls its call sites have in common.
type CommandGuardScan struct {
	lang   GuardLang
	call   *sitter.Node
	Scope  *sitter.Node
	helper *sitter.Node
	sites  []*sitter.Node
}

func newCommandGuardScan(lang GuardLang, call *sitter.Node, helperSites func(*sitter.Node) []*sitter.Node) *CommandGuardScan {
	g := &CommandGuardScan{lang: lang, call: call, Scope: lang.Scope(call)}
	g.helper = lang.Climb(call, func(GuardSite) {})
	g.sites = helperSites(g.helper)
	return g
}

// names extends the base names with every dependency's own names and values
// derived from them in one scope. defs maps each derived name to its definition.
func (g *CommandGuardScan) names(base map[string]bool, deps []analysis.Dependency, scope *sitter.Node) ([]string, map[string]string) {
	names := map[string]bool{}
	for name := range base {
		names[name] = true
	}
	for _, d := range deps {
		for _, name := range commandDepNames(d) {
			names[name] = true
		}
	}
	defs := map[string]string{}
	g.lang.Derive(scope, names, defs, map[string]*sitter.Node{})
	return sortedNameList(names), defs
}

// withSources adds, transitively, the names a derived value was computed from:
// a control on `clean` inspects `cmd` as it was when `clean` was derived, so a
// later write to `cmd` invalidates that control.
func withSources(mentioned, list []string, defs map[string]string) []string {
	seen := map[string]bool{}
	queue := append([]string{}, mentioned...)
	for len(queue) > 0 {
		name := queue[0]
		queue = queue[1:]
		if seen[name] {
			continue
		}
		seen[name] = true
		if def, ok := defs[name]; ok {
			for _, source := range list {
				if !seen[source] && mentionsAny(def, []string{source}) {
					queue = append(queue, source)
				}
			}
		}
	}
	return sortedNameList(seen)
}

// derived lists, for each dependency, the names its value is reachable by in the
// call's scope and the scopes of its helper call sites, extended with values
// computed from it (`const clean = cmd.trim()`), so a control on a derived value
// is attributed to the dependency it came from.
func (g *CommandGuardScan) Derived(deps []analysis.Dependency) [][]string {
	scopes := []*sitter.Node{g.Scope}
	for _, site := range g.sites {
		scopes = append(scopes, g.lang.Scope(site))
	}
	out := make([][]string, len(deps))
	for i, d := range deps {
		names := map[string]bool{}
		for _, scope := range scopes {
			own := map[string]bool{}
			for _, name := range commandDepNames(d) {
				own[name] = true
			}
			g.lang.Derive(scope, own, map[string]string{}, map[string]*sitter.Node{})
			for name := range own {
				names[name] = true
			}
		}
		out[i] = sortedNameList(names)
	}
	return out
}

// collect returns the controls whose condition mentions an operand, is not a
// presence-only test, and is not invalidated by an assignment between the
// control and the call. keep filters sites a language already models elsewhere.
func (g *CommandGuardScan) Collect(base map[string]bool, deps []analysis.Dependency, keep func(GuardSite) bool) []GuardSite {
	accepts := func(site GuardSite, anchor, within *sitter.Node, list []string, defs map[string]string) bool {
		if site.Cond == nil || (keep != nil && !keep(site)) {
			return false
		}
		text := g.lang.text(site.Cond)
		return mentionsAny(text, list) && !presenceOnlyCondition(text, list) &&
			!g.lang.AssignedBetween(within, site.End, anchor.StartByte(), withSources(mentionedNames(text, list), list, defs))
	}
	var out []GuardSite
	list, defs := g.names(base, deps, g.Scope)
	g.lang.Climb(g.call, func(site GuardSite) {
		if accepts(site, g.call, g.Scope, list, defs) {
			out = append(out, site)
		}
	})
	if len(g.sites) == 0 {
		return out
	}
	perSite := make([][]GuardSite, len(g.sites))
	for i, site := range g.sites {
		within := g.lang.Scope(site)
		callerList, callerDefs := g.names(base, deps, within)
		g.lang.Climb(site, func(found GuardSite) {
			if accepts(found, site, within, callerList, callerDefs) {
				perSite[i] = append(perSite[i], found)
			}
		})
	}
	return append(out, g.lang.commonGuardSites(perSite)...)
}

// collectionDefinitions returns the declarations of the constant collections
// that guard conditions test (`ALLOWED` in `if (!ALLOWED.has(cmd))`), once
// each, in source order. A guard against an allow-list cannot be judged without
// the list's contents, which live outside the handler.
func collectionDefinitions(conditions []*sitter.Node, src []byte, declaration func(name string) *sitter.Node) []*sitter.Node {
	seen := map[uint]bool{}
	var out []*sitter.Node
	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		if n.Kind() == "identifier" {
			if decl := declaration(n.Utf8Text(src)); decl != nil && !seen[decl.StartByte()] {
				seen[decl.StartByte()] = true
				out = append(out, decl)
			}
		}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			visit(n.NamedChild(i))
		}
	}
	for _, cond := range conditions {
		visit(cond)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].StartByte() < out[j].StartByte() })
	return out
}
