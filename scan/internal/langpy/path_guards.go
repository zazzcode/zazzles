package langpy

import (
	"sort"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/parse"
)

var pyMutatingCollectionMethods = map[string]bool{
	"add": true, "update": true, "append": true, "extend": true, "insert": true,
	"pop": true, "remove": true, "discard": true, "clear": true, "setdefault": true,
}

func pythonCollectionMutated(m *pythonModule, name string) bool {
	mutated := false
	pyWalk(m.tree.RootNode(), func(n *sitter.Node) {
		if mutated {
			return
		}
		switch n.Kind() {
		case "assignment", "augmented_assignment", "delete_statement":
			left := n.ChildByFieldName("left")
			if left != nil && left.Kind() == "subscript" {
				if v := left.ChildByFieldName("value"); v != nil && v.Kind() == "identifier" && pyText(m, v) == name {
					mutated = true
				}
			}
		case "call":
			fn := n.ChildByFieldName("function")
			if fn != nil && fn.Kind() == "attribute" {
				obj, attr := fn.ChildByFieldName("object"), fn.ChildByFieldName("attribute")
				if obj != nil && attr != nil && obj.Kind() == "identifier" && pyText(m, obj) == name && pyMutatingCollectionMethods[pyText(m, attr)] {
					mutated = true
				}
			}
		}
	})
	return mutated
}

// pyConstantCollection reports a module-level list, tuple, set or dict (or a
// set/frozenset/tuple/list call of one) made only of string literals and never mutated.
func pyConstantCollection(m *pythonModule, name string) bool {
	trimmed := strings.TrimSpace(name)
	node := m.vars[trimmed]
	if node == nil || pythonReassigned(m, trimmed) || pythonCollectionMutated(m, trimmed) {
		return false
	}
	if node.Kind() == "call" {
		fn := pyText(m, node.ChildByFieldName("function"))
		args := pyArgs(node)
		if (fn != "set" && fn != "frozenset" && fn != "tuple" && fn != "list") || len(args) != 1 {
			return false
		}
		node = args[0]
	}
	switch node.Kind() {
	case "set", "list", "tuple":
		count := 0
		for i := uint(0); i < node.NamedChildCount(); i++ {
			c := node.NamedChild(i)
			if c.Kind() == "comment" {
				continue
			}
			if c.Kind() != "string" || stringHasInterpolation(c) {
				return false
			}
			count++
		}
		return count > 0
	case "dictionary":
		count := 0
		for i := uint(0); i < node.NamedChildCount(); i++ {
			c := node.NamedChild(i)
			if c.Kind() == "comment" {
				continue
			}
			if c.Kind() != "pair" {
				return false // dictionary_splat or non-pair leaves contents dynamic
			}
			key := c.ChildByFieldName("key")
			if key == nil || key.Kind() != "string" || stringHasInterpolation(key) {
				return false
			}
			count++
		}
		return count > 0
	}
	return false
}

func stringHasInterpolation(n *sitter.Node) bool {
	for i := uint(0); i < n.NamedChildCount(); i++ {
		if n.NamedChild(i).Kind() == "interpolation" {
			return true
		}
	}
	return false
}

// pyModuleVarDecl returns the full assignment node (`NAME = ...`) for a module constant.
func pyModuleVarDecl(m *pythonModule, name string) *sitter.Node {
	v := m.vars[strings.TrimSpace(name)]
	if v == nil {
		return nil
	}
	if p := v.Parent(); p != nil && p.Kind() == "assignment" {
		return p
	}
	return v
}

// safeSendDirectory reports a directory expression for send_from_directory that
// is neither request-derived nor built from a local helper call, such as a
// literal, module-level configuration attribute or app.config subscript.
func (f *pythonFlow) safeSendDirectory(m *pythonModule, n *sitter.Node) bool {
	if f.pyConstantPath(m, n, 0) {
		return true
	}
	v := f.quiet(n)
	if len(v.deps) > 0 {
		return false
	}
	hasCall := false
	pyWalk(n, func(c *sitter.Node) {
		if c.Kind() == "call" {
			q := f.set.qualified(m, pyText(m, c.ChildByFieldName("function")))
			if !pyModeledPathCalls[q] && !pyPathObjectNames[q] {
				hasCall = true
			}
		}
	})
	return !hasCall
}

// pyConstantPath reports an expression built only from literals, __file__ and
// modeled path operations over those: a trusted base.
func (f *pythonFlow) pyConstantPath(m *pythonModule, n *sitter.Node, depth int) bool {
	if n == nil || depth > 6 {
		return false
	}
	switch n.Kind() {
	case "string":
		for i := uint(0); i < n.NamedChildCount(); i++ {
			if c := n.NamedChild(i); c.Kind() == "interpolation" && (c.NamedChildCount() == 0 || !f.pyConstantPath(m, c.NamedChild(0), depth+1)) {
				return false
			}
		}
		return true
	case "integer", "float":
		return true
	case "parenthesized_expression":
		return n.NamedChildCount() > 0 && f.pyConstantPath(m, n.NamedChild(0), depth+1)
	case "binary_operator":
		return f.pyConstantPath(m, n.ChildByFieldName("left"), depth+1) && f.pyConstantPath(m, n.ChildByFieldName("right"), depth+1)
	case "attribute":
		switch pyText(m, n.ChildByFieldName("attribute")) {
		case "parent", "name", "stem", "suffix", "sep":
			return f.pyConstantPath(m, n.ChildByFieldName("object"), depth+1) || strings.HasSuffix(pyText(m, n), "os.sep")
		}
		return false
	case "identifier":
		name := pyText(m, n)
		if name == "__file__" {
			return true
		}
		if _, local := f.env[name]; local {
			return false
		}
		if v := m.vars[name]; v != nil && !pythonReassigned(m, name) {
			return f.pyConstantPath(m, v, depth+1)
		}
		return false
	case "subscript":
		// app.config["X"]: Flask application configuration is not request data.
		if obj := n.ChildByFieldName("value"); obj != nil && obj.Kind() == "attribute" && pyText(m, obj.ChildByFieldName("attribute")) == "config" {
			if root := obj.ChildByFieldName("object"); root != nil && root.Kind() == "identifier" {
				if v := m.vars[pyText(m, root)]; v != nil && v.Kind() == "call" && f.set.qualified(m, pyText(m, v.ChildByFieldName("function"))) == "flask.Flask" {
					return true
				}
			}
		}
		return false
	case "call":
		q := f.set.qualified(m, pyText(m, n.ChildByFieldName("function")))
		if !pyModeledPathCalls[q] && !pyPathObjectNames[q] {
			return false
		}
		for _, a := range pyArgs(n) {
			if !f.pyConstantPath(m, a, depth+1) {
				return false
			}
		}
		return true
	}
	return false
}

// pythonPathGuards finds statements that dominate or enclose the call and
// mention a request-derived path value, and classifies each with AST polarity.
func (f *pythonFlow) pythonPathGuards(call *sitter.Node, u *analysis.CandidateUse, operand map[string]bool, info *parse.PathGuardInfo) ([]analysis.Evidence, []analysis.Evidence) {
	m := f.module
	lang := f.guardLang()
	scope := lang.Scope(call)
	type depNames struct {
		idx   int
		names map[string]bool
		list  []string
	}
	var all []depNames
	defs := map[string]string{}
	defNodes := map[string]*sitter.Node{}
	for i, d := range u.Dependencies {
		if d.SinkSlot != analysis.PathSlotFile {
			continue
		}
		names := map[string]bool{}
		for name := range operand {
			names[name] = true
		}
		for _, name := range parse.CommandDepNames(d) {
			names[name] = true
		}
		lang.Derive(scope, names, defs, defNodes)
		list := make([]string, 0, len(names))
		for name := range names {
			list = append(list, name)
		}
		sort.Strings(list)
		all = append(all, depNames{i, names, list})
	}
	var declEvidence []analysis.Evidence
	declSeen := map[int]bool{}
	collection := func(name string) bool {
		if !pyConstantCollection(m, name) {
			return false
		}
		if decl := pyModuleVarDecl(m, name); decl != nil && !declSeen[int(decl.StartByte())] {
			declSeen[int(decl.StartByte())] = true
			declEvidence = append(declEvidence, m.evidence("allowlist_definition", decl))
		}
		return true
	}
	baseConst := func(name string) bool {
		trimmed := strings.TrimSpace(name)
		if v := m.vars[trimmed]; v != nil && !pythonReassigned(m, trimmed) && f.pyConstantPath(m, v, 0) {
			if decl := pyModuleVarDecl(m, trimmed); decl != nil && !declSeen[int(decl.StartByte())] {
				declSeen[int(decl.StartByte())] = true
				declEvidence = append(declEvidence, m.evidence("constant_base", decl))
			}
			return true
		}
		return false
	}
	var guards []analysis.Evidence
	seen := map[int]bool{}
	consider := func(kind string, polarity parse.GuardPolarity, cond, whole *sitter.Node, guardEnd uint) {
		if cond == nil || seen[int(whole.StartByte())] {
			return
		}
		text := pyText(m, cond)
		covered := map[int]bool{}
		var union []string
		for _, d := range all {
			if !parse.MentionsAny(text, d.list) || parse.PresenceOnlyCondition(text, d.list) {
				continue
			}
			var mentioned []string
			for _, name := range d.list {
				if parse.MentionsAny(text, []string{name}) {
					mentioned = append(mentioned, name)
				}
			}
			if lang.AssignedBetween(scope, guardEnd, call.StartByte(), mentioned) {
				continue
			}
			covered[d.idx] = true
			union = append(union, d.list...)
		}
		if len(covered) == 0 {
			return
		}
		seen[int(whole.StartByte())] = true
		class, rootContain := parse.ClassifyPathGuardAST(cond, m.src, polarity, union, defs, defNodes, collection, baseConst)
		if class == analysis.PathGuardPresenceOrType {
			return
		}
		ev := m.evidence(kind, whole)
		info.NoteWithMeta(ev, class, covered, rootContain)
		guards = append(guards, ev)
	}
	climb := func(start *sitter.Node) *sitter.Node {
		return lang.Climb(start, func(site parse.GuardSite) {
			consider(site.Kind, site.Polarity, site.Cond, site.Whole, site.End)
		})
	}
	helper := climb(call)
	sites := f.pyHelperCallSites(helper)
	if len(sites) > 1 {
		for _, site := range sites {
			before := len(guards)
			climb(site)
			siteEnforcing := false
			for _, g := range guards[before:] {
				if analysis.EnforcingPathGuard(info.Kinds[parse.GuardKey(g)]) {
					siteEnforcing = true
				}
			}
			if !siteEnforcing {
				info.AmbiguousCallers = true
			}
		}
	} else if len(sites) == 1 {
		climb(sites[0])
	}
	// Also attach verified import declaration for any terminating abort/HTTPException
	// used inside dominating guards so the model knows abort(403) does not fall through.
	for _, g := range guards {
		if n := parse.NodeAt(m.tree.RootNode(), g.Span.StartByte, g.Span.EndByte); n != nil {
			pyWalk(n, func(c *sitter.Node) {
				if c.Kind() == "call" {
					callee := pyText(m, c.ChildByFieldName("function"))
					switch f.qualified(callee) {
					case "flask.abort", "werkzeug.exceptions.abort", "sys.exit", "fastapi.HTTPException":
						root := strings.Split(callee, ".")[0]
						if imp, ok := m.imports[root]; ok && imp.node != nil && !declSeen[int(imp.node.StartByte())] {
							declSeen[int(imp.node.StartByte())] = true
							declEvidence = append(declEvidence, m.evidence("module_import", imp.node))
						}
					}
				}
			})
		}
	}
	return guards, declEvidence
}
