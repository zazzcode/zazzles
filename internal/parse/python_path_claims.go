package parse

import (
	"fmt"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
)

// pythonPathBlockerKind reports whether a gap kind can leave an operand path unresolved.
func pythonPathBlockerKind(kind string) bool {
	return pythonCommandBlockers[kind] || kind == "path_spread_unresolved"
}

// completePythonPath assembles the claim-scoped completeness for a Python use at
// the point where its flow, guards and operands are known.
func (f *pythonFlow) completePythonPath(u *analysis.CandidateUse, call *sitter.Node, operands pythonValue, guards []analysis.Evidence, guardIndex []int, names map[string]bool, info *pathGuardInfo) {
	m := f.module
	blockers := []analysis.Gap{}
	coverage := []analysis.Gap{}
	resolved := []analysis.Gap{}
	transfers := []analysis.Evidence{}
	transferSeen := map[string]bool{}
	addTransfer := func(e analysis.Evidence) {
		key := fmt.Sprintf("%s:%d:%d:%s", e.Span.File, e.Span.StartByte, e.Span.EndByte, e.Kind)
		if !transferSeen[key] {
			transferSeen[key] = true
			transfers = append(transfers, e)
		}
	}
	baseSeen := map[int]bool{}
	var bases []analysis.Evidence
	addBase := func(e analysis.Evidence) {
		if e.Kind != "" && !baseSeen[e.Span.StartByte] {
			baseSeen[e.Span.StartByte] = true
			bases = append(bases, e)
		}
	}
	hasGuard := len(guards) > 0
	for _, g := range append(append([]analysis.Gap{}, u.Gaps...), f.guardGaps(operands)...) {
		if !pythonPathBlockerKind(g.Kind) || (g.Kind == "python_call_unresolved" && g.At.StartByte == int(call.StartByte()) && g.At.File == m.file) {
			coverage = append(coverage, g)
			continue
		}
		if hasGuard {
			if evidence, ok := f.modeledPathGap(g); ok {
				resolved = append(resolved, g)
				if evidence.Kind == "constant_base" || evidence.Kind == "module_import" {
					addBase(evidence)
				} else if evidence.Kind != "" && touchesCommandDependency(g, u.Dependencies) {
					addTransfer(evidence)
				}
				continue
			}
		}
		if (g.Kind == "python_call_unresolved" || g.Kind == "python_value_unresolved" || g.Kind == "python_dispatch_unresolved") && !touchesCommandDependency(g, u.Dependencies) {
			coverage = append(coverage, g)
			continue
		}
		if !hasGuard {
			if evidence, ok := f.modeledPathGap(g); ok {
				coverage = append(coverage, g)
				if evidence.Kind == "transformation" {
					addTransfer(evidence)
				}
				continue
			}
		}
		if evidence, ok := f.supportedCommandGap(g, names); ok {
			coverage = append(coverage, g)
			addTransfer(evidence)
			continue
		}
		blockers = append(blockers, g)
	}
	u.Context = append(u.Context, bases...)
	extra := map[string][]analysis.Evidence{
		"invoked_callable": {f.route.module.evidence("invoked_callable", f.route.fn)},
		"control_flow":     append([]analysis.Evidence{m.evidence("operation", call)}, f.context...),
		"transformation":   transfers,
	}
	if len(bases) > 0 {
		extra["constant_base"] = append(extra["constant_base"], bases...)
	}
	c := pathCompleteness(u, extra, dedupeGaps(blockers), dedupeGaps(coverage))
	c.Resolved = append(c.Resolved, dedupeGaps(resolved)...)
	for _, t := range transfers {
		c.ModelFacts = append(c.ModelFacts, "Supported transfer "+t.Kind+" "+t.Text+" at "+t.Span.File+" carries its operand into the result without a modeled constraint; it is not a validator.")
	}
	finishPathFlows(u, c, guards, guardIndex, info, func(g analysis.Gap, d analysis.Dependency) bool {
		return gapTouchesDependency(g, d) || pythonGapTouches(g, d)
	})
	u.Completeness = c
	u.Gaps = dedupeGaps(append(append([]analysis.Gap{}, u.Gaps...), blockers...))
}

// modeledPathGap recognizes a gap on a verified path call, a pathlib object or
// a constant trusted base. For a module constant or verified stdlib import it
// returns the declaration span so the model receives the source definition.
func (f *pythonFlow) modeledPathGap(g analysis.Gap) (analysis.Evidence, bool) {
	m := f.set.modules[g.At.File]
	if m == nil {
		return analysis.Evidence{}, false
	}
	node := nodeAt(m.tree.RootNode(), g.At.StartByte, g.At.EndByte)
	if node == nil {
		return analysis.Evidence{}, false
	}
	if node.Kind() == "identifier" {
		name := pyText(m, node)
		if decl := pyModuleVarDecl(m, name); decl != nil && !pythonReassigned(m, name) && f.pyConstantPath(m, m.vars[name], 0) {
			return m.evidence("constant_base", decl), true
		}
		// The Flask application object itself is not a value dependency.
		if v := m.vars[name]; v != nil && v.Kind() == "call" && f.set.qualified(m, pyText(m, v.ChildByFieldName("function"))) == "flask.Flask" {
			return analysis.Evidence{}, true
		}
	}
	if node.Kind() == "identifier" || node.Kind() == "attribute" {
		// A reference to the os/io/pathlib module itself is not a value dependency.
		q := f.set.qualified(m, pyText(m, node))
		switch q {
		case "os", "os.path", "posixpath", "pathlib", "io", "urllib.parse":
			root := strings.Split(pyText(m, node), ".")[0]
			if imp, ok := m.imports[root]; ok && imp.node != nil {
				return m.evidence("module_import", imp.node), true
			}
			return analysis.Evidence{}, true
		}
	}
	if f.pyConstantPath(m, node, 0) {
		return analysis.Evidence{}, true
	}
	if node.Kind() != "call" {
		return analysis.Evidence{}, false
	}
	fn := node.ChildByFieldName("function")
	q := f.set.qualified(m, pyText(m, fn))
	if pyModeledPathCalls[q] || pyPathObjectNames[q] {
		if f.set.commandTampered(m, strings.Split(q, ".")[0]) {
			return analysis.Evidence{}, false
		}
		return m.evidence("transformation", node), true
	}
	if fn != nil && fn.Kind() == "attribute" && pyPathMethods[pyText(m, fn.ChildByFieldName("attribute"))] {
		return m.evidence("transformation", node), true
	}
	return analysis.Evidence{}, false
}
