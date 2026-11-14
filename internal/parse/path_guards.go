package parse

import (
	"regexp"
	"sort"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
)

type pathGuardScan struct {
	m        *sourceModule
	info     *pathGuardInfo
	guards   []analysis.Evidence
	decls    []analysis.Evidence
	declSeen map[int]bool
	seen     map[int]bool
}

// derive extends names with variables initialized from a known name
// (`const rel = path.relative(root, full)`) so a check on the derived value is
// attributed to the operand it came from; defs keeps each derived definition.
func (g *pathGuardScan) derive(scope *sitter.Node, names map[string]bool, defs map[string]string, defNodes map[string]*sitter.Node) {
	list := func() []string {
		out := make([]string, 0, len(names))
		for name := range names {
			out = append(out, name)
		}
		sort.Strings(out)
		return out
	}
	for round := 0; round < 4; round++ {
		changed := false
		var walk func(*sitter.Node)
		walk = func(n *sitter.Node) {
			if n.Kind() == "variable_declarator" {
				id, v := n.ChildByFieldName("name"), n.ChildByFieldName("value")
				if id != nil && v != nil && id.Kind() == "identifier" {
					name := id.Utf8Text(g.m.src)
					if !names[name] && mentionsAny(v.Utf8Text(g.m.src), list()) {
						names[name] = true
						defs[name] = v.Utf8Text(g.m.src)
						defNodes[name] = v
						changed = true
					}
				}
			}
			for i := uint(0); i < n.NamedChildCount(); i++ {
				walk(n.NamedChild(i))
			}
		}
		walk(scope)
		if !changed {
			return
		}
	}
}

// assignedBetween reports an assignment to one of the mentioned names between a
// control and the call, which makes the control inspect a different value.
func (g *pathGuardScan) assignedBetween(scope *sitter.Node, from, to uint, mentioned []string) bool {
	found := false
	var walk func(*sitter.Node)
	walk = func(n *sitter.Node) {
		if found || n.EndByte() <= from || n.StartByte() >= to {
			return
		}
		if n.Kind() == "assignment_expression" || n.Kind() == "augmented_assignment_expression" {
			left := n.ChildByFieldName("left")
			if left != nil && left.Kind() == "identifier" && n.StartByte() >= from {
				for _, name := range mentioned {
					if left.Utf8Text(g.m.src) == name {
						found = true
					}
				}
			}
		}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			walk(n.NamedChild(i))
		}
	}
	walk(scope)
	return found
}

// localFunctionName names a function declared locally: a function declaration or
// a function expression assigned to a variable.
func localFunctionName(m *sourceModule, fn *sitter.Node) string {
	if fn == nil {
		return ""
	}
	if fn.Kind() == "function_declaration" {
		if id := fn.ChildByFieldName("name"); id != nil {
			return id.Utf8Text(m.src)
		}
	}
	if p := fn.Parent(); p != nil && p.Kind() == "variable_declarator" {
		if id := p.ChildByFieldName("name"); id != nil && id.Kind() == "identifier" {
			return id.Utf8Text(m.src)
		}
	}
	return ""
}

// pathGuards finds statements that dominate or enclose the filesystem call and
// mention a request-derived path value, and classifies each with AST polarity.
func (s *moduleSet) pathGuards(info *pathGuardInfo) func(*analysis.CandidateUse) ([]analysis.Evidence, []analysis.Evidence) {
	return func(u *analysis.CandidateUse) ([]analysis.Evidence, []analysis.Evidence) {
		info.ambiguousCallers = false
		m := s.modules[u.Sink.Span.File]
		if m == nil {
			return nil, nil
		}
		call := nodeAt(m.tree.RootNode(), u.Sink.Span.StartByte, u.Sink.Span.EndByte)
		if call == nil {
			return nil, nil
		}
		scan := &pathGuardScan{m: m, info: info, declSeen: map[int]bool{}, seen: map[int]bool{}}
		scan.run(u, call)
		u.Context = append(u.Context, scan.decls...)
		return scan.guards, nil
	}
}

func (scan *pathGuardScan) run(u *analysis.CandidateUse, call *sitter.Node) {
	m, info := scan.m, scan.info
	operand := map[string]bool{}
	var collect func(*sitter.Node)
	collect = func(n *sitter.Node) {
		if n.Kind() == "identifier" {
			operand[n.Utf8Text(m.src)] = true
		}
		if isFunction(n) {
			return
		}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			collect(n.NamedChild(i))
		}
	}
	if args := call.ChildByFieldName("arguments"); args != nil {
		if first := args.NamedChild(0); first != nil {
			collect(first)
		}
	}
	scope := call
	for p := call.Parent(); p != nil; p = p.Parent() {
		scope = p
		if isFunction(p) || p.Kind() == "function_declaration" {
			break
		}
	}
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
		for _, name := range commandDepNames(d) {
			names[name] = true
		}
		scan.derive(scope, names, defs, defNodes)
		list := make([]string, 0, len(names))
		for name := range names {
			list = append(list, name)
		}
		sort.Strings(list)
		all = append(all, depNames{i, names, list})
	}
	collection := func(name string) bool {
		trimmed := strings.TrimSpace(name)
		if !constantCollection(m, trimmed) {
			return false
		}
		if decl := jsTopDeclarationNode(m, trimmed); decl != nil && !scan.declSeen[int(decl.StartByte())] {
			scan.declSeen[int(decl.StartByte())] = true
			scan.decls = append(scan.decls, m.evidence("allowlist_definition", decl))
		}
		return true
	}
	baseConst := func(name string) bool {
		trimmed := strings.TrimSpace(name)
		v := topVariable(m, trimmed)
		if v == nil || shadowedAnywhere(m, trimmed) || bindingReassigned(m, trimmed) || !constantPathValue(m, v, 0) {
			return false
		}
		if decl := jsTopDeclarationNode(m, trimmed); decl != nil && !scan.declSeen[int(decl.StartByte())] {
			scan.declSeen[int(decl.StartByte())] = true
			scan.decls = append(scan.decls, m.evidence("constant_base", decl))
		}
		return true
	}
	consider := func(kind string, polarity guardPolarity, cond, whole *sitter.Node, guardEnd uint) {
		if cond == nil || scan.seen[int(whole.StartByte())] {
			return
		}
		text := cond.Utf8Text(m.src)
		covered := map[int]bool{}
		var union []string
		for _, d := range all {
			if !mentionsAny(text, d.list) || pathPresenceOnly(cond, d.list, defs, m.src, 0) {
				continue
			}
			var mentioned []string
			for _, name := range d.list {
				if mentionsAny(text, []string{name}) {
					mentioned = append(mentioned, name)
				}
			}
			if scan.assignedBetween(scope, guardEnd, call.StartByte(), mentioned) {
				continue
			}
			covered[d.idx] = true
			union = append(union, d.list...)
		}
		if len(covered) == 0 {
			return
		}
		scan.seen[int(whole.StartByte())] = true
		class, rootContain := classifyPathGuardAST(cond, m.src, polarity, union, defs, defNodes, collection, baseConst)
		if class == analysis.PathGuardPresenceOrType {
			return
		}
		ev := m.evidence(kind, whole)
		info.noteWithMeta(ev, class, covered, rootContain)
		scan.guards = append(scan.guards, ev)
	}
	climb := func(start *sitter.Node) *sitter.Node {
		child := start
		for p := start.Parent(); p != nil; p = p.Parent() {
			switch p.Kind() {
			case "statement_block", "program":
				for i := uint(0); i < p.NamedChildCount(); i++ {
					sib := p.NamedChild(i)
					if sib.StartByte() >= child.StartByte() {
						break
					}
					if sib.Kind() == "if_statement" && alwaysExits(sib.ChildByFieldName("consequence")) {
						consider("terminating_guard", guardRejectsWhenTrue, sib.ChildByFieldName("condition"), sib, sib.EndByte())
					}
				}
			case "if_statement":
				cond, cons := p.ChildByFieldName("condition"), p.ChildByFieldName("consequence")
				if cond != nil && cons != nil {
					if child.StartByte() >= cons.StartByte() && child.EndByte() <= cons.EndByte() {
						consider("enclosing_guard", guardEnforcesWhenTrue, cond, cond, cond.EndByte())
					} else if alt := p.ChildByFieldName("alternative"); alt != nil && child.StartByte() >= alt.StartByte() && child.EndByte() <= alt.EndByte() {
						consider("enclosing_guard", guardRejectsWhenTrue, cond, cond, cond.EndByte())
					}
				}
			}
			child = p
			if isFunction(p) || p.Kind() == "function_declaration" {
				return p
			}
		}
		return nil
	}
	helper := climb(call)
	scan.checkHelperCallers(u, helper, climb)
	scan.attachImplicitGuards(u)
}

func (scan *pathGuardScan) checkHelperCallers(u *analysis.CandidateUse, helper *sitter.Node, climb func(*sitter.Node) *sitter.Node) {
	m, info := scan.m, scan.info
	name := localFunctionName(m, helper)
	if name == "" {
		return
	}
	var sites []*sitter.Node
	for _, e := range u.Context {
		if e.Kind != "handler" && e.Kind != "path_handler" {
			continue
		}
		if body := nodeAt(m.tree.RootNode(), e.Span.StartByte, e.Span.EndByte); body != nil && e.Span.File == m.file {
			walkCalls(body, func(c *sitter.Node) {
				if fn := c.ChildByFieldName("function"); fn != nil && fn.Kind() == "identifier" && fn.Utf8Text(m.src) == name && !(c.StartByte() >= helper.StartByte() && c.EndByte() <= helper.EndByte()) {
					sites = append(sites, c)
				}
			})
		}
	}
	if len(sites) > 1 {
		for _, site := range sites {
			before := len(scan.guards)
			climb(site)
			siteEnforcing := false
			for _, g := range scan.guards[before:] {
				if analysis.EnforcingPathGuard(info.kinds[guardKey(g)]) {
					siteEnforcing = true
				}
			}
			if !siteEnforcing {
				info.ambiguousCallers = true
			}
		}
	} else if len(sites) == 1 {
		climb(sites[0])
	}
}

func (scan *pathGuardScan) attachImplicitGuards(u *analysis.CandidateUse) {
	m, info := scan.m, scan.info
	if e := u.Path.Extractor; e != nil && e.Assessment == "fixed_version" {
		covered := map[int]bool{}
		for i, d := range u.Dependencies {
			if d.SinkSlot == analysis.PathSlotArchive {
				covered[i] = true
			}
		}
		ev := u.Context[e.Context]
		info.note(ev, analysis.PathGuardLibraryEntryCheck, covered)
		scan.guards = append(scan.guards, ev)
	}
	if u.Path.ContractID == analysispacks.ExpressSendContract {
		if root := sendRootOption(m, u); root != nil {
			covered := map[int]bool{}
			for i, d := range u.Dependencies {
				if d.SinkSlot == analysis.PathSlotFile {
					covered[i] = true
				}
			}
			ev := m.evidence("framework_root", root)
			info.note(ev, analysis.PathGuardFrameworkRoot, covered)
			scan.guards = append(scan.guards, ev)
		}
	}
}

// sendRootOption returns the root pair of the options object of an Express send
// when its value is a constant trusted base.
func sendRootOption(m *sourceModule, u *analysis.CandidateUse) *sitter.Node {
	for _, o := range u.Path.Operands {
		if o.Slot != analysis.PathSlotOption || len(o.Context) == 0 {
			continue
		}
		e := u.Context[o.Context[0]]
		obj := nodeAt(m.tree.RootNode(), e.Span.StartByte, e.Span.EndByte)
		if obj == nil || obj.Kind() != "object" {
			continue
		}
		props, ok := jsOptions(m, obj)
		if !ok {
			continue
		}
		if v := props["root"]; v != nil && constantPathValue(m, v, 0) {
			return v
		}
	}
	return nil
}

// pathPresenceOnly distinguishes a truthiness gate from a boolean alias whose
// definition actually checks path content. Non-input feature gates do not
// establish containment; an input-taking unknown helper remains a control.
func pathPresenceOnly(n *sitter.Node, names []string, defs map[string]string, src []byte, depth int) bool {
	if n == nil || depth > 8 {
		return false
	}
	text := n.Utf8Text(src)
	if !mentionsAny(text, names) {
		return true
	}
	switch n.Kind() {
	case "parenthesized_expression":
		return n.NamedChildCount() == 1 && pathPresenceOnly(n.NamedChild(0), names, defs, src, depth+1)
	case "identifier":
		def := defs[text]
		if regexp.MustCompile(`\.(?:has|includes|indexOf|startsWith|endsWith|isAbsolute)\s*\(|[=!<>]=|&&|\|\|`).MatchString(def) {
			return false
		}
		return true
	case "member_expression", "subscript_expression":
		return true
	case "unary_expression":
		op := n.ChildByFieldName("operator")
		return op != nil && op.Utf8Text(src) == "!" && pathPresenceOnly(n.ChildByFieldName("argument"), names, defs, src, depth+1)
	case "binary_expression":
		op := n.ChildByFieldName("operator")
		if op == nil {
			return false
		}
		if op.Utf8Text(src) == "&&" || op.Utf8Text(src) == "||" {
			return pathPresenceOnly(n.ChildByFieldName("left"), names, defs, src, depth+1) && pathPresenceOnly(n.ChildByFieldName("right"), names, defs, src, depth+1)
		}
		return emptyComparison.MatchString(strings.Trim(text, "() "))
	}
	return false
}
