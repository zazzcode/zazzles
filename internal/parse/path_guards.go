package parse

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
)

// pathGuardInfo records, while the syntax context is available, the kind of
// each guard and which dependencies' derived values it mentions. The assembly
// reads it back when it attaches guards to flows.
type pathGuardInfo struct {
	kinds map[string]string
	deps  map[string]map[int]bool
	// ambiguousCallers records a helper with several call sites of which one has no
	// control, so the controls of the others cannot be attributed to the flow.
	ambiguousCallers bool
}

func newPathGuardInfo() *pathGuardInfo {
	return &pathGuardInfo{kinds: map[string]string{}, deps: map[string]map[int]bool{}}
}

func guardKey(e analysis.Evidence) string {
	return fmt.Sprintf("%s:%d:%d", e.Span.File, e.Span.StartByte, e.Span.EndByte)
}

func (g *pathGuardInfo) note(e analysis.Evidence, kind string, deps map[int]bool) {
	g.kinds[guardKey(e)] = kind
	g.deps[guardKey(e)] = deps
}

var (
	dotDotText      = regexp.MustCompile(`['"]\.\.['"]|\\\.\\\.|/\\\.\\\./|\.\.(?:/|\\\\)`)
	boundaryText    = regexp.MustCompile(`(?:\bsep\b|\bpath\.sep\b|\bos\.sep\b|["'` + "`" + `][\\/]+["'` + "`" + `]|\+\s*["'` + "`" + `][\\/])`)
	startsWithCall  = regexp.MustCompile(`(?:\.\s*(?:startsWith|startswith)\s*\(([^)]*)\))|(?:\.\s*indexOf\s*\(([^)]*)\)\s*===?\s*0)`)
	relativeCall    = regexp.MustCompile(`\.\s*(?:relative|relpath|is_relative_to|relative_to)\s*\(`)
	commonPathCall  = regexp.MustCompile(`\.\s*commonpath\s*\(`)
	membershipCall  = regexp.MustCompile(`([A-Za-z_$][\w$.]*|\[[^\]]*\])\s*\.\s*(?:has|includes|indexOf)\s*\(([^)]*)\)`)
	inOperator      = regexp.MustCompile(`([A-Za-z_$][\w$.\[\]'"]*)\s+(not\s+)?in\s+([A-Za-z_$][\w$]*|\[[^\]]*\]|\([^)]*\)|\{[^}]*\})`)
	jsSubscriptTest = regexp.MustCompile(`([A-Za-z_$][\w$]*)\s*\[\s*([A-Za-z_$][\w$.]*)\s*\]`)
	// keyPresenceTest is `'k' [not] in <container>`; emptyComparison is `x == ''`, `x != None`.
	// Neither constrains what a present value contains.
	keyPresenceTest = regexp.MustCompile(`^\s*(?:not\s+)?r?['"][\w -]*['"]\s+(?:not\s+)?in\s+[A-Za-z_][\w.]*\s*$`)
	emptyComparison = regexp.MustCompile(`^\s*(?:not\s+)?[\w.\[\]'"]+\s*(?:==|!=|is not|is)\s*(?:''|""|None|null|undefined)\s*$`)
	// separatorText is a test for a path separator character in the value.
	separatorText = regexp.MustCompile(`(?:includes|indexOf|contains|find)\s*\(\s*(?:path\.sep|os\.sep|['"][\\/]['"])\s*\)|['"][\\/]['"]\s+(?:not\s+)?in\b|\b(?:os|path)\.sep\s+(?:not\s+)?in\b`)
	constantList  = regexp.MustCompile(`^[\[\(\{]\s*(?:(?:r?['"][^'"]*['"])\s*(?::\s*[^,\]\)\}]*)?\s*,?\s*)+[\]\)\}]$`)
)

// classifyPathGuardText classifies a control that mentions the path value.
// defs maps a derived variable to its defining expression so a check on
// `rel` is understood as the relative-path check it came from. collectionIs
// reports whether an identifier is a constant finite collection of literals.
func classifyPathGuardText(cond string, names []string, defs map[string]string, collectionIs func(string) bool) string {
	if keyPresenceTest.MatchString(cond) || emptyComparison.MatchString(cond) {
		return analysis.PathGuardPresenceOrType
	}
	text := cond
	related := cond
	for name, def := range defs {
		if mentionsAny(cond, []string{name}) {
			related += " " + def
		}
	}
	for _, m := range membershipCall.FindAllStringSubmatch(text, -1) {
		receiver, arg := strings.TrimSpace(m[1]), m[2]
		if !mentionsAny(arg, names) || mentionsAny(receiver, names) {
			continue
		}
		if (strings.HasPrefix(receiver, "[") && constantList.MatchString(receiver)) || collectionIs(receiver) {
			return analysis.PathGuardAllowlist
		}
	}
	for _, m := range inOperator.FindAllStringSubmatch(text, -1) {
		left, right := strings.TrimSpace(m[1]), strings.TrimSpace(m[3])
		if !mentionsAny(left, names) || mentionsAny(right, names) {
			continue
		}
		if constantList.MatchString(right) || collectionIs(right) {
			return analysis.PathGuardAllowlist
		}
	}
	for _, m := range jsSubscriptTest.FindAllStringSubmatch(text, -1) {
		if mentionsAny(m[2], names) && collectionIs(m[1]) {
			return analysis.PathGuardAllowlist
		}
	}
	switch {
	case commonPathCall.MatchString(related):
		return analysis.PathGuardCommonPath
	case relativeCall.MatchString(related):
		return analysis.PathGuardRelative
	}
	if m := startsWithCall.FindStringSubmatch(related); m != nil {
		arg := m[1] + m[2]
		if boundaryText.MatchString(arg) {
			return analysis.PathGuardPrefixBoundary
		}
		if dotDotText.MatchString(arg) {
			return analysis.PathGuardDotDotText
		}
		return analysis.PathGuardPrefixBare
	}
	if dotDotText.MatchString(text) {
		return analysis.PathGuardDotDotText
	}
	if separatorText.MatchString(text) {
		return analysis.PathGuardSeparatorText
	}
	return analysis.PathGuardUnclassified
}

type pathGuardScan struct {
	m      *sourceModule
	info   *pathGuardInfo
	guards []analysis.Evidence
	seen   map[int]bool
}

// derive extends names with variables initialized from a known name
// (`const rel = path.relative(root, full)`) so a check on the derived value is
// attributed to the operand it came from; defs keeps each derived definition.
func (g *pathGuardScan) derive(scope *sitter.Node, names map[string]bool, defs map[string]string) {
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
// mention a request-derived path value, and classifies each. Presence and type
// tests are not recorded: they never constrain content.
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
		scan := &pathGuardScan{m: m, info: info, seen: map[int]bool{}}
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
		// Per dependency: the operand's own identifiers plus that dependency's
		// value chain, extended through derived variables.
		type depNames struct {
			idx   int
			names map[string]bool
			list  []string
		}
		var all []depNames
		defs := map[string]string{}
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
			scan.derive(scope, names, defs)
			list := make([]string, 0, len(names))
			for name := range names {
				list = append(list, name)
			}
			sort.Strings(list)
			all = append(all, depNames{i, names, list})
		}
		collection := func(name string) bool { return constantCollection(m, strings.TrimSpace(name)) }
		consider := func(kind string, cond, whole *sitter.Node, guardEnd uint) {
			if cond == nil || scan.seen[int(whole.StartByte())] {
				return
			}
			text := cond.Utf8Text(m.src)
			covered := map[int]bool{}
			var union []string
			for _, d := range all {
				if !mentionsAny(text, d.list) || presenceOnlyCondition(text, d.list) {
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
			class := classifyPathGuardText(text, union, defs, collection)
			if class == analysis.PathGuardPresenceOrType {
				return // a presence or emptiness test never constrains content
			}
			ev := m.evidence(kind, whole)
			info.note(ev, class, covered)
			scan.guards = append(scan.guards, ev)
		}
		// climb collects the controls that dominate or enclose start within its
		// function and returns that function.
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
							consider("terminating_guard", sib.ChildByFieldName("condition"), sib, sib.EndByte())
						}
					}
				case "if_statement":
					cond := p.ChildByFieldName("condition")
					if cond != nil && int(child.StartByte()) >= int(cond.EndByte()) {
						consider("enclosing_guard", cond, cond, cond.EndByte())
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
		if name := localFunctionName(m, helper); name != "" {
			// The sink is inside a local helper: the controls that dominate its call
			// site in the calling function apply to the values passed in. Several call
			// sites cannot be told apart, so any site without a control leaves the
			// flow unresolved rather than borrowing a sibling's control.
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
			unguarded := false
			for _, site := range sites {
				before := len(scan.guards)
				climb(site)
				if len(scan.guards) == before && len(sites) > 1 {
					unguarded = true
				}
			}
			if unguarded {
				info.ambiguousCallers = true
			}
		}
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
		return scan.guards, nil
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
