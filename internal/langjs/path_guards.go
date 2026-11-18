package langjs

import (
	"regexp"
	"sort"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
	"github.com/zazzcode/zazzles/internal/parse"
)

type pathGuardScan struct {
	m        *sourceModule
	info     *parse.PathGuardInfo
	guards   []analysis.Evidence
	decls    []analysis.Evidence
	declSeen map[int]bool
	seen     map[int]bool
	// next enables the Next.js presence and type-only schema classification.
	next bool
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
func (s *moduleSet) pathGuards(info *parse.PathGuardInfo) func(*analysis.CandidateUse) ([]analysis.Evidence, []analysis.Evidence) {
	return func(u *analysis.CandidateUse) ([]analysis.Evidence, []analysis.Evidence) {
		info.AmbiguousCallers = false
		m := s.modules[u.Sink.Span.File]
		if m == nil {
			return nil, nil
		}
		call := parse.NodeAt(m.tree.RootNode(), u.Sink.Span.StartByte, u.Sink.Span.EndByte)
		if call == nil {
			return nil, nil
		}
		scan := &pathGuardScan{m: m, info: info, declSeen: map[int]bool{}, seen: map[int]bool{}, next: s.nextProjectFor(m.file) != nil}
		scan.run(u, call)
		u.Context = append(u.Context, scan.decls...)
		return scan.guards, s.catchAllJoinTransforms(m, u)
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
	lang := m.guardLang()
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
	consider := func(kind string, polarity parse.GuardPolarity, cond, whole *sitter.Node, guardEnd uint) {
		if cond == nil || scan.seen[int(whole.StartByte())] {
			return
		}
		text := cond.Utf8Text(m.src)
		covered := map[int]bool{}
		var union []string
		for _, d := range all {
			if !parse.MentionsAny(text, d.list) || pathPresenceOnly(cond, d.list, defs, m.src, 0) {
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
		scan.seen[int(whole.StartByte())] = true
		if scan.next && nonContainingTest(m, cond, union, u) {
			return
		}
		class, rootContain := parse.ClassifyPathGuardAST(cond, m.src, polarity, union, defs, defNodes, collection, baseConst)
		if class == analysis.PathGuardPresenceOrType {
			return
		}
		ev := m.evidence(kind, whole)
		info.NoteWithMeta(ev, class, covered, rootContain)
		scan.guards = append(scan.guards, ev)
	}
	climb := func(start *sitter.Node) *sitter.Node {
		return lang.Climb(start, func(site parse.GuardSite) {
			consider(site.Kind, site.Polarity, site.Cond, site.Whole, site.End)
		})
	}
	helper := climb(call)
	scan.checkHelperCallers(u, helper, climb)
	scan.attachImplicitGuards(u)
	if scan.next {
		for _, d := range all {
			scan.lookupPreconditions(call, d.idx, d.list)
		}
		for i, d := range u.Dependencies {
			if d.SinkSlot != analysis.PathSlotFile {
				continue
			}
			for _, t := range d.Transfers {
				if separatorStrippingReplace(t.Text) && !scan.seen[t.Span.StartByte] {
					scan.seen[t.Span.StartByte] = true
					ev := t
					ev.Kind = "component_sanitizer"
					scan.info.NoteWithMeta(ev, analysis.PathGuardComponentSanitizer, map[int]bool{i: true}, false)
					scan.guards = append(scan.guards, ev)
					break // one sanitizer per path; its assignment repeats it
				}
			}
		}
	}
}

var replaceNegatedClass = regexp.MustCompile(`\.replace(?:All)?\(\s*/\[\^([^\]\\/]*)\]\+?/g[a-z]*\s*,\s*("[^"/\\]*"|'[^'/\\]*')\s*\)\s*$`)

// separatorStrippingReplace reports `x.replace(/[^allowed]/g, "_")` whose
// allowed class and replacement contain no path separator: the result is a
// single path component (it cannot contain / or \\).
func separatorStrippingReplace(text string) bool {
	m := replaceNegatedClass.FindStringSubmatch(strings.TrimSpace(text))
	return m != nil && !strings.ContainsAny(m[1], "/\\")
}

// lookupPreconditions records, in Next.js code, an early exit when a Prisma
// record lookup keyed by the tracked value finds nothing (`const p = await
// prisma.x.findUnique({ where: { id } }); if (!p) return ...`). The value must
// then equal an existing key. Whether that contains the path is the
// assessment's question, so the guard is recorded unclassified, never as proof.
func (scan *pathGuardScan) lookupPreconditions(call *sitter.Node, dep int, names []string) {
	m := scan.m
	var fn *sitter.Node
	for p := call.Parent(); p != nil; p = p.Parent() {
		if isFunction(p) || p.Kind() == "function_declaration" {
			fn = p
			break
		}
	}
	if fn == nil {
		return
	}
	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		if n.StartByte() >= call.StartByte() || (isFunction(n) && n != fn) {
			return
		}
		if n.Kind() == "if_statement" && n.EndByte() <= call.StartByte() && !scan.seen[int(n.StartByte())] {
			cond := unwrapTS(n.ChildByFieldName("condition"))
			for cond != nil && cond.Kind() == "unary_expression" {
				cond = unwrapTS(cond.ChildByFieldName("argument"))
			}
			body := n.ChildByFieldName("consequence")
			if cond != nil && cond.Kind() == "identifier" && body != nil && exitsBlock(m, body) {
				def := unwrapTS(definitionAt(m, cond, cond.Utf8Text(m.src)))
				if def != nil && def.Kind() == "await_expression" && def.NamedChildCount() == 1 {
					def = unwrapTS(def.NamedChild(0))
				}
				if def != nil && def.Kind() == "call_expression" {
					if fnText := def.ChildByFieldName("function"); fnText != nil && prismaFilterMethods[lastSegment(fnText.Utf8Text(m.src))] {
						if args := def.ChildByFieldName("arguments"); args != nil && strings.Contains(args.Utf8Text(m.src), "where") && parse.MentionsAny(args.Utf8Text(m.src), names) {
							scan.seen[int(n.StartByte())] = true
							ev := m.evidence("guard_test", n)
							scan.info.NoteWithMeta(ev, analysis.PathGuardUnclassified, map[int]bool{dep: true}, false)
							scan.guards = append(scan.guards, ev)
						}
					}
				}
			}
		}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			visit(n.NamedChild(i))
		}
	}
	visit(fn.ChildByFieldName("body"))
}

func lastSegment(s string) string {
	if i := strings.LastIndex(s, "."); i >= 0 {
		return s[i+1:]
	}
	return s
}

// exitsBlock reports a consequence that returns, throws or calls a Next.js
// navigation exit.
func exitsBlock(m *sourceModule, n *sitter.Node) bool {
	switch n.Kind() {
	case "return_statement", "throw_statement":
		return true
	case "expression_statement":
		return n.NamedChildCount() == 1 && nextNavigationExit(m, n.NamedChild(0))
	case "statement_block":
		for i := uint(0); i < n.NamedChildCount(); i++ {
			if exitsBlock(m, n.NamedChild(i)) {
				return true
			}
		}
	}
	return false
}

func (scan *pathGuardScan) checkHelperCallers(u *analysis.CandidateUse, helper *sitter.Node, climb func(*sitter.Node) *sitter.Node) {
	info := scan.info
	sites := jsHelperCallSites(scan.m, u.Context, helper)
	if len(sites) > 1 {
		for _, site := range sites {
			before := len(scan.guards)
			climb(site)
			siteEnforcing := false
			for _, g := range scan.guards[before:] {
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
		info.Note(ev, analysis.PathGuardLibraryEntryCheck, covered)
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
			info.Note(ev, analysis.PathGuardFrameworkRoot, covered)
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
		obj := parse.NodeAt(m.tree.RootNode(), e.Span.StartByte, e.Span.EndByte)
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
	if !parse.MentionsAny(text, names) {
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
		return parse.EmptyComparison.MatchString(strings.Trim(text, "() "))
	}
	return false
}

// nonContainingTest recognizes, in Next.js code, two tests that cannot contain
// a path: a bare truthiness test of the tracked value (`if (!file)`) and a
// zod `success` test of a validation helper result whose schema rule for every
// tracked field is type-only (z.string() with optional/length modifiers). A
// schema with a regex, enum, refine or similar rule stays a possible control.
func nonContainingTest(m *sourceModule, cond *sitter.Node, names []string, u *analysis.CandidateUse) bool {
	src := m.src
	fields := trackedFields(u)
	c := unwrapTS(cond)
	if c != nil && c.Kind() == "binary_expression" {
		// `ext === ".pdf"` on extname(value), or a sibling validated field
		// compared with a literal: neither constrains the path text.
		op := c.ChildByFieldName("operator")
		l, r := unwrapTS(c.ChildByFieldName("left")), unwrapTS(c.ChildByFieldName("right"))
		if op != nil && (op.Utf8Text(src) == "===" || op.Utf8Text(src) == "!==" || op.Utf8Text(src) == "==" || op.Utf8Text(src) == "!=") && l != nil && r != nil {
			id := l
			if l.Kind() == "string" {
				id = r
			} else if r.Kind() != "string" {
				return false
			}
			if id.Kind() != "identifier" {
				return false
			}
			def := definitionAt(m, id, id.Utf8Text(src))
			if def == nil {
				return false
			}
			d := strings.TrimSpace(def.Utf8Text(src))
			if extnameCall.MatchString(d) {
				return true
			}
			if sm := siblingField.FindStringSubmatch(d); sm != nil && len(fields) > 0 && !fields[sm[1]] {
				return true
			}
		}
		return false
	}
	for c != nil && c.Kind() == "unary_expression" {
		if op := c.ChildByFieldName("operator"); op == nil || op.Utf8Text(src) != "!" {
			return false
		}
		c = unwrapTS(c.ChildByFieldName("argument"))
	}
	if c == nil {
		return false
	}
	text := c.Utf8Text(src)
	in := func(name string) bool {
		for _, n := range names {
			if n == name {
				return true
			}
		}
		return false
	}
	if c.Kind() == "identifier" && in(text) {
		return true
	}
	if c.Kind() != "member_expression" {
		return false
	}
	obj, prop := c.ChildByFieldName("object"), c.ChildByFieldName("property")
	if obj == nil || prop == nil || obj.Kind() != "identifier" || prop.Utf8Text(src) != "success" {
		return false
	}
	if !in(obj.Utf8Text(src)) && !validatedResult(m, obj, u) {
		return false
	}
	var schemas []string
	for _, e := range u.Context {
		if e.Kind == "validation_schema" {
			schemas = append(schemas, e.Text)
		}
	}
	if len(schemas) == 0 || len(fields) == 0 {
		return false
	}
	for field := range fields {
		typeOnly := false
		for _, schema := range schemas {
			typeOnly = typeOnly || zodFieldTypeOnly(schema, field)
		}
		if !typeOnly {
			return false
		}
	}
	return true
}

var zodTypeOnlyRule = regexp.MustCompile(`^z\.(?:coerce\.)?string\(\)(?:\.(?:optional|nullable|nullish|trim|toLowerCase|toUpperCase)\(\)|\.(?:min|max|length)\(\s*\d+\s*(?:,[^)]*)?\)|\.(?:default|describe)\([^()]*\))*$`)

// zodFieldTypeOnly reports a `field: z.string()...` rule in schema source whose
// only modifiers are optionality, trimming, case and length.
func zodFieldTypeOnly(schema, field string) bool {
	re := regexp.MustCompile(`(?m)(?:^|[{,\s])` + regexp.QuoteMeta(field) + `\s*:\s*(z\.[^,\n}]*)`)
	m := re.FindStringSubmatch(schema)
	if m == nil {
		return false
	}
	rule := strings.Join(strings.Fields(m[1]), "")
	return zodTypeOnlyRule.MatchString(rule)
}

var extnameCall = regexp.MustCompile(`^(?:path\.)?extname\(`)
var siblingField = regexp.MustCompile(`^[A-Za-z_$][\w$]*\.data\.([A-Za-z_$][\w$]*)(?:\s*\?\?.*)?$`)

// trackedFields lists the validated fields a use's dependencies project.
func trackedFields(u *analysis.CandidateUse) map[string]bool {
	fields := map[string]bool{}
	for _, d := range u.Dependencies {
		validated := false
		for _, t := range d.Transfers {
			if t.Kind == "validated_parse" {
				validated = true
			}
			if validated && t.Kind == "field_projection" {
				fields[strings.Trim(t.Text, `"' `)] = true
			}
		}
	}
	return fields
}

// validatedResult reports a local bound to the validation helper call that a
// dependency of u passed through (its validated_parse transfer).
func validatedResult(m *sourceModule, id *sitter.Node, u *analysis.CandidateUse) bool {
	def := unwrapTS(definitionAt(m, id, id.Utf8Text(m.src)))
	if def != nil && def.Kind() == "await_expression" && def.NamedChildCount() == 1 {
		def = unwrapTS(def.NamedChild(0))
	}
	if def == nil {
		return false
	}
	for _, d := range u.Dependencies {
		for _, t := range d.Transfers {
			if t.Kind == "validated_parse" && t.Span.File == m.file && t.Span.StartByte == int(def.StartByte()) && t.Span.EndByte == int(def.EndByte()) {
				return true
			}
		}
	}
	return false
}
