package parse

import (
	"regexp"
	"sort"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
)

// commandRequiredRoles are the mandatory evidence obligations of the claim,
// unioned with the catalog's selected obligations by policy.
var commandRequiredRoles = []string{"input_source", "sink_binding", "invoked_callable", "control_flow", "command_operands", "execution_configuration"}

const commandScope = "command execution claim over the supplied entry invocation, verified process API contract, effective operands, execution configuration and guard/transfer context; an unsafe witness needs only its own source-to-operand path"

func commandFields(u analysis.CandidateUse, entry analysis.EntryPoint) []string {
	fields := map[string]bool{}
	for _, d := range u.Dependencies {
		if entry.Kind == "graphql" || entry.Kind == "grpc" {
			fields[d.Source.Text] = true
			continue
		}
		parts := strings.Split(d.Source.Text, ".")
		if len(parts) > 2 {
			fields[parts[len(parts)-1]] = true
		}
	}
	out := []string{}
	for name := range fields {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// commandCompleteness builds the claim-scoped completeness shared by every
// language adapter. Language adapters supply blockers, guard evidence and
// supported-transfer evidence they established from source.
func commandCompleteness(u *analysis.CandidateUse, extraRoles map[string][]analysis.Evidence, blockers, coverage []analysis.Gap) *analysis.Completeness {
	// Control-kind evidence in a command use must not become an applicable control
	// of the shared invocation context: that would change the invocation identity
	// and every existing sibling candidate ID. The kinds are namespaced here and
	// restored as role names below.
	for i, e := range u.Context {
		switch e.Kind {
		case "guard_test", "conditional_test", "branch_precondition", "authentication_adapter", "invoked_callable":
			u.Context[i].Kind = "command_" + e.Kind
		}
	}
	roles := evidenceRoles(u.Context)
	for kind, items := range roles {
		if strings.HasPrefix(kind, "command_") {
			switch strings.TrimPrefix(kind, "command_") {
			case "guard_test", "conditional_test", "branch_precondition", "authentication_adapter", "invoked_callable":
				roles[strings.TrimPrefix(kind, "command_")] = append(roles[strings.TrimPrefix(kind, "command_")], items...)
				delete(roles, kind)
			}
		}
	}
	c := &analysis.Completeness{ClaimKind: "command_execution", Required: append([]string{}, commandRequiredRoles...),
		Evidence: roles, Blockers: blockers, Coverage: coverage, Scope: commandScope}
	if c.Blockers == nil {
		c.Blockers = []analysis.Gap{}
	}
	if c.Coverage == nil {
		c.Coverage = []analysis.Gap{}
	}
	for role, items := range extraRoles {
		c.Evidence[role] = append(c.Evidence[role], items...)
	}
	c.Evidence["command_operands"] = c.Evidence["command_operand"]
	delete(c.Evidence, "command_operand")
	for _, d := range u.Dependencies {
		c.Evidence["input_source"] = append(c.Evidence["input_source"], d.Source)
	}
	if len(c.Evidence["invoked_callable"]) == 0 {
		c.Evidence["invoked_callable"] = append([]analysis.Evidence{}, c.Evidence["handler"]...)
	}
	f := u.Command
	c.ModelFacts = []string{
		"Platform assumption: " + f.Platform + " semantics are a declared analysis assumption, not inferred from the scanner host; Windows, batch, cmd and PowerShell behavior is not modeled.",
		"Verified operation " + f.Operation + "; API shell mode " + f.APIShellMode + ", effective shell mode " + f.EffectiveShellMode + commandInterpreterFact(f) + ", argv shape " + f.ArgvShape + ".",
		"Dependency, operand and path records in command facts refer to the evidence table by index. Each path keeps its own source, transfers and guard facts; a guard or constraint on one operand, branch or invocation does not protect another.",
	}
	return c
}

func commandInterpreterFact(f *analysis.CommandFacts) string {
	if f.Interpreter == "" {
		return ""
	}
	return " (interpreter " + f.Interpreter + ")"
}

// commandDepNames lists the identifiers a dependency is reachable by: its
// source text and the names it was assigned or projected to.
var commandIdentifier = regexp.MustCompile(`^\s*([A-Za-z_$][\w$]*)`)

func commandDepNames(d analysis.Dependency) []string {
	python := strings.HasSuffix(d.Source.Span.File, ".py")
	var names []string
	if !python {
		names = append(names, d.Source.Text)
	}
	for _, t := range d.Transfers {
		switch t.Kind {
		case "assignment", "value_reference", "argument_to_parameter":
			if m := commandIdentifier.FindStringSubmatch(t.Text); len(m) == 2 {
				names = append(names, m[1])
			}
		case "field_projection":
			if python {
				// The projected request expression, never the bare key literal.
				if strings.ContainsAny(t.Text, "([") {
					names = append(names, t.Text)
				}
			} else if m := commandIdentifier.FindStringSubmatch(t.Text); len(m) == 2 {
				names = append(names, m[1])
			}
		}
	}
	return names
}

var presenceWords = regexp.MustCompile(`\b(not|is|None|and|or|typeof|null|undefined|string|true|false|len)\b`)

// environmentTests are request-method and framework-version comparisons: they
// select a path but never constrain the content of an operand.
var environmentTests = regexp.MustCompile(`[\w.]*\.(method|VERSION)[\w\[\]]*\s*(==|!=|<=|>=|<|>)\s*("[^"]*"|'[^']*'|\d+)`)

// requestAccessors are keyed reads such as request.GET.get("x"): a read, not a constraint.
var requestAccessors = regexp.MustCompile(`[\w.]+\.get\([^)]*\)`)
var stringLiterals = regexp.MustCompile(`"[^"]*"|'[^']*'`)
var presencePunct = regexp.MustCompile(`[\s()!=<>'"&|]`)

// presenceOnlyCondition reports a condition that only tests whether the
// operands exist, are non-empty or have a runtime type. Such a test does not
// constrain content and is never recorded as a guard.
func presenceOnlyCondition(condition string, names []string) bool {
	rest := requestAccessors.ReplaceAllString(condition, "")
	ordered := append([]string{}, names...)
	// Longest names first so a container prefix never splits a projection.
	sort.Slice(ordered, func(i, j int) bool { return len(ordered[i]) > len(ordered[j]) })
	for _, name := range ordered {
		if name != "" {
			rest = strings.ReplaceAll(rest, name, "")
		}
	}
	rest = environmentTests.ReplaceAllString(rest, "")
	rest = presenceWords.ReplaceAllString(rest, "")
	rest = presencePunct.ReplaceAllString(rest, "")
	return rest == ""
}

var plainIdentifier = regexp.MustCompile(`^[A-Za-z_$][\w$]*$`)

// mentionsAny matches identifiers by word boundary and expressions exactly.
func mentionsAny(text string, names []string) bool {
	for _, name := range names {
		if name == "" {
			continue
		}
		if plainIdentifier.MatchString(name) {
			// Text inside string literals is data, never a reference to the operand.
			text := stringLiterals.ReplaceAllString(text, `""`)
			if regexp.MustCompile(`(^|[^\w$.])` + regexp.QuoteMeta(name) + `($|[^\w$])`).MatchString(text) {
				return true
			}
		} else if strings.Contains(text, name) {
			return true
		}
	}
	return false
}

// finishCommandPaths records, per path, the guards found for that
// dependency and whether an unresolved transfer blocks it. A guard that does
// not mention a dependency never covers it; adequacy is never decided here.
// guardContext[i] is the use.Context index of guards[i].
func finishCommandPaths(u *analysis.CandidateUse, c *analysis.Completeness, guards []analysis.Evidence, guardContext []int, touches func(analysis.Gap, analysis.Dependency) bool) {
	f := u.Command
	for i := range f.Paths {
		p := &f.Paths[i]
		dep := u.Dependencies[p.Dependency]
		names := commandDepNames(dep)
		var controls []int
		for j, g := range guards {
			if mentionsAny(g.Text, names) {
				controls = append(controls, guardContext[j])
			}
		}
		unknown := false
		for _, g := range c.Blockers {
			if touches(g, dep) {
				unknown = true
			}
		}
		switch {
		case unknown:
			p.Protection = "unknown"
			p.Reason = "an unresolved transfer or helper touches this source-to-operand path"
		case len(controls) > 0:
			p.Protection = "guarded"
			p.Controls = controls
			p.Reason = "a dominating or enclosing control mentions this operand; its adequacy is not established by the scanner"
		default:
			p.Protection = "raw"
		}
	}
	if len(guards) > 0 {
		c.Evidence["guard"] = append(c.Evidence["guard"], guards...)
	}
	// A per-path summary so one unresolved sibling is not mistaken for the state of every path.
	summary := []string{}
	for _, p := range f.Paths {
		summary = append(summary, "dependency "+itoa(p.Dependency)+" ("+u.Dependencies[p.Dependency].Source.Text+") -> "+p.Operand+": "+p.Protection)
	}
	if len(summary) > 0 {
		c.ModelFacts = append(c.ModelFacts, "Operand path facts: "+strings.Join(summary, "; ")+". A raw or guarded path is an independent source-to-operand witness; an unknown sibling path stays visible as a blocker for that path only and does not make a supported raw path unknown.")
	}
}

// assembleCommandClaims completes every Node command candidate before catalog
// attachment: claim kind, roles, blockers, guard evidence and the selected
// contract. It runs with and without explicit check files.
func (s *moduleSet) assembleCommandClaims(report *analysis.AnalysisReport) {
	entries := map[string]analysis.EntryPoint{}
	for _, e := range report.Entries {
		entries[e.ID] = e
	}
	for i := range report.Uses {
		u := &report.Uses[i]
		if u.Kind != "command_execution_candidate" || u.Command == nil || u.Completeness != nil {
			continue
		}
		entry, ok := entries[u.EntryID]
		if !ok {
			continue
		}
		fields := commandFields(*u, entry)
		check := analysis.Check{ID: "automatic-command", Kind: "command_execution", Fields: fields}
		switch entry.Kind {
		case "graphql":
			check.Selector = &analysis.EntrySelector{Kind: "graphql", Type: entry.GraphQL.Type, Field: entry.GraphQL.Field}
		case "grpc":
			service := entry.GRPC.Service
			if entry.GRPC.Package != "" {
				service = entry.GRPC.Package + "." + service
			}
			check.Selector = &analysis.EntrySelector{Kind: "grpc", Service: service, Method: entry.GRPC.Method}
		default:
			check.Method, check.Path = entry.HTTPRoute().Method, entry.HTTPRoute().PathPattern
		}
		s.contextLimits = nil
		s.contextFields = fields
		// Only this invocation's entry supplies chain evidence: a sibling entry with an
		// identical (empty) selector must not contribute its registration gaps.
		scoped := *report
		scoped.Entries = []analysis.EntryPoint{entry}
		chain, chainGaps := s.chainEvidence(&scoped, check)
		chainGaps = s.withoutTransportOnlyGaps(chainGaps)
		blockers := []analysis.Gap{}
		for _, g := range append(append([]analysis.Gap{}, chainGaps...), s.contextLimits...) {
			// The process call itself receives the request value; that is the claim, not a missing helper.
			if g.Kind == "input_helper_unresolved" && g.At.File == u.Sink.Span.File && g.At.StartByte >= u.Sink.Span.StartByte && g.At.EndByte <= u.Sink.Span.EndByte {
				continue
			}
			blockers = append(blockers, g)
		}

		// Control flow of the supplied handlers.
		controlComplete := false
		var complete []analysis.Evidence
		extra := map[string][]analysis.Evidence{"invoked_callable": nil}
		for _, e := range u.Context {
			if e.Kind != "handler" {
				continue
			}
			module := s.modules[e.Span.File]
			if module == nil {
				continue
			}
			body := nodeAt(module.tree.RootNode(), e.Span.StartByte, e.Span.EndByte)
			if body == nil {
				continue
			}
			edges, missing := controlContext(module, body)
			u.ControlEdges = append(u.ControlEdges, edges...)
			blockers = append(blockers, missing...)
			controlComplete = len(missing) == 0
			if controlComplete {
				complete = append(complete, e)
			}
			extra["control_flow"] = append(extra["control_flow"], e)
		}
		// Guards that dominate or enclose the call and mention an operand.
		guards, transforms := s.commandGuards(u)
		guardIndex := []int{}
		for _, g := range guards {
			guardIndex = append(guardIndex, len(u.Context))
			u.Context = append(u.Context, g)
		}
		u.Context = append(u.Context, chain...)
		coverage := []analysis.Gap{}
		for _, g := range u.Gaps {
			switch {
			case s.commandGapCovered(u, g, controlComplete, complete, transforms, extra):
				coverage = append(coverage, g)
			default:
				blockers = append(blockers, g)
			}
		}
		c := commandCompleteness(u, extra, blockers, coverage)
		if len(chain) > 0 && len(chainGaps) == 0 && len(s.contextLimits) == 0 {
			// Supplied route/middleware context supersedes discovery's generic warning.
			remaining := []analysis.Gap{}
			for _, g := range c.Coverage {
				if g.Kind == "middleware_unresolved" {
					c.Resolved = append(c.Resolved, g)
				} else {
					remaining = append(remaining, g)
				}
			}
			c.Coverage = remaining
		}
		for _, t := range transforms {
			c.ModelFacts = append(c.ModelFacts, "Supported transfer "+t.Text+" at "+t.Span.File+" carries its receiver into the result; judge whether its pattern constrains the value. The transfer is not a validator by itself.")
		}
		finishCommandPaths(u, c, guards, guardIndex, func(g analysis.Gap, d analysis.Dependency) bool { return gapTouchesDependency(g, d) })
		u.Completeness = c
		u.APIModel = analysispacks.CommandContract(u.Command.ContractID)
		u.Gaps = append(append([]analysis.Gap{}, u.Gaps...), c.Blockers...)
		u.Gaps = dedupeGaps(u.Gaps)
		u.Check = nil
	}
}

func dedupeGaps(in []analysis.Gap) []analysis.Gap {
	seen := map[string]bool{}
	out := []analysis.Gap{}
	for _, g := range in {
		key := g.Kind + "|" + g.Detail + "|" + g.At.File + "|" + string(rune(g.At.StartByte))
		if !seen[key] {
			seen[key] = true
			out = append(out, g)
		}
	}
	return out
}

// gapTouchesDependency reports whether the gap lies on this dependency's
// source or transfer chain, excluding enclosing statements that merely
// contain unrelated operands.
func gapTouchesDependency(g analysis.Gap, d analysis.Dependency) bool {
	for _, e := range append([]analysis.Evidence{d.Source}, d.Transfers...) {
		if e.Kind != "input_source" && e.Kind != "call_argument_dependency" {
			continue
		}
		if g.At.File == e.Span.File && g.At.StartByte >= e.Span.StartByte && g.At.EndByte <= e.Span.EndByte {
			return true
		}
	}
	return false
}

// commandGapCovered decides whether a discovery gap leaves the command claim
// intact. A gap on a request-derived operand path stays a blocker unless it
// is a supported transfer or an unrelated response/output limitation.
func (s *moduleSet) commandGapCovered(u *analysis.CandidateUse, g analysis.Gap, controlComplete bool, complete []analysis.Evidence, transforms []analysis.Evidence, extra map[string][]analysis.Evidence) bool {
	switch g.Kind {
	case "middleware_unresolved", "unsupported_callback", "async_response_unresolved", "async_continuation", "command_shell_option_ignored", "command_configuration_request_controlled", "external_response_unresolved":
		return true
	case "unknown_call_result":
		// The process call's own return value and callback are not command operands.
		return !s.touchesAnyDependency(g, *u)
	case "unknown_transfer", "unknown_value":
		if !s.touchesAnyDependency(g, *u) {
			return true
		}
		m := s.modules[g.At.File]
		var n *sitter.Node
		if m != nil {
			n = nodeAt(m.tree.RootNode(), g.At.StartByte, g.At.EndByte)
		}
		if n != nil && nativeStringOperation(m, n) {
			extra["transformation"] = append(extra["transformation"], m.evidence("transformation", n))
			return true
		}
		for _, t := range transforms {
			if t.Span.File == g.At.File && t.Span.StartByte == g.At.StartByte && t.Span.EndByte == g.At.EndByte {
				extra["transformation"] = append(extra["transformation"], t)
				return true
			}
		}
		return false
	case "unsupported_control_flow", "unknown_control_effect":
		return controlComplete
	case "branch_exit":
		for _, body := range complete {
			if g.At.File == body.Span.File && g.At.StartByte >= body.Span.StartByte && g.At.EndByte <= body.Span.EndByte {
				return true
			}
		}
		return false
	case "conditional_merge":
		m := s.modules[g.At.File]
		if m != nil {
			if n := nodeAt(m.tree.RootNode(), g.At.StartByte, g.At.EndByte); n != nil && n.Kind() == "ternary_expression" {
				extra["conditional_value"] = append(extra["conditional_value"], m.evidence("conditional_value", n))
				return true
			}
		}
		return false
	case "input_validation_absent", "input_validation_unresolved", "input_validation_middleware", "validation_insufficient_for_sink", "validation_type_only", "sink_must_bind_free_text", "validation_free_text_bound":
		// Field policy is a separate claim.
		return true
	}
	return false
}

func (s *moduleSet) touchesAnyDependency(g analysis.Gap, u analysis.CandidateUse) bool {
	for _, d := range u.Dependencies {
		if gapTouchesDependency(g, d) {
			return true
		}
	}
	return false
}

// commandGuards finds statements that dominate or enclose the process call
// and mention a request-derived operand identifier or source. It also
// returns supported regex-capture transfers on operand paths.
func (s *moduleSet) commandGuards(u *analysis.CandidateUse) (guards, transforms []analysis.Evidence) {
	m := s.modules[u.Sink.Span.File]
	if m == nil {
		return nil, nil
	}
	call := nodeAt(m.tree.RootNode(), u.Sink.Span.StartByte, u.Sink.Span.EndByte)
	if call == nil {
		return nil, nil
	}
	names := map[string]bool{}
	args := call.ChildByFieldName("arguments")
	var collect func(*sitter.Node)
	collect = func(n *sitter.Node) {
		if n.Kind() == "identifier" {
			names[n.Utf8Text(m.src)] = true
		}
		if isFunction(n) {
			return
		}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			collect(n.NamedChild(i))
		}
	}
	if args != nil {
		collect(args)
	}
	for _, d := range u.Dependencies {
		for _, name := range commandDepNames(d) {
			names[name] = true
		}
	}
	mentions := func(cond *sitter.Node) bool {
		if cond == nil {
			return false
		}
		list := make([]string, 0, len(names))
		for name := range names {
			list = append(list, name)
		}
		text := cond.Utf8Text(m.src)
		return mentionsAny(text, list) && !presenceOnlyCondition(text, list)
	}
	seen := map[int]bool{}
	add := func(kind string, n *sitter.Node) {
		if !seen[int(n.StartByte())] {
			seen[int(n.StartByte())] = true
			guards = append(guards, m.evidence(kind, n))
		}
	}
	child := call
	scope := call.Parent()
	for p := call.Parent(); p != nil; p = p.Parent() {
		switch p.Kind() {
		case "statement_block", "program":
			for i := uint(0); i < p.NamedChildCount(); i++ {
				sib := p.NamedChild(i)
				if sib.StartByte() >= child.StartByte() {
					break
				}
				if sib.Kind() == "if_statement" && mentions(sib.ChildByFieldName("condition")) && alwaysExits(sib.ChildByFieldName("consequence")) {
					add("terminating_guard", sib)
				}
			}
		case "if_statement":
			cond := p.ChildByFieldName("condition")
			if cond != nil && int(child.StartByte()) >= int(cond.EndByte()) && mentions(cond) {
				add("enclosing_guard", cond)
			}
		}
		child = p
		if isFunction(p) || p.Kind() == "function_declaration" {
			scope = p
			break
		}
	}
	// Supported regex capture: receiver.match(<regex literal>)[n].
	walkCalls(scope, func(c *sitter.Node) {
		fn := c.ChildByFieldName("function")
		if fn == nil || fn.Kind() != "member_expression" {
			return
		}
		prop := fn.ChildByFieldName("property")
		a := c.ChildByFieldName("arguments")
		if prop == nil || a == nil || prop.Utf8Text(m.src) != "match" || a.NamedChildCount() != 1 {
			return
		}
		arg := a.NamedChild(0)
		literal := arg.Kind() == "regex"
		if arg.Kind() == "identifier" {
			if v := variable(m, arg.Utf8Text(m.src)); v != nil && v.Kind() == "regex" {
				literal = true
			}
		}
		if literal {
			transforms = append(transforms, m.evidence("regex_capture", c))
		}
	})
	return guards, transforms
}

func alwaysExits(n *sitter.Node) bool {
	if n == nil {
		return false
	}
	switch n.Kind() {
	case "return_statement", "throw_statement":
		return true
	case "statement_block":
		for i := uint(0); i < n.NamedChildCount(); i++ {
			if alwaysExits(n.NamedChild(i)) {
				return true
			}
		}
	case "if_statement":
		alt := n.ChildByFieldName("alternative")
		if alt != nil && alt.NamedChildCount() > 0 {
			return alwaysExits(n.ChildByFieldName("consequence")) && alwaysExits(alt.NamedChild(alt.NamedChildCount()-1))
		}
	}
	return false
}

// commandTransportMiddleware are libraries whose middleware populate req.session,
// req.cookies or response headers and never rewrite req.query or req.body. The
// list extends the shared transport set for the command claim only, so no
// existing analyzer's blockers change.
var commandTransportMiddleware = map[string]bool{"express-session": true, "express-rate-limit": true}

// withoutTransportOnlyGaps drops unresolved-middleware gaps for call factories
// of transport-only libraries; every other unresolved middleware stays blocking.
func (s *moduleSet) withoutTransportOnlyGaps(gaps []analysis.Gap) []analysis.Gap {
	out := []analysis.Gap{}
	for _, g := range gaps {
		if g.Kind == "applicable_middleware_unresolved" {
			if m := s.modules[g.At.File]; m != nil {
				if n := nodeAt(m.tree.RootNode(), g.At.StartByte, g.At.EndByte); n != nil && n.Kind() == "call_expression" {
					if fn := n.ChildByFieldName("function"); fn != nil && fn.Kind() == "identifier" {
						if imp, ok := m.imports[fn.Utf8Text(m.src)]; ok && commandTransportMiddleware[imp.module] {
							continue
						}
					}
				}
			}
		}
		out = append(out, g)
	}
	return out
}
