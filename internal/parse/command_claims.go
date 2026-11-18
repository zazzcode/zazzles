package parse

import (
	"sort"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
)

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

// finishCommandPaths records, per path, the guards found for that
// dependency and whether an unresolved transfer blocks it. A guard that does
// not mention a dependency never covers it; adequacy is never decided here.
// guardContext[i] is the use.Context index of guards[i]; derived[d] lists the
// names of values computed from dependency d that a guard may test instead.
func finishCommandPaths(u *analysis.CandidateUse, c *analysis.Completeness, guards []analysis.Evidence, guardContext []int, derived [][]string, touches func(analysis.Gap, analysis.Dependency) bool) {
	finishOperandPaths(u, u.Command.Paths, c, guards, guardContext, derived, touches)
}

// assembleCommandClaims completes every Node command candidate before catalog
// attachment: claim kind, roles, blockers, guard evidence and the selected
// contract. It runs with and without explicit check files.
func (s *moduleSet) assembleCommandClaims(report *analysis.AnalysisReport) {
	s.assembleClaims(report, claimHooks{
		kind:      "command_execution_candidate",
		checkID:   "automatic-command",
		checkKind: "command_execution",
		present:   func(u *analysis.CandidateUse) bool { return u.Command != nil },
		fields:    commandFields,
		guards:    s.commandGuards,
		gapCovered: func(u *analysis.CandidateUse, g analysis.Gap, controlComplete bool, complete, transforms []analysis.Evidence, extra map[string][]analysis.Evidence) bool {
			return s.commandGapCovered(u, g, controlComplete, complete, transforms, extra)
		},
		complete: commandCompleteness,
		finish: func(u *analysis.CandidateUse, c *analysis.Completeness, guards []analysis.Evidence, guardIndex []int) {
			finishCommandPaths(u, c, guards, guardIndex, s.commandDerivedNames(u), func(g analysis.Gap, d analysis.Dependency) bool { return gapTouchesDependency(g, d) })
		},
		contract: func(u *analysis.CandidateUse) *analysis.APIModel {
			return analysispacks.CommandContract(u.Command.ContractID)
		},
		resolve: s.resolveGuardedControlFlow,
	})
}

// guardControlFlowGaps are the control-flow limitations the handler walk records
// for an `if` statement it does not traverse.
var guardControlFlowGaps = map[string]bool{"unsupported_control_flow": true, "branch_exit": true, "unknown_control_effect": true}

// resolveGuardedControlFlow settles the control-flow gaps recorded on a
// terminating guard the guard engine verified: an `if` with no alternative whose
// consequence always exits has no effect on later code except ending the
// request, which the guard evidence states. Gaps anywhere else stay as coverage.
func (s *moduleSet) resolveGuardedControlFlow(u *analysis.CandidateUse, c *analysis.Completeness, guards []analysis.Evidence) {
	settled := func(g analysis.Gap) bool {
		if !guardControlFlowGaps[g.Kind] {
			return false
		}
		for _, e := range guards {
			if e.Kind != terminatingGuardKind || e.Span.File != g.At.File || e.Span.StartByte != g.At.StartByte || e.Span.EndByte != g.At.EndByte {
				continue
			}
			if m := s.modules[e.Span.File]; m != nil {
				if n := nodeAt(m.tree.RootNode(), e.Span.StartByte, e.Span.EndByte); n != nil && n.Kind() == "if_statement" && n.ChildByFieldName("alternative") == nil {
					return true
				}
			}
		}
		return false
	}
	remaining := []analysis.Gap{}
	for _, g := range c.Coverage {
		if settled(g) {
			c.Resolved = append(c.Resolved, g)
		} else {
			remaining = append(remaining, g)
		}
	}
	c.Coverage = remaining
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
// and mention a request-derived operand identifier, source or value derived
// from one, in the polarity the code gives them. It also returns supported
// regex-capture transfers on operand paths.
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
	scan := newCommandGuardScan(m.guardLang(), call, func(helper *sitter.Node) []*sitter.Node { return jsHelperCallSites(m, u.Context, helper) })
	seen := map[int]bool{}
	var conditions []*sitter.Node
	next := s.nextProjectFor(m.file) != nil
	nameList := make([]string, 0, len(names))
	for n := range names {
		nameList = append(nameList, n)
	}
	for _, site := range scan.Collect(names, u.Dependencies, nil) {
		// In Next.js code a truthiness or type-only schema test of the value is
		// not a destination or argument control.
		if next && nonContainingTest(m, site.Cond, nameList, u) {
			continue
		}
		if !seen[int(site.Whole.StartByte())] {
			seen[int(site.Whole.StartByte())] = true
			guards = append(guards, m.evidence(commandGuardEvidenceKind(site), site.Whole))
			conditions = append(conditions, site.Cond)
		}
	}
	for _, decl := range collectionDefinitions(conditions, m.src, func(name string) *sitter.Node {
		if constantCollection(m, name) {
			return jsTopDeclarationNode(m, name)
		}
		return nil
	}) {
		u.Context = append(u.Context, m.evidence("allowlist_definition", decl))
	}
	// A call outside any function is scanned within its own parent only, as before.
	regexScope := scan.scope
	if regexScope.Kind() == "program" {
		regexScope = call.Parent()
	}
	// Supported regex capture: receiver.match(<regex literal>)[n].
	walkCalls(regexScope, func(c *sitter.Node) {
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

// commandDerivedNames recomputes the derived names of a Node command use's dependencies.
func (s *moduleSet) commandDerivedNames(u *analysis.CandidateUse) [][]string {
	m := s.modules[u.Sink.Span.File]
	if m == nil {
		return nil
	}
	call := nodeAt(m.tree.RootNode(), u.Sink.Span.StartByte, u.Sink.Span.EndByte)
	if call == nil {
		return nil
	}
	return newCommandGuardScan(m.guardLang(), call, func(helper *sitter.Node) []*sitter.Node { return jsHelperCallSites(m, u.Context, helper) }).Derived(u.Dependencies)
}
