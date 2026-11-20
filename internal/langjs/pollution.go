package langjs

import (
	"fmt"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
	"github.com/zazzcode/zazzles/internal/parse"
)

type pollutionWrite struct {
	operation, operand string
	source, target     int
	sites              []*sitter.Node
	guard              pollutionGuard
}

type pollutionGuard struct {
	kind     string
	unknown  bool
	blocked  []string
	evidence []analysis.Evidence
}

type pollutionOperand struct {
	node  *sitter.Node
	value value
}

func (f *flow) pollutionCall(call, fn, arguments *sitter.Node, values []value) {
	if f.client != nil || f.pollutionRead || f.set == nil || !pollutionRequest(values) {
		return
	}
	if b, ok := lodashWrite(f.module, fn); ok {
		args, values := pollutionArguments(arguments, values)
		f.lodashPollutionCall(call, fn, args, values, b)
		return
	}
	m, callee := f.set.resolveCall(f.module, call)
	if callee == nil || pollutionBindingWritten(f.module, fn) {
		return
	}
	if f.helpers != nil && f.helpers.stack[fmt.Sprintf("%s:%d", m.file, callee.StartByte())] {
		return
	}
	writes := f.set.sourcePollutionWrites(m, callee)
	if len(writes) == 0 || callHasSpread(call) {
		return
	}
	args, values := pollutionArguments(arguments, values)
	for index, w := range writes {
		if w.source >= len(args) || w.target >= len(args) {
			continue
		}
		// Anchor each operand at the call and retain all matching write sites.
		binding := []analysis.Evidence{
			f.module.evidence("sink_binding", fn),
			m.evidence("sink_binding", callee),
		}
		for _, site := range w.sites {
			binding = append(binding, m.evidence("prototype_write", site))
		}
		if w.guard.kind == "" && pollutionNullTarget(f.module, call, args[w.target]) {
			w.guard = pollutionGuard{kind: "null_prototype_root", evidence: []analysis.Evidence{f.module.evidence("key_guard", args[w.target])}}
		}
		facts := &analysis.PollutionFacts{Operation: w.operation, KeyOperand: w.operand}
		f.recordPollution(call, index, []pollutionOperand{{args[w.source], values[w.source]}}, facts, binding, w.guard)
	}
}

func (f *flow) recordPollution(sink *sitter.Node, writeIndex int, operands []pollutionOperand, facts *analysis.PollutionFacts, binding []analysis.Evidence, guard pollutionGuard) {
	var deps []analysis.Dependency
	var operandEvidence []analysis.Evidence
	var gaps []analysis.Gap
	var capacities []string
	for _, arg := range operands {
		added := false
		for _, d := range arg.value.deps {
			capacity := f.pollutionKeyCapacity(d, facts.KeyOperand)
			if capacity == "scalar" {
				continue
			}
			d.SinkSlot = facts.KeyOperand
			deps = append(deps, d)
			capacities = append(capacities, capacity)
			added = true
		}
		if added {
			operandEvidence = append(operandEvidence, f.module.evidence("key_operand", arg.node))
			gaps = append(gaps, arg.value.gaps...)
		}
	}
	if len(deps) == 0 {
		return
	}

	facts.Guard = guard.kind
	facts.Blocked, facts.Open = analysispacks.ListPrototypeKeys(append(facts.Blocked, guard.blocked...))
	routes := analysispacks.OpenPrototypeRoutes(facts.Open, facts.KeyLevels)
	context := append([]analysis.Evidence{}, f.context...)
	context = append(context, binding...)
	context = append(context, operandEvidence...)
	controls := make([]int, 0, len(guard.evidence))
	for _, e := range guard.evidence {
		controls = append(controls, len(context))
		context = append(context, e)
	}

	for i, capacity := range capacities {
		p := analysis.CommandPath{Dependency: i, Operand: facts.KeyOperand, Protection: "unknown", Controls: controls}
		switch {
		case capacity != "key_bearing":
			p.Reason = "key_control_unknown"
		case guard.kind == "unknown" || guard.kind == "null_prototype_root" || guard.unknown && len(routes) > 0:
			p.Reason = "key_guard_coverage_unknown"
		case len(routes) == 0 && len(controls) > 0:
			p.Protection = "guarded"
		case len(routes) > 0:
			p.Protection = "raw"
		}
		facts.Paths = append(facts.Paths, p)
	}

	m := f.module
	id := fmt.Sprintf("use:%s:%s:%d:pollution", f.invocation.ID, m.file, sink.StartByte())
	if writeIndex > 0 {
		id += fmt.Sprintf(":%d", writeIndex)
	}
	u := analysis.CandidateUse{
		ID:      id,
		EntryID: f.entry.ID, EntryKind: f.entry.Kind, InvocationContextID: f.invocation.ID,
		Kind: analysis.PollutionKind, Sink: m.evidence(analysis.PollutionKind, sink),
		Dependencies: deps, Context: context, Pollution: facts,
		Gaps: append(append([]analysis.Gap{}, f.gaps...), gaps...), Assessment: analysis.Assessment{Status: "not_run"},
	}
	for _, p := range facts.Paths {
		if p.Reason != "" {
			u.Gaps = append(u.Gaps, f.gap(p.Reason, "A key-bearing operand or its effective guard is unresolved", sink))
		}
	}
	if facts.ContractID != "" && facts.Version == "" {
		u.Gaps = append(u.Gaps, f.gap("version_unresolved", "No verified affected version for "+facts.Package, sink))
	}
	if guard.kind == "deny_list" && len(routes) > 0 {
		u.Gaps = append(u.Gaps, f.gap("key_guard_incomplete", "Open prototype lookup: "+strings.Join(routes, ", "), sink))
	}
	f.uses = append(f.uses, u)
}

func (f *flow) pollutionKeyCapacity(d analysis.Dependency, operand string) string {
	if d.Source.Kind != "input_source" {
		return "unknown"
	}
	capacity := "unknown"
	if o, ok := f.set.webOriginFor(d.Source); ok {
		switch {
		case o.origin == "http.body" && o.initialType != "string":
			capacity = "key_bearing"
		case o.initialType == "string" || o.initialType == "number" || o.initialType == "boolean":
			capacity = "scalar"
		}
	} else if f.entry.Kind == "http" {
		capacity = f.pollutionHTTPKeyCapacity(d.Source)
	}
	for _, t := range d.Transfers {
		if t.Kind != "call_argument_dependency" && t.Kind != "json_copy" {
			continue
		}
		if m := f.set.modules[t.Span.File]; m != nil {
			n := parse.NodeAt(m.tree.RootNode(), t.Span.StartByte, t.Span.EndByte)
			switch {
			case pollutionJSONParse(m, n):
				capacity = "key_bearing"
			case n != nil && nativeStringOperation(m, n):
				if operand == "source" {
					capacity = "scalar"
				}
			default:
				capacity = "unknown"
			}
		}
	}
	return capacity
}

func (f *flow) pollutionHTTPKeyCapacity(source analysis.Evidence) string {
	// A source already established by the entry flow may use the main request
	// binding, an alias/destructuring binding or the renamed helper parameter.
	parts := strings.Split(source.Text, ".")
	container := ""
	if len(parts) == 1 {
		container = f.parts[parts[0]]
	} else if part := f.parts[parts[0]]; part != "" {
		container = part
	} else {
		container = parts[1]
	}
	switch container {
	case "body", "payload":
		return "key_bearing"
	case "params", "headers", "cookies":
		if len(parts) > 2 || f.parts[parts[0]] != "" && len(parts) > 1 {
			return "scalar"
		}
	case "url", "originalUrl", "baseUrl", "path":
		return "scalar"
	}
	return "unknown"
}

func pollutionJSONParse(m *sourceModule, n *sitter.Node) bool {
	if n == nil || n.Kind() != "call_expression" || !pollutionBuiltin(m, n, "JSON", "parse") {
		return false
	}
	fn, args := n.ChildByFieldName("function"), n.ChildByFieldName("arguments")
	return fn != nil && fn.Utf8Text(m.src) == "JSON.parse" && args != nil && args.NamedChildCount() == 1
}

func pollutionGlobal(m *sourceModule, n *sitter.Node, name string) bool {
	return !m.cachedShadowed(n, name) && !topLevelBinding(m, name) && !bindingReassigned(m, name)
}

func pollutionBuiltin(m *sourceModule, n *sitter.Node, root, member string) bool {
	if !pollutionGlobal(m, n, root) {
		return false
	}
	writes := m.bindingWrites().written
	for _, name := range strings.Split(member, ".") {
		if writes[root+"."+name] || writes[root+"['"+name+"']"] || writes[root+"[\""+name+"\"]"] {
			return false
		}
		root += "." + name
	}
	return true
}

func (s *moduleSet) assemblePollutionClaims(report *analysis.AnalysisReport) {
	s.assembleClaims(report, claimHooks{
		kind: analysis.PollutionKind, checkID: "automatic-pollution", checkKind: "pollution",
		present: func(u *analysis.CandidateUse) bool { return u.Pollution != nil },
		fields:  commandFields, chainEvidence: s.interpreterChainEvidence,
		guards: func(*analysis.CandidateUse) ([]analysis.Evidence, []analysis.Evidence) { return nil, nil },
		chainGapCovered: func(u *analysis.CandidateUse, g analysis.Gap) bool {
			return g.Kind == "input_helper_unresolved" && s.pollutionParseGap(g)
		},
		gapCovered: func(u *analysis.CandidateUse, g analysis.Gap, complete bool, bodies, transforms []analysis.Evidence, extra map[string][]analysis.Evidence) bool {
			return g.Kind == "key_guard_incomplete" ||
				(g.Kind == "unknown_transfer" || g.Kind == "unknown_value") && s.pollutionParseGap(g) ||
				s.commandGapCovered(u, g, complete, bodies, transforms, extra)
		},
		complete: func(u *analysis.CandidateUse, extra map[string][]analysis.Evidence, blockers, coverage []analysis.Gap) *analysis.Completeness {
			c := parse.SSRFCompleteness(u, extra, blockers, coverage)
			c.ClaimKind, c.Required = "pollution", analysispacks.PollutionRoles()
			c.Scope = "prototype write over the key-bearing operand in this application invocation"
			delete(c.Evidence, "destination_operand")
			return c
		},
		finish: func(*analysis.CandidateUse, *analysis.Completeness, []analysis.Evidence, []int) {},
		contract: func(u *analysis.CandidateUse) *analysis.APIModel {
			return analysispacks.PollutionContract(u.Pollution.ContractID)
		},
	})
}

func (s *moduleSet) pollutionParseGap(g analysis.Gap) bool {
	m := s.modules[g.At.File]
	if m == nil {
		return false
	}
	n := parse.NodeAt(m.tree.RootNode(), g.At.StartByte, g.At.EndByte)
	if n != nil && n.Kind() == "identifier" && n.Utf8Text(m.src) == "JSON" {
		if p := n.Parent(); p != nil && p.Kind() == "member_expression" {
			n = p.Parent()
		}
	}
	return pollutionJSONParse(m, n)
}

func pollutionRequest(values []value) bool {
	for _, v := range values {
		for _, dep := range v.deps {
			if dep.Source.Kind == "input_source" {
				return true
			}
		}
	}
	return false
}

// pollutionArguments ignores comments without changing the shared argument list.
func pollutionArguments(arguments *sitter.Node, values []value) ([]*sitter.Node, []value) {
	args := make([]*sitter.Node, 0, len(values))
	operands := make([]value, 0, len(values))
	for i, v := range values {
		n := arguments.NamedChild(uint(i))
		if n.Kind() != "comment" {
			args = append(args, n)
			operands = append(operands, v)
		}
	}
	return args, operands
}
