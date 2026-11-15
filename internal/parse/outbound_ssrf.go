package parse

import (
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
)

// axiosURLMethods take the destination URL as their first argument.
var axiosURLMethods = map[string]bool{"get": true, "delete": true, "head": true, "options": true, "post": true, "put": true, "patch": true}

// outboundOperation verifies the client behind a fetch/axios-shaped call. It
// returns the operation name, its contract and binding evidence, and the index
// of the destination argument, or ok=false when the binding is not verified or
// the destination is not a positional URL (an axios config object).
func (f *flow) outboundOperation(call, fn, args *sitter.Node) (op, contract string, binding []analysis.Evidence, dest int, ok bool) {
	m := f.module
	if args == nil || args.NamedChildCount() == 0 {
		return "", "", nil, -1, false
	}
	first := args.NamedChild(0)
	if fn.Kind() == "identifier" && fn.Utf8Text(m.src) == "fetch" {
		// The WHATWG global: no import, declaration, parameter or assignment rebinds it.
		if shadowed(call, "fetch", m.src) || topLevelBinding(m, "fetch") || bindingReassigned(m, "fetch") {
			return "", "", nil, -1, false
		}
		return "fetch", analysispacks.FetchURLContract, []analysis.Evidence{m.evidence("sink_binding", fn)}, 0, true
	}
	parts := strings.Split(fn.Utf8Text(m.src), ".")
	root := parts[0]
	imp, imported := m.imports[root]
	if !imported || imp.module != "axios" || (imp.name != "default" && imp.name != "*") || shadowed(call, root, m.src) || bindingReassigned(m, root) {
		return "", "", nil, -1, false
	}
	rest := parts[1:]
	if len(rest) > 0 && rest[0] == "default" {
		rest = rest[1:]
	}
	method := ""
	switch {
	case len(rest) == 0:
		// axios(url, config); axios(config) carries the URL inside an object.
		if first.Kind() == "object" {
			return "", "", nil, -1, false
		}
		method = "axios"
	case len(rest) == 1 && axiosURLMethods[rest[0]]:
		method = "axios." + rest[0]
	default:
		return "", "", nil, -1, false
	}
	return method, analysispacks.AxiosURLContract, []analysis.Evidence{m.evidence("sink_binding", imp.declaration), m.evidence("sink_binding", fn)}, 0, true
}

// destinationOrigin classifies what the bounded flow established for the
// destination operand only. It never upgrades an unknown value.
func (f *flow) destinationOrigin(call, arg *sitter.Node, v value) string {
	request, external := false, false
	for _, d := range v.deps {
		switch d.Source.Kind {
		case "input_source":
			request = true
		default:
			external = true
		}
	}
	switch {
	case request:
		return analysis.DestinationRequest
	case external:
		return analysis.DestinationExternalData
	}
	if arg == nil {
		return analysis.DestinationUnestablished
	}
	return f.staticOrigin(call, arg, 0)
}

func (f *flow) staticOrigin(call, n *sitter.Node, depth int) string {
	m := f.module
	switch n.Kind() {
	case "string":
		return analysis.DestinationConstant
	case "template_string":
		for i := uint(0); i < n.NamedChildCount(); i++ {
			if n.NamedChild(i).Kind() == "template_substitution" {
				return analysis.DestinationUnestablished
			}
		}
		return analysis.DestinationConstant
	case "member_expression":
		if f.environmentRead(call, n) {
			return analysis.DestinationEnvironment
		}
	case "identifier":
		if depth > 0 {
			return analysis.DestinationUnestablished
		}
		if value := localInitializer(m, call, n.Utf8Text(m.src)); value != nil && !bindingReassigned(m, n.Utf8Text(m.src)) {
			return f.staticOrigin(call, value, depth+1)
		}
	}
	return analysis.DestinationUnestablished
}

// environmentRead reports process.env.NAME or process.env['NAME'] with an
// unshadowed process global.
func (f *flow) environmentRead(call, n *sitter.Node) bool {
	m := f.module
	obj := n.ChildByFieldName("object")
	if n.Kind() == "subscript_expression" {
		obj = n.ChildByFieldName("object")
	}
	if obj == nil || obj.Utf8Text(m.src) != "process.env" {
		return false
	}
	return !shadowed(call, "process", m.src) && !topLevelBinding(m, "process")
}

// localInitializer returns the initializer of the nearest enclosing const/let/var
// declaration of name, or the default value of a parameter of that name.
func localInitializer(m *sourceModule, call *sitter.Node, name string) *sitter.Node {
	for p := call.Parent(); p != nil; p = p.Parent() {
		if params := p.ChildByFieldName("parameters"); params != nil {
			for i := uint(0); i < params.NamedChildCount(); i++ {
				param := params.NamedChild(i)
				if param.Kind() == "required_parameter" || param.Kind() == "optional_parameter" {
					pattern, value := param.ChildByFieldName("pattern"), param.ChildByFieldName("value")
					if pattern != nil && pattern.Utf8Text(m.src) == name {
						return value
					}
				}
				if param.Kind() == "assignment_pattern" {
					left, right := param.ChildByFieldName("left"), param.ChildByFieldName("right")
					if left != nil && left.Utf8Text(m.src) == name {
						return right
					}
				}
				if param.Kind() == "identifier" && param.Utf8Text(m.src) == name {
					return nil
				}
			}
		}
		if p.Kind() == "statement_block" || p.Kind() == "program" {
			for i := uint(0); i < p.NamedChildCount(); i++ {
				d := p.NamedChild(i)
				if d.Kind() == "export_statement" {
					d = d.ChildByFieldName("declaration")
				}
				if d == nil || (d.Kind() != "lexical_declaration" && d.Kind() != "variable_declaration") {
					continue
				}
				for j := uint(0); j < d.NamedChildCount(); j++ {
					decl := d.NamedChild(j)
					if id := decl.ChildByFieldName("name"); id != nil && id.Kind() == "identifier" && id.Utf8Text(m.src) == name {
						return decl.ChildByFieldName("value")
					}
				}
			}
		}
	}
	return nil
}

// ssrfRequiredRoles are the mandatory evidence obligations of the claim,
// unioned with the catalog's selected obligations by policy.
var ssrfRequiredRoles = []string{"input_source", "sink_binding", "invoked_callable", "control_flow", "destination_operand"}

const ssrfScope = "server-side request forgery claim over the supplied entry invocation, verified outbound client contract, the destination operand and guard/transfer context; request data sent as body or headers is not destination control"

// ssrfCompleteness builds the claim-scoped completeness shared by every
// language adapter.
func ssrfCompleteness(u *analysis.CandidateUse, extraRoles map[string][]analysis.Evidence, blockers, coverage []analysis.Gap) *analysis.Completeness {
	roles := namespacedRoles(u, "ssrf_")
	c := &analysis.Completeness{ClaimKind: "ssrf", Required: append([]string{}, ssrfRequiredRoles...), Evidence: roles, Blockers: blockers, Coverage: coverage, Scope: ssrfScope}
	if c.Blockers == nil {
		c.Blockers = []analysis.Gap{}
	}
	if c.Coverage == nil {
		c.Coverage = []analysis.Gap{}
	}
	for role, items := range extraRoles {
		c.Evidence[role] = append(c.Evidence[role], items...)
	}
	for _, d := range u.Dependencies {
		c.Evidence["input_source"] = append(c.Evidence["input_source"], d.Source)
	}
	c.Evidence["destination_operand"] = append(c.Evidence["destination_operand"], u.Sink)
	if len(c.Evidence["invoked_callable"]) == 0 {
		c.Evidence["invoked_callable"] = append([]analysis.Evidence{}, c.Evidence["handler"]...)
	}
	c.ModelFacts = []string{
		"Verified operation " + u.Outbound.Operation + " (contract " + u.Outbound.ContractID + "); a request-derived value reaches its destination operand. Dependencies tagged sink_slot destination are the destination paths; other call arguments are not destination control.",
		"Dependency and path records in outbound facts refer to the evidence table by index. Each path keeps its own source, transfers and guard facts; a guard on one value, branch or invocation does not protect another.",
	}
	return c
}

// finishSSRFPaths records per-path protection with the shared operand-path rules.
func finishSSRFPaths(u *analysis.CandidateUse, c *analysis.Completeness, guards []analysis.Evidence, guardContext []int, derived [][]string, touches func(analysis.Gap, analysis.Dependency) bool) {
	finishOperandPaths(u, u.Outbound.Paths, c, guards, guardContext, derived, touches)
}

// assembleSSRFClaims completes every Node SSRF candidate before catalog attachment.
func (s *moduleSet) assembleSSRFClaims(report *analysis.AnalysisReport) {
	s.assembleClaims(report, claimHooks{
		kind:      "ssrf_candidate",
		checkID:   "automatic-ssrf",
		checkKind: "ssrf",
		// The stage-resolved chain of the invocation, as for path claims, so a
		// handler reached through a wrapper keeps its own predecessors only.
		chainEvidence: s.pathChainEvidence,
		present:       func(u *analysis.CandidateUse) bool { return u.Outbound != nil },
		fields:        commandFields,
		guards:        s.commandGuards,
		gapCovered: func(u *analysis.CandidateUse, g analysis.Gap, controlComplete bool, complete, transforms []analysis.Evidence, extra map[string][]analysis.Evidence) bool {
			return s.commandGapCovered(u, g, controlComplete, complete, transforms, extra)
		},
		complete: ssrfCompleteness,
		finish: func(u *analysis.CandidateUse, c *analysis.Completeness, guards []analysis.Evidence, guardIndex []int) {
			finishSSRFPaths(u, c, guards, guardIndex, s.commandDerivedNames(u), func(g analysis.Gap, d analysis.Dependency) bool { return gapTouchesDependency(g, d) })
		},
		contract: func(u *analysis.CandidateUse) *analysis.APIModel {
			return analysispacks.SSRFContract(u.Outbound.ContractID)
		},
		resolve: s.resolveGuardedControlFlow,
	})
}
