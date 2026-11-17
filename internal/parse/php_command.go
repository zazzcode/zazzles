package parse

import (
	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
)

// phpCommandOps is the D-6 operation table: one contract, shell-string
// semantics for every entry.
var phpCommandOps = map[string]string{
	"system":     "system",
	"exec":       "exec",
	"shell_exec": "shell_exec",
	"passthru":   "passthru",
	"popen":      "popen",
	"proc_open":  "proc_open",
}

// commandUse records a command_execution_candidate for a verified process
// operation. slots lists operand slot names in call order.
func (f *phpFlow) commandUse(n *sitter.Node, op string, slots []string, values []phpValue, nodes []*sitter.Node) phpValue {
	m := f.module
	facts := &analysis.CommandFacts{Operation: op, ContractID: analysispacks.PHPProgramContract, Platform: "posix", APIShellMode: "enabled", EffectiveShellMode: "enabled", ArgvShape: "none", Operands: []analysis.CommandOperand{}, Paths: []analysis.CommandPath{}}
	var all phpValue
	var context []analysis.Evidence
	var deps []phpDep
	request := false
	for i, slot := range slots {
		var v phpValue
		var node *sitter.Node
		if i < len(values) {
			v = values[i]
		}
		if i < len(nodes) {
			node = nodes[i]
		}
		if node == nil {
			node = n
		}
		o := analysis.CommandOperand{Slot: slot}
		if text, ok := phpStringLiteral(m, node); ok {
			o.Constant = text
		} else {
			o.Dynamic = true
		}
		o.Context = append(o.Context, len(context))
		context = append(context, m.evidence("command_operand", node))
		for _, d := range v.deps {
			d.dep.SinkSlot = slot
			o.Dependencies = append(o.Dependencies, len(deps))
			protection := "raw"
			switch d.protection {
			case "shell_quoted":
				protection = "quoted"
			case "numeric", "non_content":
				protection = "constrained"
			case "unknown":
				protection = "unknown"
			}
			facts.Paths = append(facts.Paths, analysis.CommandPath{Dependency: len(deps), Operand: slot, Protection: protection})
			deps = append(deps, d)
			request = true
		}
		facts.Operands = append(facts.Operands, o)
		all = phpCombine(all, v)
	}
	if !request {
		return phpValue{unknown: true, evidence: []analysis.Evidence{m.evidence("command_output", n)}}
	}
	u := f.addUse("command_execution_candidate", n, phpValue{deps: deps, gaps: all.gaps})
	u.Command = facts
	u.APIModel = analysispacks.CommandContract(analysispacks.PHPProgramContract)
	u.Context = append(u.Context, context...)
	u.Context = append(u.Context, m.evidence("sink_binding", phpCallee(n)))
	c := &analysis.Completeness{ClaimKind: "command_execution", Required: []string{"input_source", "sink_binding", "invoked_callable", "control_flow", "command_operands", "execution_configuration"}, Evidence: map[string][]analysis.Evidence{
		"sink_binding":            {m.evidence("sink_binding", phpCallee(n))},
		"invoked_callable":        {f.entryEvidence()},
		"command_operands":        context,
		"execution_configuration": {m.evidence("operation", n)},
		"control_flow":            append([]analysis.Evidence{m.evidence("operation", n)}, f.context...),
	}, Blockers: []analysis.Gap{}, Coverage: append([]analysis.Gap{}, u.Gaps...), Scope: "Bounded PHP source-to-process flow; every listed operation passes its command string to a shell."}
	// Blockers ride the operand value's own gaps; flow-wide gaps stay visible
	// in u.Gaps/Coverage without vetoing the claim (shared helper bodies
	// accumulate unrelated unresolved constructs).
	for _, g := range append([]analysis.Gap{}, all.gaps...) {
		switch g.Kind {
		case "php_parameter_unresolved", "php_value_unresolved", "php_call_unresolved", "php_loop_unresolved", "php_expression_unresolved", "php_global_unresolved", "work_limit", "dependency_limit", "transfer_limit":
			c.Blockers = append(c.Blockers, g)
		}
	}
	for _, d := range deps {
		if d.dep.Source.Kind == "input_source" || d.dep.Source.Kind == "storage_source" {
			c.Evidence["input_source"] = append(c.Evidence["input_source"], d.dep.Source)
		}
	}
	u.Completeness = c
	return phpValue{unknown: true, evidence: []analysis.Evidence{m.evidence("command_output", n)}}
}
