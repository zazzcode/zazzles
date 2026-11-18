package langphp

import (
	"strings"

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
	// guardOperand maps a guarded path to its operand's local context index;
	// the shared contract requires guarded paths to cite a control.
	guardOperand := map[int]int{}
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
			protection, reason := "raw", ""
			switch d.protection {
			case "shell_quoted":
				protection, reason = "guarded", "escapeshellarg/escapeshellcmd quotes the shell operand"
			case "numeric", "non_content":
				protection, reason = "guarded", "numeric or non-content value cannot carry shell syntax"
			case "unknown", phpUnwritten:
				protection = "unknown"
			case phpShellDenylist:
				// The deny-list leaves a shell metacharacter usable.
				protection = "raw"
			}
			if protection == "guarded" {
				guardOperand[len(facts.Paths)] = o.Context[0]
			}
			facts.Paths = append(facts.Paths, analysis.CommandPath{Dependency: len(deps), Operand: slot, Protection: protection, Reason: reason})
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
	base := len(u.Context)
	for i, local := range guardOperand {
		facts.Paths[i].Controls = []int{base + local}
	}
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
	c.Blockers = append(c.Blockers, phpStoredOnlyBlockers(deps, u.Sink.Span)...)
	u.Completeness = c
	return phpValue{unknown: true, evidence: []analysis.Evidence{m.evidence("command_output", n)}}
}

// phpShellDenylist labels a value passed through a finite literal str_replace
// deny-list that leaves at least one shell metacharacter intact. Only command
// sinks read it as raw; every other family treats it as unknown.
const phpShellDenylist = "shell_denylist"

// phpShellMetas are the POSIX shell characters that start a new command,
// substitution or redirection.
const phpShellMetas = ";&|`$()<>\n"

// phpShellMetaSurvives reports whether some shell metacharacter is not
// removed by the single-character removals of a deny-list. Removing a
// multi-character sequence (`&&`, `| `) never removes its characters.
func phpShellMetaSurvives(removed map[string]bool) bool {
	for _, c := range phpShellMetas {
		if !removed[string(c)] {
			return true
		}
	}
	return false
}

// phpDenylistProtect applies protection to raw paths only; already
// transformed paths become unknown, as any removal would leave them.
func phpDenylistProtect(v phpValue, protection string) phpValue {
	v.deps = append([]phpDep{}, v.deps...)
	for i := range v.deps {
		if v.deps[i].protection == "raw" {
			v.deps[i].protection = protection
		} else {
			v.deps[i].protection = "unknown"
		}
	}
	return v
}

// phpNonShellProtection maps the command-only deny-list label to unknown for
// every non-command family.
func phpNonShellProtection(p string) string {
	if p == phpShellDenylist {
		return "unknown"
	}
	return p
}

// literalRemovals returns the single characters a str_replace call deletes
// (or replaces with text free of shell metacharacters), when the search and
// replacement operands are finite literals: an array literal, a string, or
// the array_keys($map)/$map pair of a literal map.
func (f *phpFlow) literalRemovals(search, replace *sitter.Node) (map[string]bool, bool) {
	m := f.module
	removed := map[string]bool{}
	note := func(term, replacement string) {
		if len([]rune(term)) == 1 && !strings.ContainsAny(replacement, phpShellMetas) {
			removed[term] = true
		}
	}
	if search != nil && search.Kind() == "function_call_expression" && phpText(m, phpCallee(search)) == "array_keys" && f.builtin("array_keys") {
		args := phpArgs(search)
		if len(args) != 1 || phpVarName(m, args[0]) == "" || phpVarName(m, args[0]) != phpVarName(m, replace) {
			return nil, false
		}
		mapValue, ok := f.env[phpVarName(m, args[0])]
		if !ok || len(mapValue.deps) > 0 || len(mapValue.fields) == 0 {
			return nil, false
		}
		for key, value := range mapValue.fields {
			replacement, ok := phpSQLText(value)
			if !ok {
				return nil, false
			}
			note(key, replacement)
		}
		return removed, true
	}
	terms := phpArrayLiteralStrings(m, search)
	if terms == nil {
		text, ok := phpStringLiteral(m, search)
		if !ok {
			return nil, false
		}
		terms = []string{text}
	}
	replacements := phpArrayLiteralStrings(m, replace)
	if replacements == nil {
		text, ok := phpStringLiteral(m, replace)
		if !ok {
			return nil, false
		}
		for _, term := range terms {
			note(term, text)
		}
		return removed, true
	}
	for i, term := range terms {
		replacement := ""
		if i < len(replacements) {
			replacement = replacements[i]
		}
		note(term, replacement)
	}
	return removed, true
}
