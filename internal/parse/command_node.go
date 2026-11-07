package parse

import (
	"fmt"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
)

// Node child_process operations. Contract IDs are owned by the catalog;
// the parser only selects one after the import/require binding is verified.
var nodeCommandOps = map[string]struct {
	contract string
	shell    bool
}{
	"exec":         {analysispacks.NodeShellContract, true},
	"execSync":     {analysispacks.NodeShellContract, true},
	"execFile":     {analysispacks.NodeArgvContract, false},
	"execFileSync": {analysispacks.NodeArgvContract, false},
	"spawn":        {analysispacks.NodeArgvContract, false},
	"spawnSync":    {analysispacks.NodeArgvContract, false},
}

func childProcessModule(module string) bool {
	return module == "child_process" || module == "node:child_process"
}

// readCommandDestructuring records `const { exec, spawn: run } = require('child_process')`.
func (m *sourceModule) readCommandDestructuring(pattern, v, declaration *sitter.Node) {
	path, member, ok := requireBinding(m, v)
	if !ok || member != "*" || !childProcessModule(path) {
		return
	}
	for i := uint(0); i < pattern.NamedChildCount(); i++ {
		c := pattern.NamedChild(i)
		local, name := "", ""
		switch c.Kind() {
		case "shorthand_property_identifier_pattern":
			local = c.Utf8Text(m.src)
			name = local
		case "pair_pattern":
			key, value := c.ChildByFieldName("key"), c.ChildByFieldName("value")
			if key != nil && value != nil && value.Kind() == "identifier" {
				local, name = value.Utf8Text(m.src), key.Utf8Text(m.src)
			}
		}
		if local != "" && !bindingReassigned(m, local) {
			m.commandNames[local] = importBinding{path, name, declaration}
		}
	}
}

// nodeCommandBinding resolves the called function to a child_process member.
// Only an actual import/require of the core module, unshadowed and never
// reassigned, is verified; a demonstrated fake or shadowed symbol is not.
func (f *flow) nodeCommandBinding(call, fn *sitter.Node) (string, []analysis.Evidence, bool) {
	m := f.module
	switch fn.Kind() {
	case "identifier":
		name := fn.Utf8Text(m.src)
		if shadowed(call, name, m.src) {
			return "", nil, false
		}
		var b importBinding
		if imp, ok := m.imports[name]; ok && childProcessModule(imp.module) && imp.name != "*" && imp.name != "default" {
			b = imp
		} else if imp, ok := m.commandNames[name]; ok {
			b = imp
		} else {
			return "", nil, false
		}
		if _, known := nodeCommandOps[b.name]; !known || bindingReassigned(m, name) {
			return "", nil, false
		}
		return b.name, []analysis.Evidence{m.evidence("sink_binding", b.declaration), m.evidence("sink_binding", fn)}, true
	case "member_expression":
		obj, prop := fn.ChildByFieldName("object"), fn.ChildByFieldName("property")
		if obj == nil || prop == nil {
			return "", nil, false
		}
		op := prop.Utf8Text(m.src)
		if _, known := nodeCommandOps[op]; !known {
			return "", nil, false
		}
		switch obj.Kind() {
		case "identifier":
			name := obj.Utf8Text(m.src)
			imp, ok := m.imports[name]
			if !ok || !childProcessModule(imp.module) || (imp.name != "*" && imp.name != "default") || shadowed(call, name, m.src) || bindingReassigned(m, name) {
				return "", nil, false
			}
			return op, []analysis.Evidence{m.evidence("sink_binding", imp.declaration), m.evidence("sink_binding", fn)}, true
		case "call_expression":
			if path, member, ok := requireBinding(m, obj); ok && member == "*" && childProcessModule(path) {
				return op, []analysis.Evidence{m.evidence("sink_binding", obj), m.evidence("sink_binding", fn)}, true
			}
		}
	}
	return "", nil, false
}

// jsOptions classifies an options object literal. Spreads, computed or
// duplicate keys cannot be interpreted and leave the configuration unresolved.
func jsOptions(m *sourceModule, obj *sitter.Node) (map[string]*sitter.Node, bool) {
	props := map[string]*sitter.Node{}
	for i := uint(0); i < obj.NamedChildCount(); i++ {
		p := obj.NamedChild(i)
		var key string
		var value *sitter.Node
		switch p.Kind() {
		case "pair":
			k := p.ChildByFieldName("key")
			if k == nil || (k.Kind() != "property_identifier" && k.Kind() != "string") {
				return props, false
			}
			key = k.Utf8Text(m.src)
			if text, ok := stringLiteral(k, m.src); ok {
				key = text
			}
			value = p.ChildByFieldName("value")
		case "shorthand_property_identifier":
			key, value = p.Utf8Text(m.src), p
		case "comment":
			continue
		default:
			return props, false
		}
		if _, dup := props[key]; dup {
			return props, false
		}
		props[key] = value
	}
	return props, true
}

// quiet evaluates an expression again without recording sinks, context or
// gaps a second time (operands were already traversed with the whole call).
func (f *flow) quiet(n *sitter.Node) value {
	uses, gaps, context, work := len(f.uses), len(f.gaps), len(f.context), f.work
	v := f.eval(n)
	f.uses, f.gaps, f.context, f.work = f.uses[:uses], f.gaps[:gaps], f.context[:context], work
	return v
}

type jsCommandBuilder struct {
	f       *flow
	facts   *analysis.CommandFacts
	deps    []analysis.Dependency
	context []analysis.Evidence
	gaps    []analysis.Gap
	request bool
}

// operand records one slot. Request dependencies are copied per slot so each
// operand keeps its own source-to-slot path.
func (b *jsCommandBuilder) operand(slot string, n *sitter.Node, v value) {
	o := analysis.CommandOperand{Slot: slot}
	if text, ok := stringLiteral(n, b.f.module.src); ok {
		o.Constant = text
	} else if n.Kind() != "string" {
		o.Dynamic = true
	}
	o.Context = append(o.Context, len(b.context))
	b.context = append(b.context, b.f.module.evidence("command_operand", n))
	for _, d := range v.deps {
		d.SinkSlot = slot
		o.Dependencies = append(o.Dependencies, len(b.deps))
		b.facts.Paths = append(b.facts.Paths, analysis.CommandPath{Dependency: len(b.deps), Operand: slot, Protection: "raw"})
		b.deps = append(b.deps, d)
		b.request = true
	}
	b.gaps = append(b.gaps, v.gaps...)
	b.facts.Operands = append(b.facts.Operands, o)
}

func (b *jsCommandBuilder) gap(kind, detail string, n *sitter.Node) {
	b.gaps = append(b.gaps, b.f.gap(kind, detail, n))
}

// commandCall recognizes a verified child_process operation and records a
// command_execution_candidate when request data reaches any process operand.
func (f *flow) commandCall(call, fn, args *sitter.Node) bool {
	op, binding, ok := f.nodeCommandBinding(call, fn)
	if !ok || args == nil {
		return false
	}
	spec := nodeCommandOps[op]
	b := &jsCommandBuilder{f: f, facts: &analysis.CommandFacts{Operation: "child_process." + op, ContractID: spec.contract, Platform: "posix", APIShellMode: "disabled", EffectiveShellMode: "disabled", ArgvShape: "none", Operands: []analysis.CommandOperand{}, Paths: []analysis.CommandPath{}}}
	if spec.shell {
		b.facts.APIShellMode, b.facts.EffectiveShellMode = "enabled", "enabled"
	}
	var nodes []*sitter.Node
	for i := uint(0); i < args.NamedChildCount(); i++ {
		c := args.NamedChild(i)
		if c.Kind() == "comment" {
			continue
		}
		if c.Kind() == "spread_element" {
			b.gap("command_spread_unresolved", "spread argument to a process call is not modeled", c)
		}
		nodes = append(nodes, c)
	}
	if len(nodes) == 0 {
		return false
	}
	// Position 0 is the command (exec) or the executable (argv operations).
	var argvNode, optionsNode *sitter.Node
	for _, n := range nodes[1:] {
		switch {
		case n.Kind() == "array" && !spec.shell && argvNode == nil && optionsNode == nil:
			argvNode = n
		case isFunction(n):
		case optionsNode == nil && (n.Kind() == "object" || n.Kind() == "identifier" || n.Kind() == "member_expression" || n.Kind() == "call_expression"):
			if argvNode == nil && !spec.shell && n.Kind() != "object" {
				// A non-literal second argument may be an argv array or options.
				argvNode = n
			} else {
				optionsNode = n
			}
		}
	}
	firstSlot := analysis.CommandSlotShell
	if !spec.shell {
		firstSlot = analysis.CommandSlotExecutable
	}
	// Options first: shell mode decides how the operands are read.
	configEvidence := call
	if optionsNode != nil {
		configEvidence = optionsNode
		if optionsNode.Kind() != "object" {
			b.facts.APIShellMode, b.facts.EffectiveShellMode = "unknown", "unknown"
			if spec.shell {
				b.facts.APIShellMode = "enabled"
				b.facts.EffectiveShellMode = "enabled"
			}
			b.gap("command_options_unresolved", "process options are not an object literal", optionsNode)
		} else if props, resolved := jsOptions(f.module, optionsNode); !resolved {
			if !spec.shell {
				b.facts.APIShellMode, b.facts.EffectiveShellMode = "unknown", "unknown"
			}
			b.gap("command_options_unresolved", "process options contain a spread, computed or duplicate key", optionsNode)
		} else {
			f.nodeShellOption(b, spec.shell, props, optionsNode)
			for _, key := range []string{"cwd", "env"} {
				if v := props[key]; v != nil {
					if value := f.quiet(v); len(value.deps) > 0 {
						b.gap("command_configuration_request_controlled", key+" option is request-derived; it is configuration, not command text", v)
					}
				}
			}
		}
	}
	b.context = append(b.context, f.module.evidence("execution_configuration", configEvidence))
	first := f.quiet(nodes[0])
	if nodes[0].Kind() == "spread_element" {
		first = value{}
	}
	// A literal shell as the executable with -c keeps an interpreter command operand.
	interpreterCommand := -1
	literalExe, _ := stringLiteral(nodes[0], f.module.src)
	if !spec.shell && argvNode != nil && argvNode.Kind() == "array" {
		switch literalExe {
		case "sh", "bash", "/bin/sh", "/bin/bash", "/usr/bin/sh", "/usr/bin/bash":
			if argvNode.NamedChildCount() >= 2 {
				if flag, ok := stringLiteral(argvNode.NamedChild(0), f.module.src); ok && flag == "-c" {
					interpreterCommand = 1
					b.facts.EffectiveShellMode = "enabled"
					b.facts.Interpreter = literalExe + " -c"
				}
			}
		case "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh":
			b.facts.EffectiveShellMode = "unknown"
			b.facts.Interpreter = literalExe
			b.gap("command_interpreter_unsupported", "Windows or PowerShell interpreter semantics are not modeled", nodes[0])
		}
	}
	b.facts.JoinedShellText = !spec.shell && b.facts.EffectiveShellMode == "enabled" && b.facts.Interpreter == ""
	b.operand(firstSlot, nodes[0], first)
	switch {
	case argvNode == nil:
	case argvNode.Kind() == "array":
		b.facts.ArgvShape = "literal_list"
		index := 0
		for i := uint(0); i < argvNode.NamedChildCount(); i++ {
			e := argvNode.NamedChild(i)
			if e.Kind() == "comment" {
				continue
			}
			slot := fmt.Sprintf("%s%d", analysis.CommandSlotArgumentPrefix, index)
			if index == interpreterCommand {
				slot = analysis.CommandSlotShell
			}
			if e.Kind() == "spread_element" {
				b.facts.ArgvShape = "unknown"
				b.gap("command_spread_unresolved", "spread element in argv is not modeled", e)
				b.operand(analysis.CommandSlotArgvUnknown, e, f.quiet(e))
				break
			}
			b.operand(slot, e, f.quiet(e))
			index++
		}
	default:
		b.facts.ArgvShape = "unknown"
		b.gap("command_argv_unresolved", "argument vector is not an array literal", argvNode)
		b.operand(analysis.CommandSlotArgvUnknown, argvNode, f.quiet(argvNode))
	}
	if !b.request {
		return true // constant-only or data-only calls are not candidates
	}
	context := append([]analysis.Evidence{}, f.context...)
	context = append(context, binding...)
	// Operand/config indices were assigned relative to b.context.
	shift := len(context)
	context = append(context, b.context...)
	for i := range b.facts.Operands {
		for j := range b.facts.Operands[i].Context {
			b.facts.Operands[i].Context[j] += shift
		}
	}
	gaps := append(append([]analysis.Gap{}, f.gaps...), b.gaps...)
	use := analysis.CandidateUse{ID: fmt.Sprintf("use:%s:%s:%d", f.invocation.ID, f.module.file, call.StartByte()), EntryID: f.entry.ID, InvocationContextID: f.invocation.ID,
		Kind: "command_execution_candidate", Sink: f.module.evidence("command_execution_candidate", call), Dependencies: b.deps, Context: context, Gaps: gaps,
		Command: b.facts, APIModel: analysispacks.CommandContract(spec.contract), Assessment: analysis.Assessment{Status: "not_run"}}
	f.uses = append(f.uses, use)
	return true
}

// nodeShellOption interprets options.shell. An exec/execSync call stays
// shell-enabled whatever the option says; a custom interpreter is recorded.
func (f *flow) nodeShellOption(b *jsCommandBuilder, execLike bool, props map[string]*sitter.Node, options *sitter.Node) {
	n := props["shell"]
	if n == nil {
		return
	}
	m := f.module
	switch {
	case n.Kind() == "true":
		b.facts.APIShellMode, b.facts.EffectiveShellMode = "enabled", "enabled"
	case n.Kind() == "false" || n.Kind() == "undefined" || n.Kind() == "null":
		if execLike {
			b.gap("command_shell_option_ignored", "a disabling shell option does not turn exec into a safe argument-array API", n)
		} else {
			b.facts.APIShellMode, b.facts.EffectiveShellMode = "disabled", "disabled"
		}
	default:
		if text, ok := stringLiteral(n, m.src); ok {
			b.facts.APIShellMode, b.facts.EffectiveShellMode = "enabled", "enabled"
			b.facts.Interpreter = text
			switch text {
			case "/bin/sh", "/bin/bash", "sh", "bash", "/usr/bin/bash", "/usr/bin/sh":
			default:
				b.facts.EffectiveShellMode = "unknown"
				b.gap("command_interpreter_unsupported", "custom shell interpreter semantics are not modeled", n)
			}
			break
		}
		v := f.quiet(n)
		b.operand(analysis.CommandSlotOption, n, v)
		b.facts.APIShellMode, b.facts.EffectiveShellMode = "unknown", "unknown"
		b.gap("command_options_unresolved", "dynamic shell option", n)
	}
}
