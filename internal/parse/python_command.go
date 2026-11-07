package parse

import (
	"fmt"
	"path/filepath"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
)

// pythonCommandOps lists the verified process operations. Contract IDs are
// owned by the catalog; selection happens only after the binding is verified.
var pythonCommandOps = map[string]struct {
	contract string
	shell    bool // always a shell command string (os.*)
	keyword  string
}{
	"os.system":               {analysispacks.PythonOSContract, true, "command"},
	"os.popen":                {analysispacks.PythonOSContract, true, "cmd"},
	"subprocess.run":          {analysispacks.PythonSubprocessID, false, "args"},
	"subprocess.Popen":        {analysispacks.PythonSubprocessID, false, "args"},
	"subprocess.call":         {analysispacks.PythonSubprocessID, false, "args"},
	"subprocess.check_call":   {analysispacks.PythonSubprocessID, false, "args"},
	"subprocess.check_output": {analysispacks.PythonSubprocessID, false, "args"},
}

// commandTampered reports a local module shadowing the standard library module
// or a source-visible monkey-patch of a process API. Either defeats a verified
// binding; the result is cached per set.
func (s *pythonSet) commandTampered(m *pythonModule, module string) bool {
	if s.tampered == nil {
		s.tampered = map[string]bool{}
		for _, file := range s.files {
			mod := s.modules[file]
			if mod == nil {
				continue
			}
			pyWalk(mod.tree.RootNode(), func(n *sitter.Node) {
				switch n.Kind() {
				case "assignment", "augmented_assignment":
					left := n.ChildByFieldName("left")
					if left == nil || left.Kind() != "attribute" {
						return
					}
					root := strings.Split(pyText(mod, left), ".")[0]
					if imp, ok := mod.imports[root]; ok && imp.name == "" && (imp.module == "os" || imp.module == "subprocess") {
						s.tampered["patch:"+imp.module] = true
					}
				case "call":
					fn := pyText(mod, n.ChildByFieldName("function"))
					if fn == "setattr" {
						if args := pyArgs(n); len(args) > 0 {
							root := pyText(mod, args[0])
							if imp, ok := mod.imports[root]; ok && imp.name == "" && (imp.module == "os" || imp.module == "subprocess") {
								s.tampered["patch:"+imp.module] = true
							}
						}
					}
				}
			})
		}
	}
	if s.tampered["patch:"+module] {
		return true
	}
	dir := filepath.ToSlash(filepath.Dir(m.file))
	for _, candidate := range []string{module + ".py", module + "/__init__.py", dir + "/" + module + ".py", dir + "/" + module + "/__init__.py"} {
		if s.modules[candidate] != nil {
			return true
		}
	}
	return false
}

// pythonReassigned reports more than one module-scope assignment to name.
func pythonReassigned(m *pythonModule, name string) bool {
	count := 0
	pyWalk(m.tree.RootNode(), func(n *sitter.Node) {
		if n.Kind() == "assignment" || n.Kind() == "augmented_assignment" || n.Kind() == "delete_statement" {
			left := n.ChildByFieldName("left")
			if left != nil && left.Kind() == "identifier" && pyText(m, left) == name {
				count++
			}
		}
	})
	return count > 1
}

// commandOperation resolves the called function to a supported operation after
// verifying the actual import binding, shadowing and aliasing.
func (f *pythonFlow) commandOperation(fn *sitter.Node) (string, []analysis.Evidence, bool) {
	m := f.module
	name := pyText(m, fn)
	root := strings.Split(name, ".")[0]
	q := f.qualified(name)
	var declaration *sitter.Node
	if q == "" {
		// An immutable module-level alias such as `run = subprocess.run`.
		if _, shadow := f.env[root]; shadow || name != root || f.set.staticInvalid[m.file+":"+root] {
			return "", nil, false
		}
		node := m.vars[root]
		if node == nil || (node.Kind() != "attribute" && node.Kind() != "identifier") || pythonReassigned(m, root) {
			return "", nil, false
		}
		q = f.set.qualified(m, pyText(m, node))
		aliasRoot := strings.Split(pyText(m, node), ".")[0]
		if imp, ok := m.imports[aliasRoot]; ok {
			declaration = imp.node
		}
	}
	op, ok := pythonCommandOps[q]
	if !ok {
		return "", nil, false
	}
	module := strings.Split(q, ".")[0]
	if f.set.commandTampered(m, module) {
		return "", nil, false
	}
	if declaration == nil {
		if imp, ok := f.imports[root]; ok {
			declaration = imp.node
		} else if imp, ok := m.imports[root]; ok {
			declaration = imp.node
		}
	}
	_ = op
	evidence := []analysis.Evidence{}
	if declaration != nil {
		evidence = append(evidence, m.evidence("sink_binding", declaration))
	}
	evidence = append(evidence, m.evidence("sink_binding", fn))
	return q, evidence, true
}

// quiet evaluates an operand again without recording uses, gaps or context
// a second time.
func (f *pythonFlow) quiet(n *sitter.Node) pythonValue {
	uses, gaps, context, work := len(f.report.Uses), len(f.gaps), len(f.context), *f.work
	v := f.eval(n)
	f.report.Uses, f.gaps, f.context, *f.work = f.report.Uses[:uses], f.gaps[:gaps], f.context[:context], work
	return v
}

type pyCommandBuilder struct {
	f       *pythonFlow
	facts   *analysis.CommandFacts
	deps    []pythonDep
	context []analysis.Evidence
	gaps    []analysis.Gap
	names   map[string]bool
	request bool
}

func (b *pyCommandBuilder) operand(slot string, n *sitter.Node, v pythonValue) {
	o := analysis.CommandOperand{Slot: slot}
	if text, ok := pyLiteral(b.f.module, n); ok {
		o.Constant = text
	} else {
		o.Dynamic = true
	}
	pyWalk(n, func(c *sitter.Node) {
		if c.Kind() == "identifier" {
			b.names[pyText(b.f.module, c)] = true
		}
	})
	o.Context = append(o.Context, len(b.context))
	b.context = append(b.context, b.f.module.evidence("command_operand", n))
	for _, d := range v.deps {
		d.dep.SinkSlot = slot
		o.Dependencies = append(o.Dependencies, len(b.deps))
		b.facts.Paths = append(b.facts.Paths, analysis.CommandPath{Dependency: len(b.deps), Operand: slot, Protection: "raw"})
		b.deps = append(b.deps, d)
		b.request = true
		b.names[d.container+"."+d.key] = true
		b.names[d.dep.Source.Text] = true
		for _, name := range commandDepNames(d.dep) {
			b.names[name] = true
		}
	}
	b.gaps = append(b.gaps, v.gaps...)
	b.facts.Operands = append(b.facts.Operands, o)
}

func (b *pyCommandBuilder) gap(kind, detail string, n *sitter.Node) {
	b.gaps = append(b.gaps, b.f.gap(kind, detail, n))
}

func pyBool(n *sitter.Node) (value, known bool) {
	if n == nil {
		return false, false
	}
	switch n.Kind() {
	case "true":
		return true, true
	case "false":
		return false, true
	}
	return false, false
}

// commandCall recognizes a verified os/subprocess call and records a
// command_execution_candidate when request data reaches a process operand.
func (f *pythonFlow) commandCall(call, fn *sitter.Node) (pythonValue, bool) {
	q, binding, ok := f.commandOperation(fn)
	if !ok {
		return pythonValue{}, false
	}
	spec := pythonCommandOps[q]
	m := f.module
	b := &pyCommandBuilder{f: f, names: map[string]bool{}, facts: &analysis.CommandFacts{Operation: q, ContractID: spec.contract, Platform: "posix", APIShellMode: "disabled", EffectiveShellMode: "disabled", ArgvShape: "none", Operands: []analysis.CommandOperand{}, Paths: []analysis.CommandPath{}}}
	if spec.shell {
		b.facts.APIShellMode, b.facts.EffectiveShellMode = "enabled", "enabled"
	}
	positional := pyArgs(call)
	for i := uint(0); call.ChildByFieldName("arguments") != nil && i < call.ChildByFieldName("arguments").NamedChildCount(); i++ {
		c := call.ChildByFieldName("arguments").NamedChild(i)
		if c.Kind() == "list_splat" || c.Kind() == "dictionary_splat" || c.Kind() == "parenthesized_expression" && strings.HasPrefix(pyText(m, c), "*") {
			b.gap("command_spread_unresolved", "*args/**kwargs in a process call are not modeled", c)
		}
	}
	var first *sitter.Node
	if len(positional) > 0 {
		first = positional[0]
	} else {
		first = pyKeywordIn(m, call, spec.keyword)
	}
	if first == nil || first.Kind() == "list_splat" {
		return pythonValue{}, true
	}
	shellNode := pyKeywordIn(m, call, "shell")
	executableNode := pyKeywordIn(m, call, "executable")
	if q == "subprocess.Popen" {
		// Popen accepts bufsize, executable, ..., shell positionally.
		if len(positional) > 2 && executableNode == nil {
			executableNode = positional[2]
		}
		if len(positional) > 7 && shellNode == nil {
			shellNode = positional[7]
		}
		if len(positional) > 8 {
			b.gap("command_options_unresolved", "positional Popen options beyond shell are not modeled", positional[8])
		}
	} else if !spec.shell && len(positional) > 1 {
		b.gap("command_options_unresolved", "unexpected positional process arguments", positional[1])
	}
	b.context = append(b.context, m.evidence("execution_configuration", call))
	if !spec.shell {
		if shellNode != nil {
			if value, known := pyBool(shellNode); known && value {
				b.facts.APIShellMode, b.facts.EffectiveShellMode = "enabled", "enabled"
			} else if known {
				b.facts.APIShellMode, b.facts.EffectiveShellMode = "disabled", "disabled"
			} else {
				b.facts.APIShellMode, b.facts.EffectiveShellMode = "unknown", "unknown"
				b.operand(analysis.CommandSlotOption, shellNode, f.quiet(shellNode))
				b.gap("command_options_unresolved", "dynamic shell option", shellNode)
			}
		}
		if executableNode != nil {
			if text, lit := pyLiteral(m, executableNode); lit && !strings.Contains(text, "{") {
				b.operand(analysis.CommandSlotOverride, executableNode, f.quiet(executableNode))
			} else {
				b.operand(analysis.CommandSlotOverride, executableNode, f.quiet(executableNode))
			}
		}
		for _, key := range []string{"cwd", "env"} {
			if n := pyKeywordIn(m, call, key); n != nil {
				if v := f.quiet(n); len(v.deps) > 0 {
					b.gap("command_configuration_request_controlled", key+" is configuration, not command text", n)
				}
			}
		}
	}
	shellEnabled := b.facts.EffectiveShellMode == "enabled"
	switch first.Kind() {
	case "list", "tuple":
		b.facts.ArgvShape = "literal_list"
		var items []*sitter.Node
		for i := uint(0); i < first.NamedChildCount(); i++ {
			c := first.NamedChild(i)
			if c.Kind() == "comment" {
				continue
			}
			items = append(items, c)
		}
		interpreter := ""
		if !shellEnabled && len(items) >= 2 {
			exe, _ := pyLiteral(m, items[0])
			flag, _ := pyLiteral(m, items[1])
			switch exe {
			case "sh", "bash", "/bin/sh", "/bin/bash", "/usr/bin/sh", "/usr/bin/bash":
				if flag == "-c" {
					interpreter = exe + " -c"
				}
			case "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh":
				b.facts.EffectiveShellMode, b.facts.Interpreter = "unknown", exe
				b.gap("command_interpreter_unsupported", "Windows or PowerShell interpreter semantics are not modeled", items[0])
			}
		}
		if interpreter != "" {
			b.facts.EffectiveShellMode, b.facts.Interpreter = "enabled", interpreter
		}
		for i, item := range items {
			slot := fmt.Sprintf("%s%d", analysis.CommandSlotArgumentPrefix, i)
			switch {
			case item.Kind() == "list_splat":
				b.facts.ArgvShape = "unknown"
				b.gap("command_spread_unresolved", "starred element in an argument vector is not modeled", item)
				slot = analysis.CommandSlotArgvUnknown
			case shellEnabled && i == 0:
				slot = analysis.CommandSlotShell
			case !shellEnabled && interpreter == "" && i == 0:
				slot = analysis.CommandSlotExecutable
			case interpreter != "" && i == 0:
				slot = analysis.CommandSlotExecutable
			case interpreter != "" && i == 2:
				slot = analysis.CommandSlotShell
			}
			if b.has(slot) {
				continue
			}
			b.operand(slot, item, f.quiet(item))
		}
	default:
		// A string or an expression whose shape is not a literal sequence.
		slot := analysis.CommandSlotExecutable
		if shellEnabled {
			slot = analysis.CommandSlotShell
		} else if _, lit := pyLiteral(m, first); !lit && !spec.shell {
			b.facts.ArgvShape = "unknown"
			b.gap("command_argv_unresolved", "process arguments are not a string or list literal", first)
		}
		b.operand(slot, first, f.quiet(first))
	}
	if !b.request {
		return pythonValue{}, true
	}
	var all pythonValue
	for _, d := range b.deps {
		all.deps = append(all.deps, d)
	}
	all.gaps = b.gaps
	u := f.addUse("command_execution_candidate", call, all)
	u.Command = b.facts
	u.APIModel = analysispacks.CommandContract(spec.contract)
	u.Dependencies = make([]analysis.Dependency, len(b.deps))
	for i, d := range b.deps {
		u.Dependencies[i] = d.dep
	}
	// Guards the flow reached this call under, that mention an operand.
	guardIndex := []int{}
	var guards []analysis.Evidence
	base := len(u.Context) + len(binding)
	u.Context = append(u.Context, binding...)
	for _, e := range f.context {
		if (e.Kind == "branch_precondition" || e.Kind == "branch_false_precondition") && b.mentions(e.Text) && !b.presenceOnly(e.Text) {
			guardIndex = append(guardIndex, len(u.Context))
			u.Context = append(u.Context, e)
			guards = append(guards, e)
		}
	}
	base = len(u.Context)
	u.Context = append(u.Context, b.context...)
	for i := range u.Command.Operands {
		for j := range u.Command.Operands[i].Context {
			u.Command.Operands[i].Context[j] += base
		}
	}
	f.completePythonCommand(u, call, all, guards, guardIndex, b.names)
	return pythonValue{}, true
}

func (b *pyCommandBuilder) has(slot string) bool {
	for _, o := range b.facts.Operands {
		if o.Slot == slot {
			return true
		}
	}
	return false
}

func (b *pyCommandBuilder) presenceOnly(text string) bool {
	names := make([]string, 0, len(b.names))
	for name := range b.names {
		names = append(names, name)
	}
	return presenceOnlyCondition(text, names)
}

func (b *pyCommandBuilder) mentions(text string) bool {
	for name := range b.names {
		if name != "" && name != "." && strings.Contains(text, name) {
			return true
		}
	}
	return false
}

// pythonCommandBlockers are the gap kinds that leave an operand path unresolved.
var pythonCommandBlockers = map[string]bool{
	"python_parameter_unresolved": true, "python_value_unresolved": true, "python_call_unresolved": true, "python_loop_unresolved": true,
	"python_comprehension_unresolved": true, "python_decorator_unresolved": true, "work_limit": true, "dependency_limit": true, "transfer_limit": true,
	"input_helper_unresolved": true, "python_finally_unresolved": true, "python_dispatch_unresolved": true, "python_callback_unresolved": true,
	"command_spread_unresolved": true, "command_options_unresolved": true, "command_argv_unresolved": true, "command_interpreter_unsupported": true,
}

// completePythonCommand assembles the claim-scoped completeness for a Python
// use at the point where its flow, guards and operands are known.
func (f *pythonFlow) completePythonCommand(u *analysis.CandidateUse, call *sitter.Node, operands pythonValue, guards []analysis.Evidence, guardIndex []int, names map[string]bool) {
	blockers := []analysis.Gap{}
	coverage := []analysis.Gap{}
	transfers := []analysis.Evidence{}
	for _, g := range append(append([]analysis.Gap{}, u.Gaps...), f.guardGaps(operands)...) {
		if !pythonCommandBlockers[g.Kind] || (g.Kind == "python_call_unresolved" && g.At.StartByte == int(call.StartByte()) && g.At.File == f.module.file) {
			coverage = append(coverage, g)
			continue
		}
		if evidence, ok := f.supportedCommandGap(g, names); ok {
			coverage = append(coverage, g)
			transfers = append(transfers, evidence)
			continue
		}
		blockers = append(blockers, g)
	}
	extra := map[string][]analysis.Evidence{
		"invoked_callable": {f.route.module.evidence("invoked_callable", f.route.fn)},
		"control_flow":     append([]analysis.Evidence{f.module.evidence("operation", call)}, f.context...),
		"transformation":   transfers,
	}
	c := commandCompleteness(u, extra, dedupeGaps(blockers), dedupeGaps(coverage))
	for _, t := range transfers {
		c.ModelFacts = append(c.ModelFacts, "Supported transfer "+t.Kind+" "+t.Text+" at "+t.Span.File+" carries its operand into the result without a modeled constraint; it is not a validator.")
	}
	finishCommandPaths(u, c, guards, guardIndex, func(g analysis.Gap, d analysis.Dependency) bool {
		return gapTouchesDependency(g, d) || pythonGapTouches(g, d)
	})
	u.Completeness = c
	u.Gaps = dedupeGaps(append(append([]analysis.Gap{}, u.Gaps...), blockers...))
}

// supportedCommandGap recognizes gaps that do not make a command operand
// unknown: content-preserving stream reads/conversions and loops whose body
// never reassigns an operand. Other analyzers keep their conservative gaps.
func (f *pythonFlow) supportedCommandGap(g analysis.Gap, names map[string]bool) (analysis.Evidence, bool) {
	m := f.set.modules[g.At.File]
	if m == nil {
		return analysis.Evidence{}, false
	}
	node := nodeAt(m.tree.RootNode(), g.At.StartByte, g.At.EndByte)
	if node == nil {
		return analysis.Evidence{}, false
	}
	switch g.Kind {
	case "python_call_unresolved":
		if node.Kind() != "call" {
			return analysis.Evidence{}, false
		}
		fn := node.ChildByFieldName("function")
		if fn == nil || fn.Kind() != "attribute" {
			return analysis.Evidence{}, false
		}
		switch pyText(m, fn.ChildByFieldName("attribute")) {
		case "read", "readline", "decode", "encode":
			return m.evidence("content_preserving_transfer", node), true
		}
	case "python_loop_unresolved":
		if node.Kind() != "for_statement" && node.Kind() != "while_statement" {
			return analysis.Evidence{}, false
		}
		mutated := false
		pyWalk(node.ChildByFieldName("body"), func(n *sitter.Node) {
			switch n.Kind() {
			case "assignment", "augmented_assignment":
				if left := n.ChildByFieldName("left"); left != nil {
					root := left
					for root != nil && (root.Kind() == "attribute" || root.Kind() == "subscript") {
						if root.Kind() == "attribute" {
							root = root.ChildByFieldName("object")
						} else {
							root = root.ChildByFieldName("value")
						}
					}
					if root != nil && names[pyText(m, root)] {
						mutated = true
					}
				}
			case "call":
				// A method call on an operand may mutate it in place.
				if fn := n.ChildByFieldName("function"); fn != nil && fn.Kind() == "attribute" {
					if obj := fn.ChildByFieldName("object"); obj != nil && names[pyText(m, obj)] {
						mutated = true
					}
				}
			}
		})
		if !mutated {
			return m.evidence("loop_without_operand_mutation", node), true
		}
	}
	return analysis.Evidence{}, false
}

// pythonGapTouches reports a gap located inside any transfer of the dependency.
func pythonGapTouches(g analysis.Gap, d analysis.Dependency) bool {
	for _, e := range d.Transfers {
		if g.At.File == e.Span.File && g.At.StartByte >= e.Span.StartByte && g.At.EndByte <= e.Span.EndByte && e.Kind == "call_argument_dependency" {
			return true
		}
	}
	return false
}
