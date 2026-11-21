package langphp

import (
	"sort"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
	"github.com/zazzcode/zazzles/scan/internal/parse"
)

const symfonyYAMLClass = `Symfony\Component\Yaml\Yaml`

func (f *phpFlow) deserializationCall(call *sitter.Node, nodes []*sitter.Node, values []phpValue) {
	m := f.module
	callee := phpCallee(call)
	if len(nodes) == 0 || callee == nil {
		return
	}
	name := phpText(m, callee)
	facts := analysis.DeserializationFacts{Capability: analysis.DeserializationObjectInjection}
	var option, operand *sitter.Node
	var value phpValue
	var restriction bool
	switch call.Kind() {
	case "function_call_expression":
		if !strings.EqualFold(strings.TrimPrefix(name, `\`), "unserialize") || !f.set.phpDeserializationBuiltin(m, callee) {
			return
		}
		facts.Operation, facts.ContractID = "unserialize", analysispacks.PHPUnserialize
		operand, value = f.deserializationArgument(call, nodes, values, 0, "data")
		option, _ = f.deserializationArgument(call, nodes, values, 1, "options")
		if option != nil {
			facts.Option = phpText(m, option)
			if classes := phpAllowedClasses(m, f.deserializationOptions(call, option)); classes != nil {
				if strings.EqualFold(phpText(m, classes), "false") {
					return
				}
				restriction = phpLiteralClassList(m, classes)
			}
		}
	case "scoped_call_expression":
		scope := phpField(call, "scope")
		if !strings.EqualFold(name, "parse") || !f.phpSymfonyYAML(scope) {
			return
		}
		facts.Operation, facts.ContractID = symfonyYAMLClass+"::parse", analysispacks.PHPSymfonyYAML
		operand, value = f.deserializationArgument(call, nodes, values, 0, "input")
		option, _ = f.deserializationArgument(call, nodes, values, 1, "flags")
		if option == nil {
			return
		}
		facts.Option = phpText(m, option)
		object, literal := f.phpYAMLFlags(option)
		if literal && !object {
			return
		}
		if !literal {
			facts.Capability, facts.OptionGap = analysis.DeserializationUnresolved, "loader_unresolved"
		}
	default:
		return
	}
	if operand != nil && len(value.deps) > 0 {
		f.recordDeserialization(call, callee, operand, option, value, facts, restriction)
	}
}

func (f *phpFlow) deserializationArgument(call *sitter.Node, nodes []*sitter.Node, values []phpValue, slot uint, keyword string) (*sitter.Node, phpValue) {
	args := phpField(call, "arguments")
	var positional uint
	for i := uint(0); args != nil && i < args.NamedChildCount(); i++ {
		arg := args.NamedChild(i)
		if arg.Kind() != "argument" || arg.NamedChildCount() == 0 {
			continue
		}
		name := phpField(arg, "name")
		if name != nil {
			if phpText(f.module, name) == keyword {
				n := arg.NamedChild(arg.NamedChildCount() - 1)
				return n, f.eval(n)
			}
			continue
		}
		if positional == slot && int(i) < len(nodes) {
			return nodes[i], values[i]
		}
		positional++
	}
	return nil, phpValue{}
}

func (f *phpFlow) recordDeserialization(call, callee, operand, option *sitter.Node, v phpValue, facts analysis.DeserializationFacts, restriction bool) {
	m := f.module
	u := f.addUse(analysis.DeserializationKind, call, v)
	u.NoteDeserializationOrigin()
	binding := m.evidence("sink_binding", callee)
	u.Deserialization = &facts
	u.APIModel = analysispacks.DeserializationContract(facts.ContractID)
	u.Context = append(u.Context, binding)
	extra := map[string][]analysis.Evidence{
		"sink_binding":            {binding},
		"invoked_callable":        {f.entryEvidence()},
		"deserialization_operand": {m.evidence("deserialization_operand", operand)},
		"control_flow":            append([]analysis.Evidence{m.evidence("operation", call)}, f.context...),
	}
	var blockers, coverage []analysis.Gap
	for _, g := range u.Gaps {
		switch g.Kind {
		case "php_call_unresolved":
			if transfer, ok := f.phpDeserializationTransfer(g); ok {
				extra["transformation"] = append(extra["transformation"], transfer)
				coverage = append(coverage, g)
				continue
			}
			for _, d := range u.Dependencies {
				if parse.GapTouchesDependency(g, d) {
					blockers = append(blockers, g)
					break
				}
			}
		case "php_parameter_unresolved", "php_value_unresolved", "php_expression_unresolved", "php_global_unresolved", "php_loop_unresolved", "work_limit", "dependency_limit", "transfer_limit":
			blockers = append(blockers, g)
		default:
			coverage = append(coverage, g)
		}
	}
	blockers = append(blockers, phpStoredOnlyBlockers(v.deps, u.Sink.Span)...)
	c := parse.SSRFCompleteness(u, extra, blockers, coverage)
	c.ClaimKind = "deserialization"
	c.Scope = "Verified deserializer and independent data operand paths."
	c.Required = []string{"input_source", "sink_binding", "invoked_callable", "control_flow", "deserialization_operand"}
	delete(c.Evidence, "destination_operand")
	if facts.ContractID == analysispacks.PHPUnserialize {
		c.Evidence["deserialization_magic_class"] = f.set.phpMagicClasses()
	}
	u.Completeness = c
	var derived [][]string
	for i := range u.Dependencies {
		d := &u.Dependencies[i]
		d.SinkSlot = "data"
		facts.Paths = append(facts.Paths, analysis.CommandPath{Dependency: i, Operand: "data"})
		derived = append(derived, parse.CommandDepNames(*d))
	}
	guards, indices := f.phpDeserializationGuards(u, call, derived)
	for i, e := range guards {
		facts.Controls = append(facts.Controls, analysis.DeserializationControl{Context: indices[i], Kind: f.phpDeserializationGuard(e)})
	}
	parse.FinishOperandPaths(u, facts.Paths, c, guards, indices, derived, parse.GapTouchesDependency)
	if restriction {
		u.AddDeserializationClassRestriction(m.evidence("deserialization_class_restriction", option))
	}
}

func (f *phpFlow) phpDeserializationTransfer(g analysis.Gap) (analysis.Evidence, bool) {
	m := f.set.modules[g.At.File]
	if m == nil {
		return analysis.Evidence{}, false
	}
	n := parse.NodeAt(m.tree.RootNode(), g.At.StartByte, g.At.EndByte)
	if n == nil || n.Kind() != "function_call_expression" {
		return analysis.Evidence{}, false
	}
	callee := phpCallee(n)
	switch strings.ToLower(strings.TrimPrefix(phpText(m, callee), `\`)) {
	case "base64_decode", "urldecode", "rawurldecode", "hex2bin", "gzuncompress", "gzinflate", "gzdecode", "stripslashes", "trim":
		if callee != nil && f.set.phpDeserializationBuiltin(m, callee) {
			return m.evidence("content_preserving_transfer", n), true
		}
	}
	return analysis.Evidence{}, false
}

// phpMagicClasses lists, once per source set, the project classes a
// deserialized object can trigger: at most 20, by file then position.
func (s *phpSet) phpMagicClasses() []analysis.Evidence {
	if s.magicClassesReady {
		return s.magicClasses
	}
	x := s.classIndex()
	var out []analysis.Evidence
	for _, declarations := range x.byName {
		for _, d := range declarations {
			if d.kind != "class" || !phpHasDeserializationHook(x, d) {
				continue
			}
			out = append(out, d.module.evidence("deserialization_magic_class", phpField(d.node, "name")))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i].Span, out[j].Span
		if a.File != b.File {
			return a.File < b.File
		}
		return a.StartByte < b.StartByte
	})
	n := min(20, len(out))
	// Clipped so no record can append into the slice the others cite.
	s.magicClasses, s.magicClassesReady = out[:n:n], true
	return s.magicClasses
}

func phpHasDeserializationHook(x *phpClassIndex, d *phpClassDecl) bool {
	for _, name := range []string{"__wakeup", "__unserialize", "__destruct", "__toString", "__call", "__get", "__set", "__invoke"} {
		if phpOwnMethod(d, name) != nil {
			return true
		}
	}
	for i := uint(0); i < d.node.NamedChildCount(); i++ {
		clause := d.node.NamedChild(i)
		if clause.Kind() != "class_interface_clause" {
			continue
		}
		for j := uint(0); j < clause.NamedChildCount(); j++ {
			name := clause.NamedChild(j)
			if strings.EqualFold(x.qualify(d.module, phpText(d.module, name), name.StartByte()), "Serializable") {
				return true
			}
		}
	}
	return false
}
