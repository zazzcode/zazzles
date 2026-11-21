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

func (s *phpSet) phpDeserializationBuiltin(m *phpModule, callee *sitter.Node) bool {
	name := phpText(m, callee)
	if strings.HasPrefix(name, `\`) {
		return !strings.Contains(strings.TrimPrefix(name, `\`), `\`)
	}
	if callee.Kind() != "name" {
		return false
	}
	// Most builtins have no repository declaration with this name.
	s.indexBuiltinEffects()
	if !s.builtinEffects[strings.ToLower(name)] && !strings.Contains(string(m.src), "function") {
		return true
	}
	x := s.classIndex()
	scope := x.scopeAt(m, callee.StartByte())
	shadowed := false
	for _, file := range s.files {
		module := s.modules[file]
		if module == nil {
			continue
		}
		phpWalk(module.tree.RootNode(), func(n *sitter.Node) {
			switch n.Kind() {
			case "function_definition":
				shadowed = shadowed || strings.EqualFold(phpText(module, phpField(n, "name")), name) &&
					strings.EqualFold(x.scopeAt(module, n.StartByte()).namespace, scope.namespace)
			case "namespace_use_declaration":
				if module != m || x.scopeAt(m, n.StartByte()).start != scope.start {
					return
				}
				shadowed = shadowed || phpImportsDeserializationFunction(m, n, name)
			}
		})
		if shadowed {
			return false
		}
	}
	return true
}

func phpImportsDeserializationFunction(m *phpModule, declaration *sitter.Node, name string) bool {
	group := phpField(declaration, "body")
	parent := declaration
	if group != nil {
		parent = group
	}
	for i := uint(0); i < parent.NamedChildCount(); i++ {
		clause := parent.NamedChild(i)
		if clause.Kind() != "namespace_use_clause" {
			continue
		}
		kind := phpField(clause, "type")
		if kind == nil {
			kind = phpField(declaration, "type")
		}
		if kind == nil || kind.Kind() != "function" {
			continue
		}
		names := map[string]string{}
		phpUseClause(m, clause, "", names)
		if _, exists := names[strings.ToLower(name)]; exists {
			return true
		}
	}
	return false
}

func (f *phpFlow) phpSymfonyYAML(scope *sitter.Node) bool {
	if scope == nil || scope.Kind() != "name" && scope.Kind() != "qualified_name" {
		return false
	}
	x := f.set.classIndex()
	class := x.qualify(f.module, phpText(f.module, scope), scope.StartByte())
	return strings.EqualFold(class, symfonyYAMLClass) && len(x.byName[strings.ToLower(class)]) == 0
}

func (f *phpFlow) phpYAMLFlags(n *sitter.Node) (object, literal bool) {
	m := f.module
	switch n.Kind() {
	case "parenthesized_expression":
		if n.NamedChildCount() == 1 {
			return f.phpYAMLFlags(n.NamedChild(0))
		}
	case "integer":
		// An integer can include the object bit without naming the constant.
		return false, phpText(m, n) == "0"
	case "class_constant_access_expression":
		if n.NamedChildCount() == 2 && f.phpSymfonyYAML(n.NamedChild(0)) {
			return phpText(m, n.NamedChild(1)) == "PARSE_OBJECT", true
		}
	case "binary_expression":
		if phpText(m, phpField(n, "operator")) == "|" {
			left, right := phpField(n, "left"), phpField(n, "right")
			if left != nil && right != nil {
				a, aLiteral := f.phpYAMLFlags(left)
				b, bLiteral := f.phpYAMLFlags(right)
				return a || b, aLiteral && bLiteral
			}
		}
	}
	return false, false
}

func (f *phpFlow) deserializationOptions(call, option *sitter.Node) *sitter.Node {
	m := f.module
	if option.Kind() == "array_creation_expression" {
		return option
	}
	if option.Kind() == "name" {
		root := m.tree.RootNode()
		for i := uint(0); i < root.NamedChildCount(); i++ {
			decl := root.NamedChild(i)
			if decl.Kind() != "const_declaration" {
				continue
			}
			for j := uint(0); j < decl.NamedChildCount(); j++ {
				item := decl.NamedChild(j)
				if item.Kind() == "const_element" && item.NamedChildCount() == 2 && phpText(m, item.NamedChild(0)) == phpText(m, option) {
					return item.NamedChild(1)
				}
			}
		}
		return nil
	}
	if option.Kind() != "variable_name" {
		return nil
	}
	var scope *sitter.Node
	for p := call.Parent(); p != nil; p = p.Parent() {
		if p.Kind() == "function_definition" || p.Kind() == "method_declaration" || p.Kind() == "program" {
			scope = p
			break
		}
	}
	if scope == nil {
		return nil
	}
	var initializer *sitter.Node
	var writes int
	name := phpText(m, option)
	phpWalk(scope, func(n *sitter.Node) {
		if n.Kind() != "variable_name" || phpText(m, n) != name {
			return
		}
		left, parent := n, n.Parent()
		for parent != nil && parent.Kind() == "subscript_expression" && parent.NamedChild(0).Id() == left.Id() {
			left, parent = parent, parent.Parent()
		}
		if parent == nil {
			return
		}
		switch parent.Kind() {
		case "assignment_expression", "augmented_assignment_expression", "reference_assignment_expression":
			if target := phpField(parent, "left"); target == nil || target.Id() != left.Id() {
				return
			}
			writes++
			stmt := parent.Parent()
			if n.Id() == left.Id() && parent.Kind() == "assignment_expression" && parent.EndByte() < call.StartByte() && stmt != nil && stmt.Kind() == "expression_statement" {
				for p := call.Parent(); p != nil; p = p.Parent() {
					if stmt.Parent() != nil && p.Id() == stmt.Parent().Id() {
						initializer = phpField(parent, "right")
						break
					}
				}
			}
		case "simple_parameter", "variadic_parameter", "update_expression", "unset_statement":
			writes++
		}
	})
	if writes == 1 {
		return initializer
	}
	return nil
}

func phpAllowedClasses(m *phpModule, option *sitter.Node) *sitter.Node {
	if option == nil || option.Kind() != "array_creation_expression" {
		return nil
	}
	var out *sitter.Node
	for i := uint(0); i < option.NamedChildCount(); i++ {
		pair := option.NamedChild(i)
		if pair.Kind() != "array_element_initializer" || pair.NamedChildCount() != 2 {
			// A spread can override a previous key.
			if strings.HasPrefix(phpText(m, pair), "...") {
				out = nil
			}
			continue
		}
		key, ok := phpStringLiteral(m, pair.NamedChild(0))
		if !ok {
			out = nil
		} else if key == "allowed_classes" {
			out = pair.NamedChild(1)
		}
	}
	return out
}

func phpLiteralClassList(m *phpModule, n *sitter.Node) bool {
	if n.Kind() != "array_creation_expression" {
		return false
	}
	for i := uint(0); i < n.NamedChildCount(); i++ {
		pair := n.NamedChild(i)
		if pair.Kind() == "comment" {
			continue
		}
		if pair.Kind() != "array_element_initializer" || pair.NamedChildCount() != 1 {
			return false
		}
		item := pair.NamedChild(0)
		if _, ok := phpStringLiteral(m, item); ok {
			continue
		}
		if item.Kind() != "class_constant_access_expression" || item.NamedChildCount() != 2 || !strings.EqualFold(phpText(m, item.NamedChild(1)), "class") || item.NamedChild(0).Kind() == "variable_name" {
			return false
		}
	}
	return true
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

func (f *phpFlow) phpDeserializationGuards(u *analysis.CandidateUse, call *sitter.Node, names [][]string) ([]analysis.Evidence, []int) {
	var guards []analysis.Evidence
	var indices []int
	add := func(e analysis.Evidence, index int) {
		for _, pathNames := range names {
			if parse.MentionsAny(e.Text, pathNames) {
				if index < 0 {
					index = len(u.Context)
					u.Context = append(u.Context, e)
				}
				guards, indices = append(guards, e), append(indices, index)
				return
			}
		}
	}
	for i, e := range u.Context {
		kind := strings.TrimPrefix(e.Kind, "ssrf_")
		if kind == "branch_precondition" || kind == "branch_false_precondition" {
			add(e, i)
		}
	}
	// The PHP flow joins reject-and-continue branches without propagating
	// their context. Cite simple terminating siblings within the same block.
	for child, parent := call, call.Parent(); parent != nil; child, parent = parent, parent.Parent() {
		switch parent.Kind() {
		case "function_definition", "method_declaration", "anonymous_function":
			return guards, indices
		case "compound_statement", "program":
			for i := uint(0); i < parent.NamedChildCount(); i++ {
				stmt := parent.NamedChild(i)
				if stmt.StartByte() >= child.StartByte() {
					break
				}
				test, body := phpField(stmt, "condition"), phpField(stmt, "body")
				if stmt.Kind() != "if_statement" || test == nil || body == nil || phpField(stmt, "alternative") != nil || !f.phpRejectingDeserializationBranch(body) {
					continue
				}
				// Skip conditions on an earlier version of the operand.
				reassigned := false
				for _, d := range u.Dependencies {
					for _, tr := range d.Transfers {
						reassigned = reassigned || tr.Kind == "assignment" && tr.Span.File == f.module.file && tr.Span.StartByte > int(stmt.EndByte())
					}
				}
				if !reassigned {
					add(f.module.evidence("branch_false_precondition", test), -1)
				}
			}
		}
	}
	return guards, indices
}

func (f *phpFlow) phpRejectingDeserializationBranch(body *sitter.Node) bool {
	if body.Kind() == "compound_statement" || body.Kind() == "colon_block" {
		// Requiring a single unconditional statement excludes side effects and
		// conditional termination that the surrounding statement cannot prove.
		if body.NamedChildCount() != 1 {
			return false
		}
		body = body.NamedChild(0)
	}
	return body.Kind() == "exit_statement" || body.Kind() == "return_statement" ||
		body.Kind() == "expression_statement" && f.terminatingCall(body)
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

func (f *phpFlow) phpDeserializationGuard(e analysis.Evidence) string {
	m := f.set.modules[e.Span.File]
	kind := analysis.DeserializationFormat
	if m == nil {
		return kind
	}
	n := parse.NodeAt(m.tree.RootNode(), e.Span.StartByte, e.Span.EndByte)
	if n == nil {
		return kind
	}
	phpWalk(n, func(n *sitter.Node) {
		if n.Kind() != "function_call_expression" || kind == analysis.DeserializationIntegrity {
			return
		}
		fn := phpCallee(n)
		if fn == nil || !f.set.phpDeserializationBuiltin(m, fn) {
			return
		}
		switch strings.ToLower(strings.TrimPrefix(phpText(m, fn), `\`)) {
		case "hash_hmac", "hash_equals", "sodium_crypto_auth_verify":
			kind = analysis.DeserializationIntegrity
		case "md5", "sha1", "hash", "crc32":
			kind = analysis.DeserializationUnkeyedHash
		}
	})
	return kind
}

func (s *phpSet) phpMagicClasses() []analysis.Evidence {
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
	return out[:min(20, len(out))]
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
