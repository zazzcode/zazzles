package langjs

import (
	"fmt"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
	"github.com/zazzcode/zazzles/scan/internal/parse"
)

func (f *flow) deserializationCall(call, fn, args *sitter.Node, values []value) {
	if f.client != nil || f.set == nil {
		return
	}
	// values parallels the named children, comments included.
	index := jsArgumentIndex(args, 0)
	if index < 0 || index >= len(values) || len(values[index].deps) == 0 {
		return
	}
	data := values[index]
	m := f.module
	facts, importNode, ok := f.set.jsDeserializationFacts(m, call, fn, args)
	if !ok {
		return
	}
	fileOnly := true
	for _, d := range data.deps {
		fileOnly = fileOnly && d.Source.Kind == "file_read"
	}
	if fileOnly {
		return
	}
	deps := append([]analysis.Dependency{}, data.deps...)
	for i := range deps {
		deps[i].SinkSlot = "data"
		facts.Paths = append(facts.Paths, analysis.CommandPath{Dependency: i, Operand: "data"})
	}
	context := append([]analysis.Evidence{}, f.context...)
	context = append(context, m.evidence("sink_binding", fn), m.evidence("sink_binding", importNode))
	u := analysis.CandidateUse{
		ID:      fmt.Sprintf("use:%s:%s:%d:deserialization", f.invocation.ID, m.file, call.StartByte()),
		EntryID: f.entry.ID, EntryKind: f.entry.Kind, InvocationContextID: f.invocation.ID,
		Kind: analysis.DeserializationKind, Sink: m.evidence(analysis.DeserializationKind, call),
		Dependencies: deps, Context: context, Gaps: append(append([]analysis.Gap{}, f.gaps...), data.gaps...),
		Deserialization: &facts, Assessment: analysis.Assessment{Status: "not_run"},
	}
	u.NoteDeserializationOrigin()
	f.uses = append(f.uses, u)
}

// jsArgumentIndex returns the named-child index of the argument at a
// position, skipping the comments the grammar lists among the arguments, or
// -1 when the call has no such argument.
func jsArgumentIndex(args *sitter.Node, position int) int {
	if args == nil {
		return -1
	}
	for i := uint(0); i < args.NamedChildCount(); i++ {
		if args.NamedChild(i).Kind() == "comment" {
			continue
		}
		if position == 0 {
			return int(i)
		}
		position--
	}
	return -1
}

// jsArgument returns the argument at a position, or nil.
func jsArgument(args *sitter.Node, position int) *sitter.Node {
	if i := jsArgumentIndex(args, position); i >= 0 {
		return args.NamedChild(uint(i))
	}
	return nil
}

func (s *moduleSet) jsDeserializationFacts(m *sourceModule, call, fn, args *sitter.Node) (analysis.DeserializationFacts, *sitter.Node, bool) {
	lib, op, binding := deserializationJSImport(m, call, fn)
	facts := analysis.DeserializationFacts{Operation: lib + "." + op, Capability: analysis.DeserializationCodeExecution}
	switch {
	case lib == "node-serialize" && op == "unserialize", lib == "funcster" && op == "deepDeserialize":
		facts.ContractID = analysispacks.NodeSerialize
	case lib == "js-yaml" && containsString([]string{"load", "loadAll", "safeLoad", "safeLoadAll"}, op):
		facts.ContractID = analysispacks.JSYAML
		if !s.jsYAMLDeserialization(m, call, args, op, &facts) {
			return facts, nil, false
		}
	default:
		return facts, nil, false
	}
	return facts, binding, true
}

func deserializationJSImport(m *sourceModule, at, fn *sitter.Node) (module, name string, declaration *sitter.Node) {
	fn = unwrapTS(fn)
	if fn == nil {
		return
	}
	if fn.Kind() == "member_expression" {
		if mod, member, ok := requireBinding(m, fn); ok && !shadowed(at, "require", m.src) && !bindingReassigned(m, "require") {
			return mod, member, fn
		}
		obj, prop := fn.ChildByFieldName("object"), fn.ChildByFieldName("property")
		if obj == nil || obj.Kind() != "identifier" || prop == nil {
			return
		}
		module, member, decl := deserializationJSImport(m, at, obj)
		if decl != nil && (member == "*" || member == "default") {
			return module, prop.Utf8Text(m.src), decl
		}
		return "", "", nil
	}
	if fn.Kind() != "identifier" {
		return
	}
	local := fn.Utf8Text(m.src)
	if deserializationJSShadowed(m, at, local) || m.bindingWrites().written[local] {
		return
	}
	if imp, ok := m.imports[local]; ok && m.funcs[local] == nil {
		return imp.module, imp.name, imp.declaration
	}
	// TypeScript import assignments carry a nested require clause.
	if !strings.HasSuffix(m.file, ".ts") && !strings.HasSuffix(m.file, ".tsx") {
		return
	}
	root := m.tree.RootNode()
	for i := uint(0); i < root.NamedChildCount(); i++ {
		stmt := root.NamedChild(i)
		if stmt.Kind() != "import_statement" || stmt.NamedChildCount() == 0 {
			continue
		}
		clause := stmt.NamedChild(0)
		if clause.Kind() != "import_require_clause" || clause.NamedChildCount() < 2 || clause.NamedChild(0).Utf8Text(m.src) != local {
			continue
		}
		if mod, ok := stringLiteral(clause.ChildByFieldName("source"), m.src); ok {
			return mod, "*", stmt
		}
	}
	return
}

func deserializationJSShadowed(m *sourceModule, at *sitter.Node, name string) bool {
	if shadowed(at, name, m.src) {
		return true
	}
	for p := at.Parent(); p != nil; p = p.Parent() {
		if p.Kind() != "statement_block" {
			continue
		}
		for i := uint(0); i < p.NamedChildCount(); i++ {
			stmt := p.NamedChild(i)
			if stmt.Kind() == "function_declaration" || stmt.Kind() == "class_declaration" {
				if id := stmt.ChildByFieldName("name"); id != nil && id.Utf8Text(m.src) == name {
					return true
				}
			}
		}
	}
	return false
}

func (s *moduleSet) jsYAMLDeserialization(m *sourceModule, call, args *sitter.Node, op string, f *analysis.DeserializationFacts) bool {
	schema, explicit, opaque := jsYAMLSchema(m, args, op)
	// An options value the scanner cannot read may carry a schema.
	if strings.HasPrefix(op, "safe") && !explicit && !opaque {
		return false
	}
	if schema != nil {
		f.Option = schema.Utf8Text(m.src)
	}
	version := s.packageVersion(m.file, "js-yaml")
	v, ok := exactVersion(version)
	if !ok {
		f.Capability, f.OptionGap = analysis.DeserializationUnresolved, "version_unknown"
		return true
	}
	f.Version = version
	legacy := versionLess(v, [3]int{4, 0, 0})
	if !explicit && !opaque {
		return legacy
	}
	lib, name, _ := deserializationJSImport(m, call, schema)
	if lib == "js-yaml" && !opaque {
		switch name {
		case "CORE_SCHEMA", "JSON_SCHEMA", "FAILSAFE_SCHEMA":
			return false
		case "DEFAULT_FULL_SCHEMA":
			if legacy {
				return true
			}
		case "DEFAULT_SAFE_SCHEMA":
			if legacy {
				return false
			}
		case "DEFAULT_SCHEMA":
			if !legacy {
				return false
			}
		}
	}
	f.Capability, f.OptionGap = analysis.DeserializationUnresolved, "loader_unresolved"
	return true
}

func jsYAMLSchema(m *sourceModule, args *sitter.Node, op string) (schema *sitter.Node, explicit, opaque bool) {
	option := unwrapTS(jsArgument(args, 1))
	if containsString([]string{"loadAll", "safeLoadAll"}, op) {
		if third := jsArgument(args, 2); option == nil || isFunction(option) || third != nil {
			option = unwrapTS(third)
		}
	}
	if option == nil || option.Kind() == "null" {
		return
	}
	if option.Kind() != "object" {
		return nil, false, true
	}
	for i := uint(0); i < option.NamedChildCount(); i++ {
		item := option.NamedChild(i)
		if item.Kind() == "spread_element" {
			opaque = true
		}
		if item.Kind() == "shorthand_property_identifier" && item.Utf8Text(m.src) == "schema" {
			schema, explicit, opaque = item, true, false
		}
		key := item.ChildByFieldName("key")
		if key != nil {
			if key.Kind() == "computed_property_name" {
				opaque = true
			}
			if literal, _ := stringLiteral(key, m.src); literal == "schema" || key.Utf8Text(m.src) == "schema" {
				schema, explicit, opaque = item.ChildByFieldName("value"), true, false
			}
		}
	}
	return
}

func (s *moduleSet) assembleDeserializationClaims(report *analysis.AnalysisReport) {
	s.assembleClaims(report, claimHooks{
		kind: analysis.DeserializationKind, checkID: "automatic-deserialization", checkKind: "deserialization",
		chainEvidence: s.interpreterChainEvidence, fields: commandFields, guards: s.interpreterGuards,
		present: func(u *analysis.CandidateUse) bool { return u.Deserialization != nil },
		chainGapCovered: func(u *analysis.CandidateUse, g analysis.Gap) bool {
			return s.jsDeserializationGapCovered(u, g)
		},
		gapCovered: func(u *analysis.CandidateUse, g analysis.Gap, complete bool, bodies, transforms []analysis.Evidence, extra map[string][]analysis.Evidence) bool {
			if s.jsDeserializationGapCovered(u, g) {
				if s.touchesAnyDependency(g, *u) {
					if m := s.modules[g.At.File]; m != nil {
						if n := parse.NodeAt(m.tree.RootNode(), g.At.StartByte, g.At.EndByte); n != nil && jsDeserializationTransfer(m, n) {
							extra["transformation"] = append(extra["transformation"], m.evidence("content_preserving_transfer", n))
						}
					}
				}
				return true
			}
			return s.commandGapCovered(u, g, complete, bodies, transforms, extra)
		},
		complete: func(u *analysis.CandidateUse, extra map[string][]analysis.Evidence, blockers, coverage []analysis.Gap) *analysis.Completeness {
			c := parse.SSRFCompleteness(u, extra, blockers, coverage)
			c.ClaimKind = "deserialization"
			c.Scope = "Verified deserializer and independent data operand paths."
			c.Required = []string{"input_source", "sink_binding", "invoked_callable", "control_flow", "deserialization_operand"}
			c.Evidence["deserialization_operand"] = []analysis.Evidence{u.Sink}
			if m := s.modules[u.Sink.Span.File]; m != nil {
				if call := parse.NodeAt(m.tree.RootNode(), u.Sink.Span.StartByte, u.Sink.Span.EndByte); call != nil {
					if operand := jsArgument(call.ChildByFieldName("arguments"), 0); operand != nil {
						c.Evidence["deserialization_operand"] = []analysis.Evidence{m.evidence("deserialization_operand", operand)}
					}
				}
			}
			delete(c.Evidence, "destination_operand")
			return c
		},
		finish: func(u *analysis.CandidateUse, c *analysis.Completeness, guards []analysis.Evidence, indices []int) {
			f := u.Deserialization
			parse.FinishOperandPaths(u, f.Paths, c, guards, indices, s.commandDerivedNames(u), parse.GapTouchesDependency)
			for i, guard := range guards {
				f.Controls = append(f.Controls, analysis.DeserializationControl{Kind: s.jsDeserializationGuard(guard), Context: indices[i]})
			}
		},
		contract: func(u *analysis.CandidateUse) *analysis.APIModel {
			return analysispacks.DeserializationContract(u.Deserialization.ContractID)
		}, resolve: s.resolveGuardedControlFlow,
	})
}

func (s *moduleSet) jsDeserializationGapCovered(use *analysis.CandidateUse, g analysis.Gap) bool {
	switch g.Kind {
	case "unknown_transfer", "input_helper_unresolved", "unknown_value":
	default:
		return false
	}
	m := s.modules[g.At.File]
	if m == nil {
		return false
	}
	n := parse.NodeAt(m.tree.RootNode(), g.At.StartByte, g.At.EndByte)
	if n == nil {
		return false
	}
	if g.Kind == "unknown_value" && n.Kind() == "identifier" {
		member := n.Parent()
		return member != nil && member.Kind() == "member_expression" && sameNode(member.ChildByFieldName("object"), n) && member.Parent() != nil &&
			member.Parent().Kind() == "call_expression" && jsDeserializationTransfer(m, member.Parent())
	}
	if n.Kind() != "call_expression" {
		return false
	}
	if g.Kind == "input_helper_unresolved" && g.At.File == use.Sink.Span.File &&
		g.At.StartByte <= use.Sink.Span.StartByte && g.At.EndByte >= use.Sink.Span.EndByte {
		// An outer call takes the deserializer's result, after the data operand has been consumed.
		return true
	}
	if g.At.File == use.Sink.Span.File && g.At.StartByte == use.Sink.Span.StartByte && g.At.EndByte == use.Sink.Span.EndByte {
		return true
	}
	return jsDeserializationTransfer(m, n)
}

func jsDeserializationTransfer(m *sourceModule, n *sitter.Node) bool {
	fn := n.ChildByFieldName("function")
	if fn == nil {
		return false
	}
	name := fn.Utf8Text(m.src)
	root, _, _ := strings.Cut(name, ".")
	if containsString([]string{"Buffer.from", "String", "atob", "decodeURIComponent", "decodeURI", "unescape"}, name) &&
		!shadowed(n, root, m.src) && !topLevelBinding(m, root) && !m.bindingWrites().written[root] {
		return true
	}
	if prop := fn.ChildByFieldName("property"); prop != nil && prop.Utf8Text(m.src) == "toString" {
		return true
	}
	lib, op, _ := deserializationJSImport(m, n, fn)
	return (lib == "zlib" || lib == "node:zlib") && containsString([]string{"inflateSync", "gunzipSync", "unzipSync", "brotliDecompressSync"}, op)
}

func (s *moduleSet) jsDeserializationGuard(e analysis.Evidence) string {
	kind := analysis.DeserializationFormat
	m := s.modules[e.Span.File]
	if m == nil {
		return kind
	}
	n := parse.NodeAt(m.tree.RootNode(), e.Span.StartByte, e.Span.EndByte)
	if n != nil && n.Kind() == "if_statement" {
		n = n.ChildByFieldName("condition")
	}
	if n == nil {
		return kind
	}
	walkNodes(n, func(child *sitter.Node) {
		if child.Kind() != "call_expression" || kind == analysis.DeserializationIntegrity {
			return
		}
		lib, op, _ := deserializationJSImport(m, child, child.ChildByFieldName("function"))
		if lib != "crypto" && lib != "node:crypto" {
			return
		}
		switch op {
		case "createHmac", "timingSafeEqual":
			kind = analysis.DeserializationIntegrity
		case "createHash":
			kind = analysis.DeserializationUnkeyedHash
		}
	})
	return kind
}
