package langphp

import (
	"slices"
	"sort"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/parse"
)

// Framework types of the D-6 shapes, read from declared receiver types.
const (
	symfonyPropertyAccessor     = `Symfony\Component\PropertyAccess\PropertyAccessorInterface`
	symfonySerializer           = `Symfony\Component\Serializer\SerializerInterface`
	symfonyDenormalizer         = `Symfony\Component\Serializer\Normalizer\DenormalizerInterface`
	symfonyMapRequestPayloadArg = `Symfony\Component\HttpKernel\Attribute\MapRequestPayload`
)

// phpWholeBag reports a request dependency whose keys the request controls
// (D-7): a whole Symfony bag (all(), getPayload()->all(), toArray()) or a
// whole superglobal.
func phpWholeBag(d phpDep) bool {
	if d.dep.Source.Kind != "input_source" || d.key != "" {
		return false
	}
	switch d.container {
	case "request", "query", "body", "GET", "POST", "REQUEST":
		return true
	}
	return false
}

// phpKeyOrigin returns the request-key paths of a foreach key binding over v:
// each whole-bag dependency, with the iteration binding as its transfer. An
// array built with literal keys has none.
func phpKeyOrigin(v phpValue, at analysis.Evidence) []phpDep {
	var out []phpDep
	for _, d := range append(slices.Clone(v.deps), v.wholeBag...) {
		if phpWholeBag(d) {
			out = append(out, d)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return phpTransfer(phpValue{deps: out}, at).deps
}

// keyGuardCall marks the result of array_intersect_key with a literal key list
// as key_allow_list evidence (D-7). The returned value is otherwise unchanged.
func (f *phpFlow) keyGuardCall(n *sitter.Node, nodes []*sitter.Node, v phpValue) phpValue {
	if n.Kind() != "function_call_expression" || len(nodes) < 2 {
		return v
	}
	m := f.module
	name := strings.ToLower(strings.TrimPrefix(f.callName(n), `\`))
	if name != "array_intersect_key" || !f.builtin(name) {
		return v
	}
	for _, arg := range nodes[1:] {
		list := arg
		if arg.Kind() == "function_call_expression" && strings.EqualFold(strings.TrimPrefix(phpText(m, phpCallee(arg)), `\`), "array_flip") && f.builtin("array_flip") && len(phpArgs(arg)) == 1 {
			list = phpArgs(arg)[0]
		} else if !phpLiteralKeyArray(m, arg) {
			continue
		}
		if len(phpArrayLiteralStrings(m, list)) > 0 || phpLiteralKeyArray(m, list) {
			v.keyGuards = append(slices.Clone(v.keyGuards), m.evidence(analysis.KeyAllowList, n))
			return v
		}
	}
	return v
}

// phpLiteralKeyArray reports an array literal whose every element has a
// literal string key.
func phpLiteralKeyArray(m *phpModule, n *sitter.Node) bool {
	if n == nil || n.Kind() != "array_creation_expression" || n.NamedChildCount() == 0 {
		return false
	}
	for i := uint(0); i < n.NamedChildCount(); i++ {
		e := n.NamedChild(i)
		if e.Kind() != "array_element_initializer" || e.NamedChildCount() != 2 {
			return false
		}
		if _, ok := phpStringLiteral(m, e.NamedChild(0)); !ok {
			return false
		}
	}
	return true
}

// massAssignmentCall recognizes the call shapes of D-6: a dynamic method name
// (a set… dispatch), call_user_func with an [object, name] callable, a
// PropertyAccessorInterface::setValue, reflection property access, and the
// recorded-with-gap form, serializer and payload shapes.
func (f *phpFlow) massAssignmentCall(n *sitter.Node, nodes []*sitter.Node, values []phpValue) {
	if f.entry.HTTP == nil {
		return
	}
	m := f.module
	switch n.Kind() {
	case "member_call_expression", "nullsafe_member_call_expression":
		name, object := phpField(n, "name"), phpField(n, "object")
		if name == nil || object == nil {
			return
		}
		if name.Kind() != "name" {
			key := f.eval(phpUnwrapName(name))
			if len(key.keySources) > 0 {
				f.recordMassAssignment(n, f.eval(object).classDecl, analysis.MassAssignmentSetterCall, key, "")
			}
			return
		}
		method := phpText(m, name)
		switch method {
		case "setValue":
			if len(values) >= 3 && strings.EqualFold(f.set.receiverType(m, n, object), symfonyPropertyAccessor) && len(values[1].keySources) > 0 {
				f.recordMassAssignment(n, values[0].classDecl, analysis.MassAssignmentAccessor, values[1], "")
			}
		case "getProperty":
			if len(values) >= 1 && len(values[0].keySources) > 0 && object.Kind() == "object_creation_expression" && f.reflectionClass(object, "ReflectionClass") {
				if args := phpNewArguments(object); len(args) > 0 {
					f.recordMassAssignment(n, f.eval(args[0]).classDecl, analysis.MassAssignmentReflection, values[0], "")
				}
			}
		case "handleRequest", "submit":
			if object.Kind() != "variable_name" {
				return
			}
			data := f.formData(n, phpVarName(m, object))
			if data == nil || data.classDecl == nil || !f.doctrineEntityDecl(data.classDecl) {
				return
			}
			source := phpValue{}
			if len(nodes) > 0 {
				source = f.source(nodes[0], "request", "http.form", "")
			}
			f.recordMassAssignment(n, data.classDecl, analysis.MassAssignmentForm, source, analysis.MassAssignmentFormUnmodeled)
		case "deserialize", "denormalize":
			want := symfonySerializer
			if method == "denormalize" {
				want = symfonyDenormalizer
			}
			if len(nodes) < 2 || !strings.EqualFold(f.set.receiverType(m, n, object), want) {
				return
			}
			class := doctrineClassConstant(f.set.classIndex(), m, nodes[1])
			decl := f.symfonyClass(class)
			if decl == nil || f.symfony == nil || !f.doctrineEntityDecl(decl) {
				return
			}
			f.recordMassAssignment(n, decl, analysis.MassAssignmentSerializer, values[0], analysis.MassAssignmentSerializerUnmodeled)
		}
	case "function_call_expression":
		name := strings.ToLower(strings.TrimPrefix(f.callName(n), `\`))
		if name != "call_user_func" || !f.builtin(name) || len(nodes) < 2 {
			return
		}
		callable := nodes[0]
		if callable.Kind() != "array_creation_expression" || callable.NamedChildCount() != 2 {
			return
		}
		object, method := callable.NamedChild(0).NamedChild(0), callable.NamedChild(1).NamedChild(0)
		if object == nil || method == nil {
			return
		}
		if key := f.eval(method); len(key.keySources) > 0 {
			f.recordMassAssignment(n, f.eval(object).classDecl, analysis.MassAssignmentSetterCall, key, "")
		}
	}
}

// reflectionObject records new ReflectionProperty($object, $name) with a
// request-chosen name.
func (f *phpFlow) reflectionObject(n *sitter.Node) {
	if f.entry.HTTP == nil || !f.reflectionClass(n, "ReflectionProperty") {
		return
	}
	args := phpNewArguments(n)
	if len(args) < 2 {
		return
	}
	if key := f.eval(args[1]); len(key.keySources) > 0 {
		f.recordMassAssignment(n, f.eval(args[0]).classDecl, analysis.MassAssignmentReflection, key, "")
	}
}

func (f *phpFlow) reflectionClass(n *sitter.Node, class string) bool {
	if n == nil || n.Kind() != "object_creation_expression" {
		return false
	}
	for i := uint(0); i < n.NamedChildCount(); i++ {
		c := n.NamedChild(i)
		if c.Kind() == "name" || c.Kind() == "qualified_name" {
			x := f.set.classIndex()
			qualified := x.qualify(f.module, phpText(f.module, c), c.StartByte())
			return strings.EqualFold(qualified, class) && len(x.byName[strings.ToLower(qualified)]) == 0
		}
	}
	return false
}

// formData returns the data object of `$form = $this->createForm(Type, $data)`
// assigned to variable before call in the enclosing function.
func (f *phpFlow) formData(call *sitter.Node, variable string) *phpValue {
	m := f.module
	fn := phpEnclosing(call, "method_declaration", "function_definition")
	var data *sitter.Node
	phpWalk(phpField(fn, "body"), func(n *sitter.Node) {
		if n.StartByte() >= call.StartByte() || n.Kind() != "assignment_expression" || phpVarName(m, phpField(n, "left")) != variable {
			return
		}
		right := phpField(n, "right")
		if right == nil || right.Kind() != "member_call_expression" || phpText(m, phpField(right, "name")) != "createForm" || phpVarName(m, phpField(right, "object")) != "this" {
			return
		}
		if args := phpArgs(right); len(args) >= 2 {
			data = args[1]
		}
	})
	if data == nil || data.Kind() != "variable_name" {
		return nil
	}
	v, ok := f.env[phpVarName(m, data)]
	if !ok {
		return nil
	}
	return &v
}

// requestPayloadEntity records #[MapRequestPayload] on an action argument whose
// type is a mapped entity (D-6, recorded with its gap).
func (f *phpFlow) requestPayloadEntity(param *sitter.Node, decl *phpClassDecl) {
	if f.entry.HTTP == nil || decl == nil || !f.doctrineEntityDecl(decl) || f.symfonyAttribute(f.module, param, symfonyMapRequestPayloadArg) == nil {
		return
	}
	f.recordMassAssignment(param, decl, analysis.MassAssignmentPayload, f.source(param, "body", "http.body", ""), analysis.MassAssignmentPayloadUnmodeled)
}

func phpUnwrapName(n *sitter.Node) *sitter.Node {
	for n != nil && n.Kind() != "variable_name" && n.NamedChildCount() == 1 && n.Kind() != "member_access_expression" {
		n = n.NamedChild(0)
	}
	return n
}

// keyControlledWrite records a dynamic property write whose name the request
// chooses: $obj->$k = $v and $obj->{$k} = $v (D-6).
func (f *phpFlow) keyControlledWrite(target phpValue, key phpValue, at *sitter.Node, shape string) {
	if f.entry.HTTP == nil || len(key.keySources) == 0 {
		return
	}
	f.recordMassAssignment(at, target.classDecl, shape, key, "")
}

// recordMassAssignment emits one candidate per write per entry. For the judged
// shapes key carries the request-key paths; the framework shapes carry their
// request source and gap.
func (f *phpFlow) recordMassAssignment(sink *sitter.Node, decl *phpClassDecl, shape string, key phpValue, gapKind string) {
	m := f.module
	if decl == nil {
		return
	}
	span := parse.Span(m.file, sink)
	for _, u := range f.report.Uses {
		if u.Kind == analysis.MassAssignmentKind && u.InvocationContextID == f.invocation.ID && u.Sink.Span == span {
			return
		}
	}
	deps := key.keySources
	if gapKind != "" {
		deps = key.deps
	}
	request := false
	for _, d := range deps {
		request = request || d.dep.Source.Kind == "input_source"
	}
	if !request {
		return
	}
	u := f.addUse(analysis.MassAssignmentKind, sink, phpValue{deps: deps})
	facts := analysis.MassAssignmentFacts{Shape: shape, TargetClass: decl.fqn, TargetStored: "unresolved", SecurityFields: []analysis.SecurityField{}}
	facts.KeyGuards = phpDedupeEvidence(append(slices.Clone(key.keyGuards), f.keyConditionGuards(sink)...))
	var coverage []analysis.Gap
	switch {
	case f.symfony != nil && f.doctrineEntityDecl(decl):
		facts.TargetStored = "yes"
		keys := f.doctrineFieldKeys(decl)
		census := f.set.securityFields(f.symfony)
		var fields []securityField
		for _, name := range sortedTwigFields(keys) {
			facts.MappedFields = append(facts.MappedFields, name)
			if field, ok := census[keys[name]]; ok {
				fields = append(fields, field)
			}
		}
		facts.SecurityFields = analysisSecurityFields(fields)
		coverage = append(coverage, f.set.securityGaps(f.symfony)...)
	default:
		if f.symfony != nil {
			facts.TargetStored = "no"
		}
		var fields []securityField
		properties := symfonyProperties(decl)
		for _, name := range sortedTwigFields(properties) {
			facts.MappedFields = append(facts.MappedFields, name)
			if securityNameHints[strings.NewReplacer("_", "", "-", "").Replace(strings.ToLower(name))] {
				fields = append(fields, securityField{storageKey: "php-object:" + decl.fqn + "." + name, roles: []string{analysis.RoleNameHint},
					evidence: []analysis.Evidence{decl.module.evidence(analysis.RoleNameHint, phpPropertyElement(decl.module, properties[name], name))}})
			}
		}
		facts.SecurityFields = analysisSecurityFields(fields)
		if f.symfony == nil {
			coverage = append(coverage, analysis.Gap{Kind: analysis.SecurityFieldsUnresolved, Detail: "No framework security contract applies to this target; field roles are name hints only.", At: span})
		}
	}
	u.MassAssignment = &facts
	var sources, origins []analysis.Evidence
	for _, d := range u.Dependencies {
		sources = append(sources, d.Source)
		for _, t := range d.Transfers {
			if t.Kind == "iteration_binding" {
				origins = append(origins, t)
			}
		}
	}
	class := decl.module.evidence("target_class", phpField(decl.node, "name"))
	write := m.evidence("property_write", sink)
	c := &analysis.Completeness{
		ClaimKind: "mass_assignment",
		Required:  []string{"input_source", "key_origin", "property_write", "target_class", "control_flow"},
		Scope:     "Request-chosen property names on the target object; written values and authorization are separate claims.",
		Evidence: map[string][]analysis.Evidence{
			"input_source":   phpDedupeEvidence(sources),
			"key_origin":     phpDedupeEvidence(origins),
			"property_write": {write},
			"target_class":   {class},
			"control_flow":   append([]analysis.Evidence{m.evidence("operation", sink)}, f.context...),
		},
		Blockers: []analysis.Gap{},
		Coverage: phpMergeGaps(slices.Clone(u.Gaps), coverage),
	}
	if len(facts.KeyGuards) > 0 {
		c.Evidence["guard"] = facts.KeyGuards
	}
	if facts.TargetStored == "yes" && shape == analysis.MassAssignmentPropertyWrite {
		// The same position is the storage model's wildcard writer (D-10).
		c.Evidence["storage_write"] = []analysis.Evidence{m.evidence("storage_write_wildcard", sink)}
	}
	if gapKind != "" {
		c.Required = []string{"input_source", "property_write", "target_class", "control_flow"}
		g := analysis.Gap{Kind: gapKind, Detail: "The framework mapping's field set is not modeled in this version.", At: span}
		u.Gaps = append(u.Gaps, g)
		c.Blockers = append(c.Blockers, g)
	}
	u.Completeness = c
}

// keyConditionGuards returns the dominating conditions of a key-controlled
// write that test the key: a literal in_array(…, [...]) is key_allow_list and
// property_exists(…) is key_existence_check (D-7). Enclosing if conditions and
// earlier `if (!…) continue;` statements in the loop body count.
func (f *phpFlow) keyConditionGuards(sink *sitter.Node) []analysis.Evidence {
	m := f.module
	var out []analysis.Evidence
	classify := func(test *sitter.Node, negated bool) {
		phpWalk(test, func(n *sitter.Node) {
			if n.Kind() != "function_call_expression" {
				return
			}
			name := strings.ToLower(strings.TrimPrefix(phpText(m, phpCallee(n)), `\`))
			if !f.builtin(name) {
				return
			}
			args := phpArgs(n)
			switch {
			case name == "in_array" && len(args) >= 2 && len(phpArrayLiteralStrings(m, args[1])) > 0:
				out = append(out, m.evidence(analysis.KeyAllowList, n))
			case name == "property_exists" && len(args) == 2:
				out = append(out, m.evidence(analysis.KeyExistenceCheck, n))
			}
		})
	}
	for child, parent := sink, sink.Parent(); parent != nil; child, parent = parent, parent.Parent() {
		switch parent.Kind() {
		case "method_declaration", "function_definition", "anonymous_function", "arrow_function":
			sort.SliceStable(out, func(i, j int) bool { return out[i].Span.StartByte < out[j].Span.StartByte })
			return out
		case "if_statement":
			if body := phpField(parent, "body"); body != nil && body.Id() == child.Id() {
				classify(phpField(parent, "condition"), false)
			}
		case "compound_statement":
			for i := uint(0); i < parent.NamedChildCount(); i++ {
				s := parent.NamedChild(i)
				if s.StartByte() >= child.StartByte() {
					break
				}
				if s.Kind() == "if_statement" && phpField(s, "alternative") == nil && phpSkips(phpField(s, "body")) {
					classify(phpField(s, "condition"), true)
				}
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Span.StartByte < out[j].Span.StartByte })
	return out
}

// phpSkips reports a body that ends in continue, throw or return.
func phpSkips(body *sitter.Node) bool {
	if body == nil {
		return false
	}
	last := body
	if body.Kind() == "compound_statement" {
		if body.NamedChildCount() == 0 {
			return false
		}
		last = body.NamedChild(body.NamedChildCount() - 1)
	}
	switch last.Kind() {
	case "continue_statement", "return_statement":
		return true
	}
	return phpEndsInThrow(body)
}
