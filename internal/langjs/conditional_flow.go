package langjs

import (
	"reflect"
	"sort"
	"strconv"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/parse"
)

// Arm preconditions of a modeled JavaScript if. They are path evidence of the
// uses on that arm; unlike branch_precondition they are not promoted to an
// invocation-wide applicable control, so one arm cannot lend its test to a sibling.
const (
	branchTruePrecondition  = "branch_true_precondition"
	branchFalsePrecondition = "branch_false_precondition"
)

// armControlKinds are context kinds that state a fact about one path. At a join of
// two continuing arms they survive only when every arm carries the same item.
var armControlKinds = map[string]bool{
	branchTruePrecondition: true, branchFalsePrecondition: true, "branch_precondition": true,
	"branch_alternative": true, "conditional_test": true, parse.ConditionalFalseTest: true, "control_statement": true, "guard_test": true,
	"exception_precondition": true, "condition": true, "terminating_guard": true, "enclosing_guard": true,
}

// conditional models an if/else-if/else statement as two isolated flows. The test
// is evaluated once; each arm records its polarity; arms that return, throw or
// call the Node process.exit leave the continuing environment; when both leave,
// the statement terminates. Helper budgets and input observations stay shared for
// the invocation. Rebinding of the request/response identifiers, client and model
// setter flows keep the conservative may-path fallback.
func (f *flow) conditional(n *sitter.Node) bool {
	test, consequence := n.ChildByFieldName("condition"), n.ChildByFieldName("consequence")
	if test == nil || consequence == nil || f.client != nil || f.setterValue != nil || f.rebindsInvocation(n) {
		f.branches(n)
		return false
	}
	f.noteWeakCondition(test)
	f.eval(test)
	positive := f.module.evidence(branchTruePrecondition, test)
	negative := f.module.evidence(branchFalsePrecondition, test)
	// Arms only append to the context, gaps and writes they fork from, so the
	// suffixes past these lengths are what each arm added.
	baseContext, baseGaps, baseWrites := len(f.context), len(f.gaps), len(f.heapWrites)

	yes := f.fork(positive)
	yesExits := yes.statement(consequence)
	no := f.fork(negative)
	no.work = yes.work
	noExits := false
	if alternative := elseBody(n); alternative != nil {
		noExits = no.statement(alternative)
	}
	f.work = no.work
	if f.conditions != nil {
		*f.conditions = append(*f.conditions, modeledCondition{test, yesExits || noExits})
	}

	arms := []*flow{yes, no}
	conditions := []analysis.Evidence{positive, negative}
	exits := []bool{yesExits, noExits}
	seen := map[string]bool{}
	for _, g := range f.gaps {
		seen[gapKey(g)] = true
	}
	addGap := func(g analysis.Gap) {
		if k := gapKey(g); !seen[k] {
			seen[k] = true
			f.gaps = append(f.gaps, g)
		}
	}
	for i, arm := range arms {
		f.uses = append(f.uses, arm.uses...)
		for _, v := range arm.returns {
			f.returns = append(f.returns, tagBranch(v, conditions[i], func(analysis.Dependency) bool { return true }, 0))
		}
		// Uncertainty found on either arm (helper limits, unresolved calls) stays
		// visible to later code; a precondition never does.
		for _, g := range arm.gaps[baseGaps:] {
			addGap(g)
		}
		// A discarded unmodeled heap write keeps its uncertainty after the join.
		for _, g := range arm.heapWrites[baseWrites:] {
			f.heapWrites = append(f.heapWrites, g)
			addGap(g)
		}
	}

	var continuing []int
	for i := range arms {
		if !exits[i] {
			continuing = append(continuing, i)
		}
	}
	switch len(continuing) {
	case 0:
		return true
	case 1:
		// Only one arm reaches later code: its environment and precondition hold.
		arm := arms[continuing[0]]
		f.env = arm.env
		f.context = arm.context
		f.responseType = arm.responseType
		return false
	}
	f.context = joinArmContext(f.context[:baseContext], yes.context[baseContext+1:], no.context[baseContext+1:])
	keys := map[string]bool{}
	for _, arm := range arms {
		for key := range arm.env {
			keys[key] = true
		}
	}
	ordered := make([]string, 0, len(keys))
	for key := range keys {
		ordered = append(ordered, key)
	}
	sort.Strings(ordered)
	merged := map[string]value{}
	for _, key := range ordered {
		a, aok := yes.env[key]
		b, bok := no.env[key]
		if aok == bok && reflect.DeepEqual(a, b) {
			merged[key] = a
			continue
		}
		merged[key] = f.joinConditionalValues([]value{a, b}, conditions, n, 0)
	}
	f.env = merged
	if yes.responseType == no.responseType {
		f.responseType = yes.responseType
	} else {
		f.responseType = "unknown"
		addGap(f.gap("unknown_control_effect", "response content type differs across conditional paths", n))
	}
	return false
}

// elseBody returns the statement of an else clause, which is itself an if for an
// else-if chain.
func elseBody(n *sitter.Node) *sitter.Node {
	alternative := n.ChildByFieldName("alternative")
	if alternative == nil || alternative.Kind() != "else_clause" {
		return alternative
	}
	for i := uint(0); i < alternative.NamedChildCount(); i++ {
		if c := alternative.NamedChild(i); c.Kind() != "comment" {
			return c
		}
	}
	return nil
}

func (f *flow) fork(condition analysis.Evidence) *flow {
	out := *f
	out.env = copyValues(f.env)
	out.context = append(append([]analysis.Evidence{}, f.context...), condition)
	out.gaps = append([]analysis.Gap{}, f.gaps...)
	out.heapWrites = append([]analysis.Gap{}, f.heapWrites...)
	out.uses = nil
	out.returns = nil
	return &out
}

// joinArmContext keeps binding evidence either arm found and path controls only
// when both arms carry them; arm-only preconditions describe one path.
func joinArmContext(base, a, b []analysis.Evidence) []analysis.Evidence {
	out := append([]analysis.Evidence{}, base...)
	present := map[analysis.Evidence]bool{}
	for _, e := range out {
		present[e] = true
	}
	inB := map[analysis.Evidence]bool{}
	for _, e := range b {
		inB[e] = true
	}
	inA := map[analysis.Evidence]bool{}
	for _, e := range a {
		inA[e] = true
	}
	add := func(e analysis.Evidence, other map[analysis.Evidence]bool) {
		if present[e] || (armControlKinds[e.Kind] && !other[e]) {
			return
		}
		present[e] = true
		out = append(out, e)
	}
	for _, e := range a {
		add(e, inB)
	}
	for _, e := range b {
		add(e, inA)
	}
	return out
}

func gapKey(g analysis.Gap) string {
	return g.Kind + "|" + g.Detail + "|" + g.At.File + "|" + strconv.Itoa(g.At.StartByte) + "|" + strconv.Itoa(g.At.EndByte)
}

// rebindsInvocation reports a write to the request or response identifier inside
// the statement. Those need an identity join, not only a value join.
func (f *flow) rebindsInvocation(n *sitter.Node) bool {
	found := false
	var visit func(*sitter.Node)
	visit = func(cur *sitter.Node) {
		if found || cur == nil {
			return
		}
		if isFunction(cur) || cur.Kind() == "function_declaration" {
			return
		}
		var bindings []*sitter.Node
		switch cur.Kind() {
		case "assignment_expression", "augmented_assignment_expression":
			bindings = append(bindings, cur.ChildByFieldName("left"))
		case "variable_declarator":
			bindings = append(bindings, cur.ChildByFieldName("name"))
		case "update_expression":
			bindings = append(bindings, cur.ChildByFieldName("argument"))
		}
		for _, binding := range bindings {
			for binding != nil && binding.Kind() == "parenthesized_expression" && binding.NamedChildCount() == 1 {
				binding = binding.NamedChild(0)
			}
			if binding == nil {
				continue
			}
			if binding.Kind() == "identifier" {
				if name := binding.Utf8Text(f.module.src); name != "" && (name == f.request || name == f.response) {
					found = true
					return
				}
				continue
			}
			// A destructuring pattern can rebind the identifiers too.
			if patternBinds(binding, f.module.src, f.request, f.response) {
				found = true
				return
			}
		}
		for i := uint(0); i < cur.NamedChildCount(); i++ {
			visit(cur.NamedChild(i))
		}
	}
	visit(n)
	return found
}

func patternBinds(n *sitter.Node, src []byte, names ...string) bool {
	if n.Kind() != "object_pattern" && n.Kind() != "array_pattern" {
		return false
	}
	found := false
	var walk func(*sitter.Node)
	walk = func(c *sitter.Node) {
		if found || c == nil {
			return
		}
		switch c.Kind() {
		case "identifier", "shorthand_property_identifier_pattern":
			for _, name := range names {
				if name != "" && c.Utf8Text(src) == name {
					found = true
				}
			}
			return
		}
		for i := uint(0); i < c.NamedChildCount(); i++ {
			walk(c.NamedChild(i))
		}
	}
	walk(n)
	return found
}

// zeroValue is an absent or undefined binding: no dependency, field, gap or
// metadata. It does not take part in binding agreement at a join.
func zeroValue(v value) bool {
	if len(v.deps) > 0 || len(v.gaps) > 0 || v.fields != nil {
		return false
	}
	v.deps, v.gaps, v.pathObjectClosed = nil, nil, false
	return reflect.DeepEqual(v, value{})
}

func (f *flow) joinConditionalValues(values []value, conditions []analysis.Evidence, at *sitter.Node, depth int) value {
	count := map[string]int{}
	for _, v := range values {
		seen := map[string]bool{}
		for _, d := range v.deps {
			key := dependencyKey(d)
			if !seen[key] {
				count[key]++
				seen[key] = true
			}
		}
	}
	var out value
	for i, v := range values {
		v = tagBranch(v, conditions[i], func(d analysis.Dependency) bool { return count[dependencyKey(d)] < len(values) }, 0)
		v.fields = nil
		out = combine(out, v)
	}
	fieldNames := map[string]bool{}
	object := false
	for _, v := range values {
		object = object || v.fields != nil
		for name := range v.fields {
			fieldNames[name] = true
		}
	}
	if object && len(fieldNames) == 0 {
		out.fields = map[string]value{}
	}
	if len(fieldNames) > 0 {
		if depth >= 8 {
			out.gaps = append(out.gaps, f.gap("unknown_control_effect", "conditional object-field join depth limit reached", at))
		} else {
			out.fields = map[string]value{}
			ordered := make([]string, 0, len(fieldNames))
			for name := range fieldNames {
				ordered = append(ordered, name)
			}
			sort.Strings(ordered)
			for _, name := range ordered {
				fields := make([]value, len(values))
				same := true
				for i, v := range values {
					fields[i] = v.fields[name]
					_, ok := v.fields[name]
					_, first := values[0].fields[name]
					same = same && ok == first && reflect.DeepEqual(fields[i], fields[0])
				}
				if same {
					out.fields[name] = fields[0]
					continue
				}
				out.fields[name] = f.joinConditionalValues(fields, conditions, at, depth+1)
			}
		}
	}
	// combine is a may-dependency join; callable, storage, input and output
	// identities require agreement across every defined arm to remain verified.
	var defined []value
	for _, v := range values {
		if !zeroValue(v) {
			defined = append(defined, v)
		}
	}
	out.model, out.read = "", nil
	out.graphqlArgs, out.graphqlTransfers = nil, nil
	out.grpcInput, out.grpcTransfers = nil, nil
	out.trustedContext, out.templateFile, out.outputContext = "", "", ""
	out.apiPath, out.apiMethod, out.responseField = "", "", ""
	out.pathArchive, out.pathArchiveBinding = "", nil
	out.pathObjectClosed = true
	if len(defined) == 0 {
		out.gaps = uniqueGaps(out.gaps)
		return out
	}
	first := defined[0]
	out.model, out.read = first.model, first.read
	out.readAlternatives = append([]analysis.Evidence{}, first.readAlternatives...)
	out.graphqlArgs, out.graphqlTransfers = first.graphqlArgs, append([]analysis.Evidence{}, first.graphqlTransfers...)
	out.grpcInput, out.grpcTransfers = first.grpcInput, append([]analysis.Evidence{}, first.grpcTransfers...)
	out.trustedContext, out.templateFile, out.outputContext = first.trustedContext, first.templateFile, first.outputContext
	out.apiPath, out.apiMethod, out.responseField = first.apiPath, first.apiMethod, first.responseField
	out.pathArchive, out.pathArchiveBinding = first.pathArchive, first.pathArchiveBinding
	uncertain := false
	for _, v := range defined {
		out.pathObjectClosed = out.pathObjectClosed && v.pathObjectClosed
	}
	if len(defined) < len(values) {
		// An undefined arm has no object shape to close.
		out.pathObjectClosed = false
	}
	for _, v := range defined[1:] {
		if v.model != first.model || v.read != first.read {
			if v.model == first.model && strings.HasPrefix(v.model, "prisma:") && v.read != nil && first.read != nil && f.set != nil && f.set.nextProjectFor(f.module.file) != nil {
				// Same-model read alternatives retain the physical column identity; every
				// query witness stays separate when that column is projected.
				out.readAlternatives = append(out.readAlternatives, *first.read, *v.read)
				out.readAlternatives = append(out.readAlternatives, v.readAlternatives...)
			} else {
				out.model, out.read = "", nil
				out.readAlternatives = nil
				uncertain = true
			}
		}
		if v.graphqlArgs != first.graphqlArgs || !reflect.DeepEqual(v.graphqlTransfers, first.graphqlTransfers) {
			out.graphqlArgs, out.graphqlTransfers = nil, nil
			uncertain = true
		}
		if v.grpcInput != first.grpcInput || !reflect.DeepEqual(v.grpcTransfers, first.grpcTransfers) {
			out.grpcInput, out.grpcTransfers = nil, nil
			uncertain = true
		}
		if v.trustedContext != first.trustedContext {
			out.trustedContext = ""
			uncertain = true
		}
		if v.templateFile != first.templateFile {
			out.templateFile = ""
			uncertain = true
		}
		if v.outputContext != first.outputContext {
			out.outputContext = ""
			uncertain = true
		}
		if v.apiPath != first.apiPath || v.apiMethod != first.apiMethod || v.responseField != first.responseField {
			out.apiPath, out.apiMethod, out.responseField = "", "", "*"
			uncertain = true
		}
		if v.pathArchive != first.pathArchive || v.pathArchiveBinding != first.pathArchiveBinding {
			out.pathArchive, out.pathArchiveBinding = "", nil
			uncertain = true
		}
	}
	if uncertain {
		out.gaps = append(out.gaps, f.gap("unknown_control_effect", "conditional paths have different binding or origin metadata", at))
	}
	out.gaps = uniqueGaps(out.gaps)
	return out
}

// promoteInvocationPreconditions makes invocation controls of the arm
// preconditions that dominate the end of one resolver/handler walk and that every
// use of the walk carries: a true test becomes conditional_test, a false one
// conditional_false_test, keeping its polarity. A precondition only some uses
// carry, or that does not hold at the end of the walk, stays path evidence on
// them, so a test on one arm never becomes a control of a sibling arm.
func promoteInvocationPreconditions(uses []analysis.CandidateUse, final []analysis.Evidence) {
	if len(uses) == 0 {
		return
	}
	dominating := map[analysis.Evidence]bool{}
	for _, e := range final {
		dominating[e] = true
	}
	common := map[analysis.Evidence]int{}
	for _, u := range uses {
		seen := map[analysis.Evidence]bool{}
		for _, e := range u.Context {
			if (e.Kind == branchTruePrecondition || e.Kind == branchFalsePrecondition) && !seen[e] {
				seen[e] = true
				common[e]++
			}
		}
	}
	for i := range uses {
		for j, e := range uses[i].Context {
			if common[e] != len(uses) || !dominating[e] {
				continue
			}
			uses[i].Context[j].Kind = "conditional_test"
			if e.Kind == branchFalsePrecondition {
				uses[i].Context[j].Kind = parse.ConditionalFalseTest
			}
		}
	}
}
