package parse

import (
	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
	"reflect"
	"sort"
)

// conditional isolates each arm, retaining only continuing environments at the
// join. Collected source observations and helper work limits remain invocation-wide.
func (f *flow) conditional(n *sitter.Node) bool {
	if f.client != nil || f.setterValue != nil || f.rebindsInvocation(n) {
		f.branches(n)
		return false
	}
	test := n.ChildByFieldName("condition")
	if test == nil {
		f.branches(n)
		return false
	}
	f.noteWeakCondition(test)
	f.eval(test)
	yes, no := f.conditionalFork(), f.conditionalFork()
	positive := f.module.evidence("branch_precondition", test)
	negative := f.module.evidence("branch_false_precondition", test)
	yes.context = append(yes.context, positive)
	yt := yes.statement(n.ChildByFieldName("consequence"))
	no.work = yes.work
	no.context = append(no.context, negative)
	alternative := n.ChildByFieldName("alternative")
	if alternative != nil && alternative.Kind() == "else_clause" {
		for i := uint(0); i < alternative.NamedChildCount(); i++ {
			if c := alternative.NamedChild(i); c.Kind() != "comment" {
				alternative = c
				break
			}
		}
	}
	nt := false
	if alternative != nil {
		nt = no.statement(alternative)
	}
	f.work = no.work
	f.uses = append(f.uses, yes.uses...)
	f.uses = append(f.uses, no.uses...)
	for _, arm := range []struct {
		branch    *flow
		condition analysis.Evidence
	}{{yes, positive}, {no, negative}} {
		f.gaps = append(f.gaps, arm.branch.gaps...)
		for _, v := range arm.branch.returns {
			f.returns = append(f.returns, tagBranch(v, arm.condition, func(analysis.Dependency) bool { return true }, 0))
		}
	}
	f.gaps = uniqueGaps(f.gaps)
	var exits []*flow
	var conditions []analysis.Evidence
	if !yt {
		exits = append(exits, yes)
		conditions = append(conditions, positive)
	}
	if !nt {
		exits = append(exits, no)
		conditions = append(conditions, negative)
	}
	if len(exits) == 0 {
		return true
	}
	if len(exits) == 1 {
		f.context = exits[0].context
		f.env = map[string]value{}
		for key, v := range exits[0].env {
			f.env[key] = tagBranch(v, conditions[0], func(analysis.Dependency) bool { return true }, 0)
		}
		f.responseType = exits[0].responseType
		return false
	}
	keys := map[string]bool{}
	for _, b := range exits {
		for key := range b.env {
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
		values := make([]value, len(exits))
		for i, b := range exits {
			values[i] = b.env[key]
		}
		merged[key] = f.joinConditionalValues(values, conditions, n, 0)
	}
	f.env = merged
	if yes.responseType == no.responseType {
		f.responseType = yes.responseType
	} else {
		f.responseType = "unknown"
		f.gaps = append(f.gaps, f.gap("unknown_control_effect", "response content type differs across conditional paths", n))
	}
	return false
}

func (f *flow) conditionalFork() *flow {
	out := *f
	out.env = copyValues(f.env)
	out.context = append([]analysis.Evidence{}, f.context...)
	out.gaps = append([]analysis.Gap{}, f.gaps...)
	out.uses = nil
	out.returns = nil
	return &out
}

// Invocation-parameter writes need an identity join, not only a value join.
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
		var binding *sitter.Node
		switch cur.Kind() {
		case "assignment_expression", "augmented_assignment_expression":
			binding = cur.ChildByFieldName("left")
		case "variable_declarator":
			binding = cur.ChildByFieldName("name")
		case "update_expression":
			binding = cur.ChildByFieldName("argument")
		}
		if binding != nil && binding.Kind() == "identifier" {
			name := binding.Utf8Text(f.module.src)
			if name == f.request || name == f.response {
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
		out = combine(out, v)
	}
	fieldNames := map[string]bool{}
	for _, v := range values {
		for name := range v.fields {
			fieldNames[name] = true
		}
	}
	if len(fieldNames) > 0 {
		if depth >= 8 {
			out.fields = nil
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
				for i, v := range values {
					fields[i] = v.fields[name]
				}
				out.fields[name] = f.joinConditionalValues(fields, conditions, at, depth+1)
			}
		}
	}
	// combine is a may-dependency join; callable/storage/input identities require
	// agreement across all arms before they can remain a verified binding.
	first := values[0]
	out.graphqlArgs = first.graphqlArgs
	out.graphqlTransfers = append([]analysis.Evidence{}, first.graphqlTransfers...)
	out.grpcInput = first.grpcInput
	out.grpcTransfers = append([]analysis.Evidence{}, first.grpcTransfers...)
	out.pathObjectClosed = first.pathObjectClosed
	for _, v := range values[1:] {
		uncertain := false
		if v.model != first.model || v.read != first.read {
			out.model = ""
			out.read = nil
			uncertain = true
		}
		if v.graphqlArgs != first.graphqlArgs || !reflect.DeepEqual(v.graphqlTransfers, first.graphqlTransfers) {
			out.graphqlArgs = nil
			out.graphqlTransfers = nil
			uncertain = true
		}
		if v.grpcInput != first.grpcInput || !reflect.DeepEqual(v.grpcTransfers, first.grpcTransfers) {
			out.grpcInput = nil
			out.grpcTransfers = nil
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
		if v.apiPath != first.apiPath || v.apiMethod != first.apiMethod || v.responseField != first.responseField {
			out.apiPath = ""
			out.apiMethod = ""
			out.responseField = "*"
			uncertain = true
		}
		if v.pathArchive != first.pathArchive || v.pathArchiveBinding != first.pathArchiveBinding {
			out.pathArchive = ""
			out.pathArchiveBinding = nil
			uncertain = true
		}
		out.pathObjectClosed = out.pathObjectClosed && v.pathObjectClosed
		if uncertain {
			out.gaps = append(out.gaps, f.gap("unknown_control_effect", "conditional paths have different binding or origin metadata", at))
		}
	}
	return out
}
