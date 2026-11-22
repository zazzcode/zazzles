package langphp

import (
	"fmt"
	"slices"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

// Account enumeration. The record is a lookup by a request value on an
// account class, the branch on its result, and the responses on each side.
// The two response lists are compared with each other; no rule reads meaning
// into the text.

// noteEnumerationLookup records a candidate for a finder call whose criteria
// hold a request value, when the two branches on its result answer
// differently.
func (f *phpFlow) noteEnumerationLookup(n *sitter.Node, entity, method string, values []phpValue) {
	if f.symfony == nil || n == nil || f.report == nil || entity == "" {
		return
	}
	access := f.entry.Access
	decls := f.set.classIndex().byName[strings.ToLower(strings.TrimPrefix(entity, `\`))]
	if len(decls) != 1 || decls[0] == nil || !f.accountClass(decls[0]) {
		return
	}
	decl := decls[0]
	fields, deps, ok := f.lookupCriteria(method, values)
	if !ok || len(deps) == 0 {
		return
	}
	f.noteAccountLookup(n, deps)
	if access != nil && access.Authentication == analysis.AccessRequired {
		return
	}
	keys := f.doctrineFieldKeys(decl)
	var census []analysis.SecurityFieldFact
	for _, field := range fields {
		if fact, ok := f.censusFact(keys[field]); ok {
			census = append(census, fact)
		}
	}
	credential := func(field string) bool {
		return slices.Contains(f.censusRoles(keys[field]), analysis.RoleCredential)
	}
	f.noteEnumerationBranch(n, enumerationLookup{class: decl.fqn, method: method, fields: fields, deps: deps, census: census}, credential)
}

// enumerationLookup is one account lookup by request values.
type enumerationLookup struct {
	class, method string
	fields        []string
	deps          []phpDep
	census        []analysis.SecurityFieldFact
}

// noteEnumerationBranch records a candidate when the two sides of the branch
// on a lookup's result answer differently. A lookup whose criteria include a
// credential field is a login, which this claim does not cover.
func (f *phpFlow) noteEnumerationBranch(n *sitter.Node, l enumerationLookup, credential func(field string) bool) {
	if slices.ContainsFunc(l.fields, credential) {
		return
	}
	m := f.module
	branch, foundOnTrue := lookupBranch(m, n)
	if branch == nil {
		return
	}
	trueSide, falseSide := branchSides(m, branch)
	found, notFound := trueSide, falseSide
	if !foundOnTrue {
		found, notFound = falseSide, trueSide
	}
	if sameResponses(found, notFound) {
		return
	}
	f.emitEnumeration(n, branch, l, found, notFound)
}

// accountClass is a class implementing the Symfony UserInterface, or the
// entity class of a security.yaml user provider.
func (f *phpFlow) accountClass(decl *phpClassDecl) bool {
	if f.set.classIndex().interfacesOf(decl)[strings.ToLower(symfonyUserInterface)] {
		return true
	}
	security := f.symfony.security(f.set)
	for _, name := range security.sortedProviders() {
		if strings.EqualFold(strings.TrimPrefix(security.providers[name].class, `\`), decl.fqn) {
			return true
		}
	}
	return false
}

// lookupCriteria returns the criteria fields of a finder and the request
// dependencies of their values. method keeps its source case, so a magic
// finder names its field as declared.
func (f *phpFlow) lookupCriteria(method string, values []phpValue) ([]string, []phpDep, bool) {
	lower := strings.ToLower(method)
	if len(values) == 0 {
		return nil, nil, false
	}
	switch {
	case lower == "find":
		return []string{"id"}, phpInputDeps(values[:1]), true
	case lower == "findoneby" || lower == "findby" || lower == "count":
		criteria := values[0]
		if criteria.fields == nil {
			return nil, nil, false
		}
		var fields []string
		var deps []phpDep
		for _, key := range sortedTwigFields(criteria.fields) {
			fields = append(fields, key)
			deps = append(deps, phpInputDeps([]phpValue{criteria.fields[key]})...)
		}
		return fields, deps, true
	case strings.HasPrefix(lower, "findoneby") || strings.HasPrefix(lower, "findby"):
		name := method[len("findBy"):]
		if strings.HasPrefix(lower, "findoneby") {
			name = method[len("findOneBy"):]
		}
		if name == "" {
			return nil, nil, false
		}
		field := strings.ToLower(name[:1]) + name[1:]
		return []string{field}, phpInputDeps(values[:1]), true
	}
	return nil, nil, false
}

// lookupBranch finds the first if statement after the lookup's assignment,
// in the same statement list, whose condition tests the result variable. It
// reports whether the condition's true side is the found side.
func lookupBranch(m *phpModule, call *sitter.Node) (*sitter.Node, bool) {
	assign := call.Parent()
	for assign != nil && assign.Kind() == "parenthesized_expression" {
		assign = assign.Parent()
	}
	if assign == nil || assign.Kind() != "assignment_expression" {
		return nil, false
	}
	left := phpField(assign, "left")
	if left == nil || left.Kind() != "variable_name" {
		return nil, false
	}
	name := phpText(m, left)
	stmt := assign.Parent()
	if stmt == nil || stmt.Kind() != "expression_statement" {
		return nil, false
	}
	for next := stmt.NextNamedSibling(); next != nil; next = next.NextNamedSibling() {
		if next.Kind() == "if_statement" {
			if polarity, ok := resultTest(m, phpField(next, "condition"), name); ok {
				return next, polarity
			}
		}
		if phpAssigns(m, next, name) {
			return nil, false
		}
	}
	return nil, false
}

// resultTest classifies a condition on the lookup result: truthiness, a null
// test, count or empty. It reports whether true means found.
func resultTest(m *phpModule, c *sitter.Node, name string) (bool, bool) {
	for c != nil && c.Kind() == "parenthesized_expression" && c.NamedChildCount() == 1 {
		c = c.NamedChild(0)
	}
	if c == nil {
		return false, false
	}
	switch c.Kind() {
	case "variable_name":
		return true, phpText(m, c) == name
	case "unary_op_expression":
		if strings.HasPrefix(strings.TrimSpace(phpText(m, c)), "!") && c.NamedChildCount() == 1 {
			found, ok := resultTest(m, c.NamedChild(0), name)
			return !found, ok
		}
	case "function_call_expression":
		fn := strings.ToLower(phpText(m, phpField(c, "function")))
		args := phpArgs(c)
		if len(args) == 1 && phpText(m, args[0]) == name {
			switch fn {
			case "count", "mysqli_num_rows":
				return true, true
			}
		}
	case "empty_expression":
		if c.NamedChildCount() == 1 {
			inner := c.NamedChild(0)
			for inner != nil && inner.Kind() == "parenthesized_expression" && inner.NamedChildCount() == 1 {
				inner = inner.NamedChild(0)
			}
			if inner != nil && phpText(m, inner) == name {
				return false, true
			}
		}
	case "binary_expression":
		op := phpOperator(m, c)
		left, right := phpField(c, "left"), phpField(c, "right")
		null := func(n *sitter.Node) bool { return n != nil && strings.EqualFold(phpText(m, n), "null") }
		is := func(n *sitter.Node) bool { return n != nil && phpText(m, n) == name }
		if is(left) && null(right) || null(left) && is(right) {
			switch op {
			case "===", "==":
				return false, true
			case "!==", "!=":
				return true, true
			}
		}
		if inner, ok := resultTest(m, left, name); ok && right != nil && right.Kind() == "integer" && phpText(m, right) == "0" {
			// count($r) > 0 / count($r) === 0
			switch op {
			case ">", "!==", "!=":
				return inner, true
			case "===", "==", "<=":
				return !inner, true
			}
		}
	}
	return false, false
}

// phpAssigns reports a statement that assigns the variable at its top level.
func phpAssigns(m *phpModule, stmt *sitter.Node, name string) bool {
	if stmt.Kind() != "expression_statement" || stmt.NamedChildCount() != 1 {
		return false
	}
	e := stmt.NamedChild(0)
	return e.Kind() == "assignment_expression" && phpText(m, phpField(e, "left")) == name
}

func (f *phpFlow) emitEnumeration(n, branch *sitter.Node, l enumerationLookup, found, notFound []analysis.BranchResponse) {
	sink := f.module.evidence(analysis.AccountEnumerationKind, n)
	id := fmt.Sprintf("use:%s:%s:%d:%s", f.invocation.ID, sink.Span.File, sink.Span.StartByte, analysis.AccountEnumerationKind)
	for _, u := range f.report.Uses {
		if u.ID == id {
			return
		}
	}
	branchAt := f.module.evidence("result_branch", phpField(branch, "condition"))
	census := l.census
	if census == nil {
		census = []analysis.SecurityFieldFact{}
	}
	if found == nil {
		found = []analysis.BranchResponse{}
	}
	if notFound == nil {
		notFound = []analysis.BranchResponse{}
	}
	facts := &analysis.EnumerationFacts{
		Lookup:         analysis.EnumerationLookup{Class: l.class, Method: l.method, CriteriaFields: l.fields, Evidence: sink, Branch: branchAt},
		Found:          found,
		NotFound:       notFound,
		SecurityFields: census,
	}
	dependencies := []analysis.Dependency{}
	sources := []analysis.Evidence{}
	seen := map[string]bool{}
	for _, d := range l.deps {
		key := depKey(d)
		if seen[key] {
			continue
		}
		seen[key] = true
		dependencies = append(dependencies, d.dep)
		sources = append(sources, d.dep.Source)
	}
	access := []analysis.Evidence{}
	blockers := []analysis.Gap{}
	if f.entry.Access != nil {
		access = append(access, f.entry.Access.Sources...)
		for _, g := range f.entry.Access.Gaps {
			blockers = append(blockers, g)
		}
	}
	if len(access) == 0 {
		access = []analysis.Evidence{f.entry.Location}
	}
	for _, side := range [][]analysis.BranchResponse{found, notFound} {
		for _, r := range side {
			if r.Kind == analysis.ResponseUnresolved {
				blockers = append(blockers, analysis.Gap{Kind: analysis.ResponseUnresolved, Detail: "A response on one side of the lookup branch is not reduced to literals.", At: r.Span})
				break
			}
		}
	}
	u := analysis.CandidateUse{
		ID: id, EntryID: f.entry.ID, InvocationContextID: f.invocation.ID,
		Kind: analysis.AccountEnumerationKind, Sink: sink, Dependencies: dependencies,
		Context: phpDedupeEvidence(f.context), Gaps: append([]analysis.Gap{}, f.gaps...),
		Assessment:  analysis.Assessment{Status: "not_run"},
		Enumeration: facts,
		Completeness: &analysis.Completeness{
			ClaimKind: "account_enumeration",
			Required:  []string{"input_source", "account_lookup", "result_branch", "entry_access"},
			Scope:     "One account lookup by a request value, the branch on its result and the responses on each side.",
			Evidence: map[string][]analysis.Evidence{
				"input_source":   sources,
				"account_lookup": {sink},
				"result_branch":  {branchAt},
				"entry_access":   access,
			},
			Blockers: blockers,
			Coverage: []analysis.Gap{},
		},
	}
	f.report.Uses = append(f.report.Uses, u)
}
