package langphp

import (
	"fmt"
	"slices"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

// Account enumeration (branch 3 D-2 to D-4). The record is a lookup by a
// request value on an account class, the branch on its result, and the
// responses on each side. The two response lists are compared with each
// other; no rule reads meaning into the text.

// noteEnumerationLookup records a candidate for a finder call whose criteria
// hold a request value, when the two branches on its result answer
// differently.
func (f *phpFlow) noteEnumerationLookup(n *sitter.Node, entity, method string, values []phpValue) {
	if f.symfony == nil || n == nil || f.report == nil || entity == "" {
		return
	}
	access := f.entry.Access
	if access != nil && access.Authentication == analysis.AccessRequired {
		return
	}
	decls := f.set.classIndex().byName[strings.ToLower(strings.TrimPrefix(entity, `\`))]
	if len(decls) != 1 || !f.accountClass(decls[0]) {
		return
	}
	decl := decls[0]
	if decl == nil {
		return
	}
	fields, deps, ok := f.lookupCriteria(n, method, values)
	if !ok || len(deps) == 0 {
		return
	}
	keys := f.doctrineFieldKeys(decl)
	var census []analysis.SecurityFieldFact
	for _, field := range fields {
		key := keys[field]
		if slices.Contains(f.censusRoles(key), analysis.RoleCredential) {
			return // A lookup that includes the credential is a login (out of scope).
		}
		if fact, ok := f.censusFact(key); ok {
			census = append(census, fact)
		}
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
	f.emitEnumeration(n, branch, decl.fqn, method, fields, deps, found, notFound, census)
}

// accountClass is a class implementing the Symfony UserInterface, or the
// entity class of a security.yaml user provider (D-2).
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
// dependencies of their values.
func (f *phpFlow) lookupCriteria(n *sitter.Node, method string, values []phpValue) ([]string, []phpDep, bool) {
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
// test, count or empty (D-2). It reports whether true means found.
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
			case "count":
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

// branchSides collects the responses of the true and false side of a branch.
// A side that does not end the action continues after the if statement.
func branchSides(m *phpModule, branch *sitter.Node) ([]analysis.BranchResponse, []analysis.BranchResponse) {
	body := phpField(branch, "body")
	var alternative *sitter.Node
	for i := uint(0); i < branch.NamedChildCount(); i++ {
		c := branch.NamedChild(i)
		if c.Kind() == "else_clause" {
			alternative = phpField(c, "body")
			if alternative == nil && c.NamedChildCount() > 0 {
				alternative = c.NamedChild(c.NamedChildCount() - 1)
			}
		}
	}
	continuation := func() []analysis.BranchResponse {
		out, _ := continueAfter(m, branch)
		return out
	}
	side := func(n *sitter.Node) []analysis.BranchResponse {
		if n == nil {
			return continuation()
		}
		out, ended := collectResponses(m, statementList(n))
		if !ended {
			out = append(out, continuation()...)
		}
		return out
	}
	return side(body), side(alternative)
}

func statementList(n *sitter.Node) []*sitter.Node {
	if n == nil {
		return nil
	}
	if n.Kind() != "compound_statement" {
		return []*sitter.Node{n}
	}
	var out []*sitter.Node
	for i := uint(0); i < n.NamedChildCount(); i++ {
		if c := n.NamedChild(i); c.Kind() != "comment" {
			out = append(out, c)
		}
	}
	return out
}

// continueAfter collects the responses after a statement until the action
// returns, climbing out of enclosing blocks up to the function body.
func continueAfter(m *phpModule, stmt *sitter.Node) ([]analysis.BranchResponse, bool) {
	var out []analysis.BranchResponse
	for cur := stmt; cur != nil; {
		var rest []*sitter.Node
		for next := cur.NextNamedSibling(); next != nil; next = next.NextNamedSibling() {
			if next.Kind() != "comment" {
				rest = append(rest, next)
			}
		}
		got, ended := collectResponses(m, rest)
		out = append(out, got...)
		if ended {
			return out, true
		}
		parent := cur.Parent()
		for parent != nil && parent.Kind() != "compound_statement" {
			if parent.Kind() == "method_declaration" || parent.Kind() == "function_definition" || parent.Kind() == "program" {
				return out, false
			}
			parent = parent.Parent()
		}
		if parent == nil {
			return out, false
		}
		owner := parent.Parent()
		if owner == nil || owner.Kind() == "method_declaration" || owner.Kind() == "function_definition" || owner.Kind() == "anonymous_function" {
			return out, false
		}
		// Leave the enclosing if/else, loop or try: continue after the
		// statement that owns this block.
		for owner != nil && owner.Kind() == "else_clause" || owner != nil && owner.Kind() == "else_if_clause" {
			owner = owner.Parent()
		}
		cur = owner
	}
	return out, false
}

// collectResponses reads the responses of a straight-line statement list in
// order. Nested conditional statements are not entered: their responses are
// not on every path of this side. It reports whether the list ends the action.
func collectResponses(m *phpModule, list []*sitter.Node) ([]analysis.BranchResponse, bool) {
	var out []analysis.BranchResponse
	for _, s := range list {
		switch s.Kind() {
		case "return_statement":
			if s.NamedChildCount() > 0 {
				out = append(out, returnResponses(m, s.NamedChild(0))...)
			}
			return out, true
		case "echo_statement":
			for i := uint(0); i < s.NamedChildCount(); i++ {
				out = append(out, literalResponse(m, analysis.ResponseBody, s.NamedChild(i)))
			}
		case "expression_statement":
			if s.NamedChildCount() != 1 {
				continue
			}
			e := s.NamedChild(0)
			if e.Kind() == "throw_expression" {
				out = append(out, throwResponse(m, e))
				return out, true
			}
			if r, ok := statementResponse(m, e); ok {
				out = append(out, r...)
			}
			if e.Kind() == "exit_statement" || phpExitCall(m, e) {
				return out, true
			}
		case "exit_statement":
			if s.NamedChildCount() > 0 {
				out = append(out, literalResponse(m, analysis.ResponseBody, s.NamedChild(0)))
			}
			return out, true
		}
	}
	return out, false
}

func phpExitCall(m *phpModule, e *sitter.Node) bool {
	if e.Kind() != "function_call_expression" {
		return false
	}
	fn := strings.ToLower(phpText(m, phpField(e, "function")))
	return fn == "exit" || fn == "die"
}

func spanOf(m *phpModule, n *sitter.Node) analysis.Span {
	return m.evidence("response", n).Span
}

func literalResponse(m *phpModule, kind string, n *sitter.Node) analysis.BranchResponse {
	if text, ok := phpStringLiteral(m, n); ok {
		return analysis.BranchResponse{Kind: kind, Literal: text, Span: spanOf(m, n)}
	}
	if n != nil && (n.Kind() == "integer" || n.Kind() == "boolean") {
		return analysis.BranchResponse{Kind: kind, Literal: phpText(m, n), Span: spanOf(m, n)}
	}
	return analysis.BranchResponse{Kind: analysis.ResponseUnresolved, Span: spanOf(m, n)}
}

// statementResponse reads a response written by an expression statement:
// addFlash, echo-like calls, header Location and http_response_code.
func statementResponse(m *phpModule, e *sitter.Node) ([]analysis.BranchResponse, bool) {
	switch e.Kind() {
	case "member_call_expression":
		name := phpText(m, phpField(e, "name"))
		if strings.EqualFold(name, "addFlash") && phpText(m, phpField(e, "object")) == "$this" {
			args := phpArgs(e)
			if len(args) < 2 {
				return []analysis.BranchResponse{{Kind: analysis.ResponseUnresolved, Span: spanOf(m, e)}}, true
			}
			r := literalResponse(m, analysis.ResponseFlash, args[1])
			return []analysis.BranchResponse{r}, true
		}
	case "function_call_expression":
		fn := strings.ToLower(phpText(m, phpField(e, "function")))
		args := phpArgs(e)
		switch fn {
		case "header":
			if len(args) > 0 {
				if text, ok := phpStringLiteral(m, args[0]); ok && strings.HasPrefix(strings.ToLower(text), "location:") {
					return []analysis.BranchResponse{{Kind: analysis.ResponseRedirect, Literal: strings.TrimSpace(text[len("location:"):]), Span: spanOf(m, e)}}, true
				}
			}
		case "http_response_code":
			if len(args) > 0 {
				return []analysis.BranchResponse{literalResponse(m, analysis.ResponseStatus, args[0])}, true
			}
		case "die", "exit":
			if len(args) > 0 {
				return []analysis.BranchResponse{literalResponse(m, analysis.ResponseBody, args[0])}, true
			}
			return nil, true
		}
	}
	return nil, false
}

// returnResponses reads the response an action returns.
func returnResponses(m *phpModule, e *sitter.Node) []analysis.BranchResponse {
	for e != nil && e.Kind() == "parenthesized_expression" && e.NamedChildCount() == 1 {
		e = e.NamedChild(0)
	}
	if e == nil {
		return nil
	}
	switch e.Kind() {
	case "member_call_expression":
		if phpText(m, phpField(e, "object")) != "$this" {
			break
		}
		args := phpArgs(e)
		first := func(kind string) []analysis.BranchResponse {
			if len(args) == 0 {
				return []analysis.BranchResponse{{Kind: analysis.ResponseUnresolved, Span: spanOf(m, e)}}
			}
			return []analysis.BranchResponse{literalResponse(m, kind, args[0])}
		}
		switch strings.ToLower(phpText(m, phpField(e, "name"))) {
		case "redirecttoroute", "redirect":
			return first(analysis.ResponseRedirect)
		case "render":
			return first(analysis.ResponseTemplate)
		case "json":
			return bodyAndStatus(m, e, args)
		}
	case "object_creation_expression":
		class := strings.ToLower(phpText(m, phpObjectClassNode(e)))
		short := class[strings.LastIndex(class, `\`)+1:]
		switch short {
		case "response", "jsonresponse":
			return bodyAndStatus(m, e, phpNewArguments(e))
		case "redirectresponse":
			args := phpNewArguments(e)
			if len(args) > 0 {
				return []analysis.BranchResponse{literalResponse(m, analysis.ResponseRedirect, args[0])}
			}
		}
	}
	return []analysis.BranchResponse{{Kind: analysis.ResponseUnresolved, Span: spanOf(m, e)}}
}

// bodyAndStatus reads a literal body (a string or an array of literal
// scalars) and a literal status.
func bodyAndStatus(m *phpModule, at *sitter.Node, args []*sitter.Node) []analysis.BranchResponse {
	var out []analysis.BranchResponse
	if len(args) > 0 {
		if text, ok := literalBody(m, args[0]); ok {
			out = append(out, analysis.BranchResponse{Kind: analysis.ResponseBody, Literal: text, Span: spanOf(m, args[0])})
		} else {
			out = append(out, analysis.BranchResponse{Kind: analysis.ResponseUnresolved, Span: spanOf(m, args[0])})
		}
	}
	if len(args) > 1 {
		out = append(out, literalResponse(m, analysis.ResponseStatus, args[1]))
	}
	if len(out) == 0 {
		out = append(out, analysis.BranchResponse{Kind: analysis.ResponseBody, Span: spanOf(m, at)})
	}
	return out
}

func literalBody(m *phpModule, n *sitter.Node) (string, bool) {
	if text, ok := phpStringLiteral(m, n); ok {
		return text, true
	}
	if n == nil || n.Kind() != "array_creation_expression" {
		return "", false
	}
	literal := true
	phpWalk(n, func(c *sitter.Node) {
		switch c.Kind() {
		case "variable_name", "function_call_expression", "member_call_expression", "scoped_call_expression", "member_access_expression", "encapsed_string", "subscript_expression":
			if c.Kind() != "encapsed_string" {
				literal = false
			} else if _, ok := phpStringLiteral(m, c); !ok {
				literal = false
			}
		}
	})
	if !literal {
		return "", false
	}
	return strings.Join(strings.Fields(phpText(m, n)), " "), true
}

func throwResponse(m *phpModule, e *sitter.Node) analysis.BranchResponse {
	if e.NamedChildCount() > 0 {
		inner := e.NamedChild(0)
		if inner.Kind() == "object_creation_expression" {
			class := phpText(m, phpObjectClassNode(inner))
			return analysis.BranchResponse{Kind: analysis.ResponseException, Literal: class[strings.LastIndex(class, `\`)+1:], Span: spanOf(m, e)}
		}
		if inner.Kind() == "member_call_expression" && phpText(m, phpField(inner, "object")) == "$this" {
			return analysis.BranchResponse{Kind: analysis.ResponseException, Literal: phpText(m, phpField(inner, "name")), Span: spanOf(m, e)}
		}
	}
	return analysis.BranchResponse{Kind: analysis.ResponseUnresolved, Span: spanOf(m, e)}
}

func phpObjectClassNode(n *sitter.Node) *sitter.Node {
	for i := uint(0); i < n.NamedChildCount(); i++ {
		c := n.NamedChild(i)
		switch c.Kind() {
		case "name", "qualified_name":
			return c
		}
	}
	return nil
}

// sameResponses compares two response lists position by position (D-3). An
// unresolved response is never equal to anything.
func sameResponses(a, b []analysis.BranchResponse) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Kind == analysis.ResponseUnresolved || a[i].Kind != b[i].Kind || a[i].Literal != b[i].Literal {
			return false
		}
	}
	return true
}

func (f *phpFlow) emitEnumeration(n, branch *sitter.Node, class, method string, fields []string, deps []phpDep, found, notFound []analysis.BranchResponse, census []analysis.SecurityFieldFact) {
	sink := f.module.evidence(analysis.AccountEnumerationKind, n)
	id := fmt.Sprintf("use:%s:%s:%d:%s", f.invocation.ID, sink.Span.File, sink.Span.StartByte, analysis.AccountEnumerationKind)
	for _, u := range f.report.Uses {
		if u.ID == id {
			return
		}
	}
	branchAt := f.module.evidence("result_branch", phpField(branch, "condition"))
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
		Lookup:         analysis.EnumerationLookup{Class: class, Method: method, CriteriaFields: fields, Evidence: sink, Branch: branchAt},
		Found:          found,
		NotFound:       notFound,
		SecurityFields: census,
	}
	dependencies := []analysis.Dependency{}
	sources := []analysis.Evidence{}
	seen := map[string]bool{}
	for _, d := range deps {
		key := fmt.Sprintf("%s:%d", d.dep.Source.Span.File, d.dep.Source.Span.StartByte)
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
