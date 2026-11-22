package langphp

import (
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/parse"
)

// The branch-response reader: the literal responses each side of an if
// statement gives before the action ends. Both account-enumeration paths
// compare the two lists it returns.

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

// spanOf is the span of a response node; no evidence text is built.
func spanOf(m *phpModule, n *sitter.Node) analysis.Span {
	if n == nil {
		return analysis.Span{File: m.file}
	}
	return parse.Span(m.file, n)
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

// sameResponses compares two response lists position by position. An
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
