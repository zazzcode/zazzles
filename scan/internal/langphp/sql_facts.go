package langphp

import (
	"regexp"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/parse"
)

// phpFactTransfers keep a value's text as it is. Any other transfer after an
// escape or a conversion withdraws the fact.
var phpFactTransfers = map[string]bool{"assignment": true, "value_reference": true, "string_interpolation": true, "string_construction": true, "literal": true, "constant_binding": true, "field_projection": true, "conditional_value": true}

// phpFactAnchors names the transfer that establishes each operand fact.
var phpFactAnchors = map[string]string{"escaped": "escape_transform", "numeric": "numeric_conversion", "hex": "non_content"}

// phpHexHash is a one-argument md5 or sha1 call, whose result is hexadecimal text.
var phpHexHash = regexp.MustCompile(`^(?:md5|sha1)\s*\([^,]*\)$`)

// phpScopeWriters write variables they do not name.
var phpScopeWriters = map[string]bool{"extract": true, "parse_str": true, "eval": true, "mb_parse_str": true}

// phpSQLFacts states language-neutral facts about the operands of constructed SQL
// text: a numeric conversion, an escape inside a quoted literal, a hexadecimal
// hash. They are stated only when every operand has one, every path of each
// operand proves it and nothing later can change its text. Otherwise the record
// states none: an unknown is not a fact, and a fact decides nothing.
func phpSQLFacts(text phpValue) []string {
	var out []string
	quote := byte(0)
	for _, p := range text.pieces {
		raw, constant := p.text, !p.dynamic
		if p.dynamic && p.node != nil && p.node.Kind() == "escape_sequence" && len(p.val.deps) == 0 {
			raw, constant = p.node.Utf8Text(p.module.src), true
		}
		if constant {
			var ok bool
			if quote, ok = phpQuoteState(raw, quote); !ok {
				return nil
			}
			continue
		}
		fact, at := phpOperandFact(p)
		if fact == "" || fact == "escaped" && quote != '\'' && quote != '"' {
			return nil
		}
		source := " from " + at.Text + " at " + at.Span.File
		switch name := strings.TrimSpace(p.node.Utf8Text(p.module.src)); fact {
		case "numeric":
			out = append(out, "numeric_conversion_result: "+name+source)
		case "hex":
			out = append(out, "hash_hex_result: "+name+source)
		case "escaped":
			out = append(out, "escaped_in_quoted_literal: "+name+source+"; quoted literal")
		}
	}
	if quote != 0 {
		return nil
	}
	return out
}

// phpOperandFact returns the fact every path of one SQL operand proves, with the
// transfer that establishes it.
func phpOperandFact(p phpPiece) (string, analysis.Evidence) {
	fact, at := "", analysis.Evidence{}
	if p.node == nil || p.module == nil || len(p.val.gaps) > 0 {
		return "", at
	}
	for _, d := range p.val.deps {
		k := ""
		switch {
		case d.protection == "numeric" && d.numericAt.Kind == "numeric_conversion":
			k = "numeric"
		case d.protection == "escaped_routine":
			k = "escaped"
		case d.protection == "non_content":
			k = "hex"
		}
		if k == "" || fact != "" && k != fact {
			return "", at
		}
		anchor := -1
		for i, t := range d.dep.Transfers {
			if t.Kind == phpFactAnchors[k] && (k != "hex" || phpHexHash.MatchString(t.Text)) {
				anchor = i
			}
		}
		if anchor < 0 || !phpKeepsText(p, d.dep.Transfers[anchor], d.dep.Transfers[anchor+1:]) {
			return "", at
		}
		fact, at = k, d.dep.Transfers[anchor]
	}
	return fact, at
}

// phpKeepsText reports that the value made at anchor reaches the operand with its
// text unchanged on every path: each transfer keeps it, each alternative of a
// conditional is the value or a literal, and no variable that carries it can be
// written or passed to a call before the operand is read.
func phpKeepsText(p phpPiece, anchor analysis.Evidence, after []analysis.Evidence) bool {
	m := p.module
	root := m.tree.RootNode()
	if anchor.Span.File != m.file {
		return false
	}
	scope, limit := phpOperandScope(p.node)
	start, end := uint(anchor.Span.StartByte), uint(anchor.Span.EndByte)
	if start < scope.StartByte() || end > scope.EndByte() {
		return false
	}
	for _, t := range after {
		if !phpFactTransfers[t.Kind] || t.Span.File != m.file {
			return false
		}
		if t.Kind == "string_interpolation" || t.Kind == "string_construction" {
			break // the parts of the text show what follows
		}
		n := parse.NodeAt(root, t.Span.StartByte, t.Span.EndByte)
		switch t.Kind {
		case "conditional_value":
			if !phpAlternativesKeep(n, start, end) {
				return false
			}
		case "assignment":
			left := phpField(n, "left")
			if n == nil || n.Kind() != "assignment_expression" || left == nil || left.Kind() != "variable_name" {
				return false
			}
			if phpMayChange(m, scope, phpVarName(m, left), n.EndByte(), limit) {
				return false
			}
		}
	}
	return true
}

// phpOperandScope is the function or file body that reads the operand, and the
// last byte whose code can run before that read: the read itself, or the end of
// the outermost loop around it.
func phpOperandScope(n *sitter.Node) (scope *sitter.Node, limit uint) {
	limit = n.StartByte()
	scope = n
	for c := n; c != nil; c = c.Parent() {
		scope = c
		switch c.Kind() {
		case "for_statement", "foreach_statement", "while_statement", "do_statement":
			limit = c.EndByte()
		case "function_definition", "method_declaration", "anonymous_function", "anonymous_function_creation_expression", "arrow_function":
			return scope, limit
		}
	}
	return scope, limit
}

// phpAlternativesKeep reports that every alternative of a conditional is a literal
// or holds the anchor.
func phpAlternativesKeep(n *sitter.Node, start, end uint) bool {
	for n != nil && n.Kind() == "parenthesized_expression" && n.NamedChildCount() == 1 {
		n = n.NamedChild(0)
	}
	if n == nil {
		return false
	}
	switch n.Kind() {
	case "conditional_expression":
		if n.NamedChildCount() != 3 {
			return false
		}
		return phpAlternativesKeep(n.NamedChild(1), start, end) && phpAlternativesKeep(n.NamedChild(2), start, end)
	case "string", "integer", "float", "null", "boolean":
		return true
	case "encapsed_string":
		for i := uint(0); i < n.NamedChildCount(); i++ {
			if k := n.NamedChild(i).Kind(); k != "string_content" && k != "escape_sequence" {
				return false
			}
		}
		return true
	}
	return n.StartByte() == start && n.EndByte() == end
}

// phpMayChange reports code in scope, after from and before limit, that can change
// variable name: a write to it, a call it is passed to, or a construct that writes
// variables it does not name.
func phpMayChange(m *phpModule, scope *sitter.Node, name string, from, limit uint) bool {
	changed := false
	var walk func(*sitter.Node)
	walk = func(n *sitter.Node) {
		if changed || n.EndByte() <= from || n.StartByte() >= limit {
			return
		}
		if n.StartByte() >= from {
			switch n.Kind() {
			case "include_expression", "include_once_expression", "require_expression", "require_once_expression", "dynamic_variable_name", "global_declaration":
				changed = true
				return
			case "function_call_expression":
				if fn := phpField(n, "function"); fn == nil || phpScopeWriters[strings.ToLower(strings.TrimPrefix(phpText(m, fn), `\`))] {
					changed = true
					return
				}
			case "variable_name":
				if phpVarName(m, n) == name && phpWritePosition(n) {
					changed = true
					return
				}
			}
		}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			walk(n.NamedChild(i))
		}
	}
	walk(scope)
	return changed
}

// phpWritePosition reports a variable that is written, taken by reference or
// passed to a call. A plain read keeps it.
func phpWritePosition(n *sitter.Node) bool {
	for c, p := n, n.Parent(); p != nil; c, p = p, p.Parent() {
		switch p.Kind() {
		case "assignment_expression", "augmented_assignment_expression":
			left := phpField(p, "left")
			return left != nil && left.StartByte() == c.StartByte() && left.EndByte() == c.EndByte()
		case "argument", "reference_assignment_expression", "update_expression", "foreach_statement", "unset_statement", "list_literal", "by_ref", "reference_modifier":
			return true
		case "encapsed_string", "expression_statement", "compound_statement", "program", "if_statement", "return_statement", "echo_statement":
			return false
		}
	}
	return false
}

// phpQuoteState follows SQL quoting through constant text. A backslash escapes the
// next character, except that PHP's own \" and \' stand for the quote itself. A SQL
// comment ends what the text shows.
func phpQuoteState(s string, quote byte) (byte, bool) {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\\' && i+1 < len(s) {
			i++
			if s[i] != '"' && s[i] != '\'' {
				continue
			}
			c = s[i]
		}
		if quote == 0 && (c == '#' || strings.HasPrefix(s[i:], "/*") || strings.HasPrefix(s[i:], "--")) {
			return 0, false
		}
		switch {
		case quote == 0 && (c == '\'' || c == '"' || c == '`'):
			quote = c
		case quote == c && quote != 0:
			quote = 0
		}
	}
	return quote, true
}
