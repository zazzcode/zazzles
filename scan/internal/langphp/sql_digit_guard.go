package langphp

import (
	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
)

// phpDigitPatterns are anchored PCRE patterns that accept decimal digits only. Without
// the D modifier, $ also matches before one final line feed.
var phpDigitPatterns = map[string]bool{`^\d+$`: true, `^[0-9]+$`: true}

// digitGuard returns the preg_match that a request element read in statement has
// passed, or nil. The statement is the first of a block that runs only when the
// native preg_match of one digit pattern accepted the same element: the body of
// `if (preg_match(...))`, or the else of `if (!preg_match(...))`, with no other branch.
func (f *phpFlow) digitGuard(statement, value *sitter.Node) *sitter.Node {
	m := f.module
	block := statement.Parent()
	for s := statement.PrevNamedSibling(); s != nil; s = s.PrevNamedSibling() {
		if s.Kind() != "comment" {
			return nil
		}
	}
	// A block whose parent is the if statement is its body; an else is a clause.
	owner, negated, branches := block.Parent(), false, uint(2)
	if owner.Kind() == "else_clause" {
		owner, negated, branches = owner.Parent(), true, 3
	}
	if owner.Kind() != "if_statement" || owner.NamedChildCount() != branches {
		return nil
	}
	check := phpUnparenthesized(phpField(owner, "condition"))
	if negated {
		if phpOperator(m, check) != "!" {
			return nil
		}
		check = phpUnparenthesized(phpField(check, "argument"))
	}
	if check.Kind() != "function_call_expression" {
		return nil
	}
	args := phpPlainArguments(check)
	if len(args) != 2 || !f.nativeCall(check, "preg_match") {
		return nil
	}
	pattern, flags, _ := analysispacks.PHPRegexLiteral(phpText(m, args[0]))
	subject, key := phpLiteralElement(m, args[1])
	read, readKey := phpLiteralElement(m, value)
	if flags != "" && flags != "D" || !phpDigitPatterns[pattern] || subject != read || key != readKey {
		return nil
	}
	return check
}
