package langphp

import (
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/parse"
)

func (f *phpFlow) phpDeserializationGuards(u *analysis.CandidateUse, call *sitter.Node, names [][]string) ([]analysis.Evidence, []int) {
	var guards []analysis.Evidence
	var indices []int
	add := func(e analysis.Evidence, index int, test *sitter.Node) {
		// A presence, emptiness, type or request-method test selects a path
		// without constraining the bytes, so it is not a guard.
		if test != nil && phpPresenceOnly(f.set.modules[e.Span.File], test) {
			return
		}
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
			var test *sitter.Node
			if m := f.set.modules[e.Span.File]; m != nil {
				test = parse.NodeAt(m.tree.RootNode(), e.Span.StartByte, e.Span.EndByte)
			}
			add(e, i, test)
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
				if !f.phpGuardedNameReassigned(u, stmt, test) {
					add(f.module.evidence("branch_false_precondition", test), -1, test)
				}
			}
		}
	}
	return guards, indices
}

// phpGuardedNameReassigned reports a condition that tested an earlier version
// of the operand: a variable the condition names is assigned again after the
// conditional. A later assignment to another variable, such as decoding the
// verified value, keeps the guard.
func (f *phpFlow) phpGuardedNameReassigned(u *analysis.CandidateUse, stmt, test *sitter.Node) bool {
	m := f.module
	condition := phpText(m, test)
	for _, d := range u.Dependencies {
		for _, tr := range d.Transfers {
			if tr.Kind != "assignment" || tr.Span.File != m.file || tr.Span.StartByte <= int(stmt.EndByte()) {
				continue
			}
			assign := parse.NodeAt(m.tree.RootNode(), tr.Span.StartByte, tr.Span.EndByte)
			target := phpField(assign, "left")
			if target == nil || target.Kind() != "variable_name" || parse.MentionsAny(condition, []string{phpText(m, target)}) {
				return true
			}
		}
	}
	return false
}

// phpRejectingDeserializationBranch reports a branch whose last statement
// leaves unconditionally, so code after the conditional runs only when the
// condition is false.
func (f *phpFlow) phpRejectingDeserializationBranch(body *sitter.Node) bool {
	if body.Kind() == "compound_statement" || body.Kind() == "colon_block" {
		var last *sitter.Node
		for i := uint(0); i < body.NamedChildCount(); i++ {
			if c := body.NamedChild(i); c.Kind() != "comment" {
				last = c
			}
		}
		if last == nil {
			return false
		}
		body = last
	}
	switch body.Kind() {
	case "exit_statement", "return_statement", "throw_statement":
		return true
	case "expression_statement":
		return f.terminatingCall(body) || body.NamedChildCount() == 1 && body.NamedChild(0).Kind() == "throw_expression"
	}
	return false
}

// phpPresenceOnly reports a condition that only tests whether values exist,
// are non-empty or have a runtime type, or that compares the request method.
func phpPresenceOnly(m *phpModule, n *sitter.Node) bool {
	if m == nil || n == nil {
		return false
	}
	switch n.Kind() {
	case "parenthesized_expression":
		return n.NamedChildCount() == 1 && phpPresenceOnly(m, n.NamedChild(0))
	case "variable_name", "subscript_expression":
		return true
	case "unary_op_expression":
		return strings.HasPrefix(phpText(m, n), "!") && phpPresenceOnly(m, phpField(n, "argument"))
	case "function_call_expression":
		switch strings.ToLower(strings.TrimPrefix(phpText(m, phpCallee(n)), `\`)) {
		case "isset", "empty", "is_null", "is_string", "is_array", "is_scalar", "array_key_exists", "key_exists":
			return true
		}
	case "binary_expression":
		left, right := phpField(n, "left"), phpField(n, "right")
		if left == nil || right == nil {
			return false
		}
		switch strings.ToLower(phpText(m, phpField(n, "operator"))) {
		case "&&", "||", "and", "or":
			return phpPresenceOnly(m, left) && phpPresenceOnly(m, right)
		case "==", "===", "!=", "!==", "<>":
			return phpPresenceComparison(m, left, right) || phpPresenceComparison(m, right, left)
		}
	}
	return false
}

// phpPresenceComparison matches a value compared with null, a boolean or the
// empty string, and the request method compared with a string.
func phpPresenceComparison(m *phpModule, value, literal *sitter.Node) bool {
	if value.Kind() != "variable_name" && value.Kind() != "subscript_expression" {
		return false
	}
	switch strings.ToLower(phpText(m, literal)) {
	case "null", "true", "false", "''", `""`:
		return true
	}
	if literal.Kind() != "string" && literal.Kind() != "encapsed_string" {
		return false
	}
	text := strings.NewReplacer(" ", "", `"`, "'").Replace(phpText(m, value))
	return text == "$_SERVER['REQUEST_METHOD']"
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
