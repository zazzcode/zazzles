package langjs

import (
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
)

// pollutionPartsSource names the operand whose content becomes the walked
// parts: a parameter that is the array of parts, a parameter split by a string
// or regular-expression literal, or the split key of an enclosing key loop.
func pollutionPartsSource(m *sourceModule, at *sitter.Node, parts string, params []boundParam, keys *pollutionLoop) (int, string) {
	if i := pollutionParameter(params, parts); i >= 0 {
		if !pollutionPathParameter(m, at, parts) {
			return -1, ""
		}
		return i, "path"
	}
	split := unwrapTS(localInitializer(m, at, parts))
	if split == nil || split.EndByte() > at.StartByte() || bindingReassigned(m, parts) {
		return -1, ""
	}
	path := pollutionSplit(m, split)
	if path == "" && split.Kind() == "array" && split.NamedChildCount() == 0 {
		path = pollutionExecParts(m, at, parts)
	}
	if path == "" {
		return -1, ""
	}
	if keys != nil && path == keys.key {
		return pollutionParameter(params, keys.source), "source_keys"
	}
	return pollutionParameter(params, path), "path"
}

// pollutionSplit returns the identifier split by a non-empty string literal or
// a regular-expression literal, or matched as a whole by a global
// regular-expression literal. Each result is an array of substrings of it.
func pollutionSplit(m *sourceModule, split *sitter.Node) string {
	if split == nil || split.Kind() != "call_expression" {
		return ""
	}
	fn, args := split.ChildByFieldName("function"), split.ChildByFieldName("arguments")
	if fn == nil || fn.Kind() != "member_expression" || args == nil || args.NamedChildCount() != 1 {
		return ""
	}
	prop, separator := fn.ChildByFieldName("property"), args.NamedChild(0)
	if prop == nil {
		return ""
	}
	switch prop.Utf8Text(m.src) {
	case "split":
		if sep, literal := stringLiteral(separator, m.src); !(literal && sep != "" || separator.Kind() == "regex") {
			return ""
		}
	case "match":
		flags := separator.ChildByFieldName("flags")
		if separator.Kind() != "regex" || flags == nil || !strings.Contains(flags.Utf8Text(m.src), "g") {
			return ""
		}
	default:
		return ""
	}
	return pollutionIdentifier(fn.ChildByFieldName("object"), m.src)
}

// pollutionPathParameter accepts a parameter walked as the array of parts. The
// only write it may receive in its function is its own split, which keeps the
// caller's content.
func pollutionPathParameter(m *sourceModule, at *sitter.Node, name string) bool {
	fn := at
	for fn != nil && !isFunction(fn) && fn.Kind() != "function_declaration" && fn.Kind() != "method_definition" {
		fn = fn.Parent()
	}
	if fn == nil || fn.ChildByFieldName("body") == nil {
		return false
	}
	stable := true
	pollutionWalk(fn.ChildByFieldName("body"), func(n *sitter.Node) {
		switch n.Kind() {
		case "assignment_expression":
			if pollutionIdentifier(n.ChildByFieldName("left"), m.src) == name {
				stable = stable && pollutionSplit(m, unwrapTS(n.ChildByFieldName("right"))) == name
			}
		case "augmented_assignment_expression":
			stable = stable && pollutionIdentifier(n.ChildByFieldName("left"), m.src) != name
		case "variable_declarator":
			stable = stable && pollutionIdentifier(n.ChildByFieldName("name"), m.src) != name
		}
	})
	return stable
}

// pollutionConsumedParts names the array a while loop empties one part at a
// time: the step takes parts.shift() or parts.pop() and the loop runs while
// parts remain.
func pollutionConsumedParts(m *sourceModule, loop, take *sitter.Node) string {
	take = unwrapTS(take)
	if take == nil || take.Kind() != "call_expression" {
		return ""
	}
	fn, args := take.ChildByFieldName("function"), take.ChildByFieldName("arguments")
	if fn == nil || fn.Kind() != "member_expression" || args == nil || args.NamedChildCount() != 0 {
		return ""
	}
	parts, method := pollutionIdentifier(fn.ChildByFieldName("object"), m.src), fn.ChildByFieldName("property")
	if parts == "" || method == nil || !containsString([]string{"shift", "pop"}, method.Utf8Text(m.src)) {
		return ""
	}
	test := compactPollutionText(pollutionUnwrap(loop.ChildByFieldName("condition")), m.src)
	if !containsString([]string{parts + ".length>1", parts + ".length>0", parts + ".length"}, test) {
		return ""
	}
	return parts
}

// pollutionExecParts names the string whose regular-expression matches are
// pushed onto parts by one earlier exec loop:
// `while ((m = pattern.exec(path)) !== null) parts.push(m[1])`.
func pollutionExecParts(m *sourceModule, at *sitter.Node, parts string) string {
	fn := at
	for fn != nil && !isFunction(fn) && fn.Kind() != "function_declaration" && fn.Kind() != "method_definition" {
		fn = fn.Parent()
	}
	if fn == nil {
		return ""
	}
	path := ""
	pollutionWalk(fn.ChildByFieldName("body"), func(loop *sitter.Node) {
		if path != "" || loop.Kind() != "while_statement" || loop.EndByte() > at.StartByte() {
			return
		}
		match, source := "", ""
		pollutionWalk(loop.ChildByFieldName("condition"), func(n *sitter.Node) {
			if n.Kind() != "assignment_expression" {
				return
			}
			exec := unwrapTS(n.ChildByFieldName("right"))
			if exec == nil || exec.Kind() != "call_expression" {
				return
			}
			call, args := exec.ChildByFieldName("function"), exec.ChildByFieldName("arguments")
			if call == nil || call.Kind() != "member_expression" || args == nil || args.NamedChildCount() != 1 {
				return
			}
			pattern, method := unwrapTS(call.ChildByFieldName("object")), call.ChildByFieldName("property")
			if pattern != nil && pattern.Kind() == "identifier" {
				pattern = unwrapTS(localInitializer(m, loop, pattern.Utf8Text(m.src)))
			}
			if pattern == nil || pattern.Kind() != "regex" || method == nil || method.Utf8Text(m.src) != "exec" {
				return
			}
			match, source = pollutionIdentifier(n.ChildByFieldName("left"), m.src), pollutionIdentifier(args.NamedChild(0), m.src)
		})
		if match == "" || source == "" {
			return
		}
		pollutionWalk(loop.ChildByFieldName("body"), func(n *sitter.Node) {
			if n.Kind() != "call_expression" || compactPollutionText(n.ChildByFieldName("function"), m.src) != parts+".push" {
				return
			}
			args := n.ChildByFieldName("arguments")
			if args == nil || args.NamedChildCount() != 1 {
				return
			}
			if group := unwrapTS(args.NamedChild(0)); group.Kind() == "subscript_expression" && pollutionIdentifier(group.ChildByFieldName("object"), m.src) == match {
				path = source
			}
		})
	})
	return path
}
