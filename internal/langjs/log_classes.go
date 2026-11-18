package langjs

import (
	"regexp"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/parse"
)

var keyToken = regexp.MustCompile(`[A-Za-z0-9_$-]+`)

// classifyLogDeps turns the classified request dependencies of a logger call into
// claim gaps. Each dependency is judged on its own transfers.
func (f *flow) classifyLogDeps(deps []analysis.Dependency, at *sitter.Node) []analysis.Gap {
	seen := map[string]bool{}
	var out []analysis.Gap
	add := func(kind, detail string) {
		if seen[kind+"\x00"+detail] {
			return
		}
		seen[kind+"\x00"+detail] = true
		out = append(out, f.gap(kind, detail, at))
	}
	for _, d := range deps {
		if d.Source.Kind != "input_source" {
			continue
		}
		container, key := requestKey(d)
		class, hint := parse.LogDataClass(container, key)
		if class == "" {
			continue
		}
		label := "request " + container
		if key != "" {
			label += " field " + key
		}
		state, call := "content", ""
		if f.set != nil {
			state, call = f.set.logContent(d)
		}
		switch {
		case state == "non_content":
			add("log_non_content_only", "only a derived non-content fact of "+label+" is logged")
		case state == "unresolved":
			add("log_transform_unresolved", label+" passes through a call whose effect on content is not modeled before logging: "+call)
		case class == "protocol_credential":
			add("log_protocol_credential", label+" carries a credential under HTTP semantics and its content is written to the log")
		case class == "container":
			add("log_request_container", "the whole "+label+" is written to the log and may include credentials or personal data")
		default:
			add("log_sensitive_field_hint", label+" has a "+hint+" field-name hint and its content is written to the log")
		}
	}
	return out
}

// requestKey returns the request container and field key of a dependency. A
// destructured binding supplies the key through its field_projection transfer.
func requestKey(d analysis.Dependency) (string, string) {
	tokens := keyToken.FindAllString(d.Source.Text, -1)
	container, key := "", ""
	for i, t := range tokens {
		if i > 1 {
			break
		}
		// req.body.x has the container second; a destructured query.x has it first.
		if requestContainers[t] {
			container = t
			if i+1 < len(tokens) {
				key = tokens[i+1]
			}
			break
		}
	}
	if key == "" {
		for _, t := range d.Transfers {
			if t.Kind == "field_projection" {
				key = t.Text
				break
			}
		}
	}
	return container, key
}

// logContent reports whether a dependency reaches the logger as content, as a
// derived non-content fact, or through an unmodeled transformation. Once a value
// is reduced to a non-content fact, later transfers cannot restore its content.
func (s *moduleSet) logContent(d analysis.Dependency) (string, string) {
	unresolved := ""
	for _, t := range d.Transfers {
		m := s.modules[t.Span.File]
		if m == nil {
			continue
		}
		n := m.tree.RootNode().NamedDescendantForByteRange(uint(t.Span.StartByte), uint(t.Span.EndByte))
		if n == nil {
			continue
		}
		if nonContentNode(n, m.src) {
			return "non_content", ""
		}
		if t.Kind == "call_argument_dependency" && unresolved == "" && !contentPreservingCall(n, m.src) {
			unresolved = t.Text
		}
	}
	if unresolved != "" {
		return "unresolved", unresolved
	}
	return "content", ""
}

func nonContentNode(n *sitter.Node, src []byte) bool {
	switch n.Kind() {
	case "member_expression":
		p := n.ChildByFieldName("property")
		return p != nil && p.Utf8Text(src) == "length"
	case "binary_expression":
		op := n.ChildByFieldName("operator")
		if op == nil {
			return false
		}
		switch op.Utf8Text(src) {
		case "===", "!==", "==", "!=", "<", ">", "<=", ">=", "instanceof", "in":
			return true
		}
	case "unary_expression":
		op := n.ChildByFieldName("operator")
		return op != nil && (op.Utf8Text(src) == "!" || op.Utf8Text(src) == "typeof")
	case "call_expression":
		fn := n.ChildByFieldName("function")
		return fn != nil && fn.Kind() == "identifier" && fn.Utf8Text(src) == "Boolean" && !shadowed(n, "Boolean", src)
	}
	return false
}

// contentPreservingCall recognizes standard conversions that keep all or part of
// the value's text. Anything else, including replace(), may redact and stays unresolved.
func contentPreservingCall(n *sitter.Node, src []byte) bool {
	if n.Kind() != "call_expression" {
		return false
	}
	fn := n.ChildByFieldName("function")
	if fn == nil {
		return false
	}
	switch fn.Kind() {
	case "identifier":
		return fn.Utf8Text(src) == "String" && !shadowed(n, "String", src)
	case "member_expression":
		if fn.Utf8Text(src) == "JSON.stringify" && !shadowed(n, "JSON", src) {
			return true
		}
		p := fn.ChildByFieldName("property")
		if p == nil {
			return false
		}
		switch p.Utf8Text(src) {
		case "toString", "trim", "trimStart", "trimEnd", "toLowerCase", "toUpperCase", "slice", "substring", "substr", "concat", "join", "normalize", "padStart", "padEnd":
			return true
		}
	}
	return false
}
