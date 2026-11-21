package langphp

import (
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/parse"
)

// Per-path output context (judge evidence quality O). A value echoed inside a
// constructed string lands at one place in the markup: inside a quoted
// attribute, a URL attribute or HTML text. The context is read from the
// literal text before that place in the outermost string template the value
// is embedded in. A value built into markup inside a helper (and returned)
// takes the first non-text context along its path; otherwise the echo's own
// template, after the page's inline markup, decides.

// phpSegment is one piece of a flattened string template: literal text, or a
// value of the given byte range.
type phpSegment struct {
	start, end uint
	literal    string
	value      bool
}

// pathContexts returns each dependency's output context for an echo of n,
// or "" where the path does not reach a template the adapter can read.
func (f *phpFlow) pathContexts(n *sitter.Node, v phpValue, markup string) []string {
	out := make([]string, len(v.deps))
	for i, d := range v.deps {
		seen := map[[2]uint]bool{}
		for _, h := range append([]analysis.Evidence{d.dep.Source}, d.dep.Transfers...) {
			if h.Kind == "string_construction" || h.Kind == "string_interpolation" {
				continue // template nodes themselves, not the value's position
			}
			m := f.set.modules[h.Span.File]
			if m == nil || m.tree == nil {
				continue
			}
			at := m.tree.RootNode().NamedDescendantForByteRange(uint(h.Span.StartByte), uint(h.Span.EndByte))
			echoed := m == f.module && uint(h.Span.StartByte) >= n.StartByte() && uint(h.Span.EndByte) <= n.EndByte()
			root := phpTemplateRoot(m, at)
			if echoed {
				root = n
			}
			if root == nil || root == at {
				continue
			}
			key := [2]uint{root.StartByte(), root.EndByte()}
			if seen[key] {
				continue
			}
			seen[key] = true
			prefix := phpTemplatePrefix(m, root, uint(h.Span.StartByte))
			if echoed {
				prefix = markup + prefix
			}
			c := parse.HTMLOutputContext(prefix)
			if c != "html_text" || echoed {
				out[i] = c
				break
			}
		}
	}
	return out
}

// phpTemplateRoot climbs from a value node to the outermost string template
// containing it within one expression, or nil when it is in none. It does
// not leave a statement, an assignment or a call argument.
func phpTemplateRoot(m *phpModule, n *sitter.Node) *sitter.Node {
	var root *sitter.Node
	for p := n; p != nil && p.Parent() != nil; p = p.Parent() {
		parent := p.Parent()
		switch parent.Kind() {
		case "expression_statement", "return_statement", "echo_statement", "assignment_expression", "augmented_assignment_expression", "arguments", "compound_statement", "program":
			return root
		case "encapsed_string", "heredoc", "heredoc_body":
			root = parent
		case "binary_expression":
			if phpOperator(m, parent) == "." {
				root = parent
			}
		case "parenthesized_expression":
			if root != nil {
				root = parent
			}
		}
	}
	return root
}

// phpTemplatePrefix is the literal text of root before pos, with each value
// before it standing in as plain text.
func phpTemplatePrefix(m *phpModule, root *sitter.Node, pos uint) string {
	var b strings.Builder
	for _, s := range phpTemplateSegments(m, root) {
		if s.end > pos {
			break
		}
		if s.value {
			b.WriteString("x")
			continue
		}
		b.WriteString(s.literal)
	}
	return b.String()
}

func phpTemplateSegments(m *phpModule, n *sitter.Node) []phpSegment {
	value := []phpSegment{{start: n.StartByte(), end: n.EndByte(), value: true}}
	switch n.Kind() {
	case "parenthesized_expression":
		if n.NamedChildCount() == 1 {
			return phpTemplateSegments(m, n.NamedChild(0))
		}
	case "binary_expression":
		if phpOperator(m, n) == "." {
			left, right := phpField(n, "left"), phpField(n, "right")
			if left != nil && right != nil {
				return append(phpTemplateSegments(m, left), phpTemplateSegments(m, right)...)
			}
		}
	case "string":
		if text, ok := phpStringLiteral(m, n); ok {
			return []phpSegment{{start: n.StartByte(), end: n.EndByte(), literal: text}}
		}
	case "encapsed_string", "heredoc", "heredoc_body":
		var out []phpSegment
		for i := uint(0); i < n.ChildCount(); i++ {
			c := n.Child(i)
			if c == nil {
				continue
			}
			switch {
			case c.Kind() == "string_content" || c.Kind() == "string_value":
				out = append(out, phpSegment{start: c.StartByte(), end: c.EndByte(), literal: c.Utf8Text(m.src)})
			case c.Kind() == "escape_sequence":
				out = append(out, phpSegment{start: c.StartByte(), end: c.EndByte(), literal: phpUnescape(c.Utf8Text(m.src))})
			case c.Kind() == "heredoc_body":
				out = append(out, phpTemplateSegments(m, c)...)
			case c.IsNamed() && c.Kind() != "heredoc_start" && c.Kind() != "heredoc_end":
				out = append(out, phpSegment{start: c.StartByte(), end: c.EndByte(), value: true})
			}
		}
		return out
	}
	return value
}

func phpUnescape(s string) string {
	switch s {
	case `\"`:
		return `"`
	case `\'`:
		return `'`
	case `\\`:
		return `\`
	case `\$`:
		return `$`
	case `\n`:
		return "\n"
	case `\t`:
		return "\t"
	}
	return s
}

// recordContext is the context the record states: the one its raw paths
// share, else the echo's own context as before. A record whose raw paths
// land in different contexts keeps the echo-level statement, because the
// XSS policy compares the model's single output_context answer with it; each
// path still states its own context.
func recordContext(paths []analysis.XSSPath, echoContext string) string {
	c := ""
	for _, p := range paths {
		if p.Protection != "raw" || p.OutputContext == "" {
			continue
		}
		if c == "" {
			c = p.OutputContext
		} else if p.OutputContext != c {
			return echoContext
		}
	}
	if c == "" {
		return echoContext
	}
	return c
}
