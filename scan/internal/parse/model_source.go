package parse

import (
	sitter "github.com/tree-sitter/go-tree-sitter"
	"strings"
)

// SourceComment is the byte range of one comment excluded from model source.
type SourceComment struct{ start, end uint }

// SourceComments lists the comments (and, for Python, standalone docstrings)
// under root. They are presentation data, not operation witnesses: callers keep
// their byte positions while excluding their prose from model input.
func SourceComments(root *sitter.Node, src []byte, python bool) []SourceComment {
	var out []SourceComment
	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		if n.Kind() == "comment" {
			out = append(out, SourceComment{n.StartByte(), n.EndByte()})
			return
		}
		if python && n.Kind() == "expression_statement" && n.NamedChildCount() == 1 && n.NamedChild(0).Kind() == "string" {
			parent := n.Parent()
			owner := parent.Parent()
			doc := parent.Kind() == "module" || parent.Kind() == "block" && owner != nil && (owner.Kind() == "function_definition" || owner.Kind() == "class_definition")
			literal := strings.ToLower(n.NamedChild(0).Utf8Text(src))
			quote := strings.IndexAny(literal, "\"'")
			if quote < 0 || strings.ContainsAny(literal[:quote], "fb") {
				doc = false
			}
			if doc {
				for i := uint(0); i < parent.NamedChildCount(); i++ {
					c := parent.NamedChild(i)
					if c.Kind() == "comment" {
						continue
					}
					if c.Id() == n.Id() {
						out = append(out, SourceComment{n.StartByte(), n.EndByte()})
						return
					}
					break
				}
			}
		}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			visit(n.NamedChild(i))
		}
	}
	visit(root)
	return out
}

// ModelSource returns src[start:end] with comment prose blanked, for model input.
func ModelSource(src []byte, start, end uint, comments []SourceComment) string {
	var masked []byte
	for _, c := range comments {
		a, b := c.start, c.end
		if a < start {
			a = start
		}
		if b > end {
			b = end
		}
		if a >= b {
			continue
		}
		if masked == nil {
			masked = append([]byte{}, src[start:end]...)
		}
		for i := a - start; i < b-start; i++ {
			if masked[i] != '\n' && masked[i] != '\r' && masked[i] != '\t' {
				masked[i] = ' '
			}
		}
	}
	if masked == nil {
		return ""
	}
	return string(masked)
}
