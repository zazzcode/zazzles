package langjs

import (
	"regexp"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/parse"
)

var catchAllJoinText = regexp.MustCompile(`^[A-Za-z_$][\w$.]*\.join\(\s*(?:"[^"]*"|'[^']*'|` + "`[^`$]*`" + `)\s*\)$`)

// catchAllJoinTransforms returns the verified `catchAll.join("<literal>")`
// steps of the request flows. A Next.js catch-all route parameter is a string
// array, so `.join` is Array.prototype.join (not the node path module): it keeps
// every element's text, including `..`, and only adds the literal separator.
// It is a modeled transfer of the request value, not an unmodeled call, so a
// control on the joined string applies to the same value. The receiver must be
// the request value itself (the flow origin recorded for the route segment is
// an array), the call must be the first transformation, and the binding must
// not be reassigned.
func (s *moduleSet) catchAllJoinTransforms(m *sourceModule, u *analysis.CandidateUse) []analysis.Evidence {
	var out []analysis.Evidence
	for _, d := range u.Dependencies {
		if d.SinkSlot != analysis.PathSlotFile {
			continue
		}
		o, ok := s.webOriginFor(d.Source)
		if !ok || o.origin != "http.path" || o.initialType != "array" || d.Source.Span.File != m.file {
			continue
		}
		for _, t := range d.Transfers {
			if t.Kind == "field_projection" || t.Kind == "property_read" || t.Kind == "expression" {
				continue
			}
			if t.Kind != "call_argument_dependency" || t.Span.File != m.file || !catchAllJoinText.MatchString(t.Text) {
				break
			}
			call := parse.NodeAt(m.tree.RootNode(), t.Span.StartByte, t.Span.EndByte)
			if call == nil || call.Kind() != "call_expression" {
				break
			}
			fn, args := call.ChildByFieldName("function"), call.ChildByFieldName("arguments")
			if fn == nil || args == nil || fn.Kind() != "member_expression" || args.NamedChildCount() != 1 {
				break
			}
			recv := fn.ChildByFieldName("object")
			if recv == nil || recv.Utf8Text(m.src) != d.Source.Text || catchAllReceiverReassigned(m, recv) {
				break
			}
			out = append(out, m.evidence("transformation", call))
			break
		}
	}
	return out
}

// catchAllReceiverReassigned reports whether the receiver is anything other
// than a binding that is read exactly once in its function (by this call) and
// never reassigned. A second read could be a differently transformed alias of
// the same request value, which a control on the joined string would not cover.
func catchAllReceiverReassigned(m *sourceModule, recv *sitter.Node) bool {
	root := recv
	for root.Kind() == "member_expression" {
		root = root.ChildByFieldName("object")
		if root == nil {
			return true
		}
	}
	if root.Kind() != "identifier" || bindingReassigned(m, root.Utf8Text(m.src)) {
		return true
	}
	fn := enclosingFunction(recv)
	if fn == nil {
		return true
	}
	name, reads := root.Utf8Text(m.src), 0
	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		if n.Kind() == "identifier" && n.Utf8Text(m.src) == name {
			reads++
		}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			visit(n.NamedChild(i))
		}
	}
	visit(fn)
	return reads != 1
}
