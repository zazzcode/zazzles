package langjs

import (
	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/parse"
)

// Definitions a database package operation's source refers to.
//
// The handler and the helpers the flow entered are sent to the decision model.
// A name they use that is defined elsewhere in the repository (a constant map, a
// list of fields, a function passed as a callback, a helper the flow did not
// enter) was not, and the model then judged code it could not see. In a
// measured run 19 of 128 requests lacked such a definition. Each is added as
// evidence of kind referenced_definition: the whole module-level statement,
// found by the same definition search that finds the receiver.

const (
	maxReferencedDefinitions = 10
	maxReferencedBytes       = 3000
)

// referencedDefinitions lists the module-level statements that define names the
// record's source excerpts use, and that no excerpt or receiver path step shows.
func (s *moduleSet) referencedDefinitions(use analysis.CandidateUse) []analysis.Evidence {
	type excerpt struct {
		m *sourceModule
		n *sitter.Node
	}
	var queue []excerpt
	var shown []analysis.Span
	for _, e := range use.Context {
		switch e.Kind {
		case "handler", "helper_definition", "validation_schema", "validation_control", "condition_helper":
			shown = append(shown, e.Span)
			if m := s.modules[e.Span.File]; m != nil {
				if n := parse.NodeAt(m.tree.RootNode(), e.Span.StartByte, e.Span.EndByte); n != nil {
					queue = append(queue, excerpt{m, n})
				}
			}
		}
	}
	var path []analysis.Span
	if use.Completeness != nil {
		for _, e := range use.Completeness.Evidence["sink_binding"] {
			path = append(path, e.Span)
		}
	}
	inside := func(spans []analysis.Span, file string, start, end uint) bool {
		for _, sp := range spans {
			if sp.File == file && uint(sp.StartByte) <= start && uint(sp.EndByte) >= end {
				return true
			}
		}
		return false
	}
	var out []analysis.Evidence
	seen := map[string]bool{}
	for depth := 0; depth < 2 && len(queue) > 0; depth++ {
		var next []excerpt
		for _, q := range queue {
			// An excerpt that is a step of the receiver path defines the handle, not
			// what happens to a request value: its names are not followed.
			step := false
			for _, sp := range path {
				step = step || (sp.File == q.m.file && uint(sp.StartByte) <= q.n.StartByte() && uint(sp.EndByte) >= q.n.EndByte())
			}
			if step {
				continue
			}
			var walk func(*sitter.Node)
			walk = func(n *sitter.Node) {
				if len(out) >= maxReferencedDefinitions {
					return
				}
				if n.Kind() == "identifier" || n.Kind() == "shorthand_property_identifier" {
					// A member of a name (mongo.collection) is followed as that member,
					// not as everything the name holds.
					ref := n
					for p := ref.Parent(); p != nil && p.Kind() == "member_expression" && p.ChildByFieldName("object") != nil && p.ChildByFieldName("object").Id() == ref.Id(); p = ref.Parent() {
						ref = p
					}
					key := q.m.file + ":" + ref.Utf8Text(q.m.src)
					if !seen[key] {
						seen[key] = true
						for _, r := range s.resolveRefs(q.m, ref, nil, 0) {
							stmt := topStatement(r.n)
							if stmt == nil || stmt.Kind() == "import_statement" || stmt.EndByte()-stmt.StartByte() > maxReferencedBytes {
								continue
							}
							// Already visible: the definition itself, or its statement, is in an excerpt.
							if inside(shown, r.m.file, r.n.StartByte(), r.n.EndByte()) || inside(shown, r.m.file, stmt.StartByte(), stmt.EndByte()) {
								continue
							}
							// A statement on the receiver path is already shown there.
							onPath := false
							for _, sp := range path {
								onPath = onPath || (sp.File == r.m.file && uint(sp.StartByte) >= stmt.StartByte() && uint(sp.EndByte) <= stmt.EndByte())
							}
							if onPath || len(out) >= maxReferencedDefinitions {
								continue
							}
							e := r.m.evidence("referenced_definition", stmt)
							shown = append(shown, e.Span)
							out = append(out, e)
							next = append(next, excerpt{r.m, stmt})
						}
					}
				}
				for i := uint(0); i < n.NamedChildCount(); i++ {
					walk(n.NamedChild(i))
				}
			}
			walk(q.n)
		}
		queue = next
	}
	return out
}

// topStatement is the module-level statement that contains n, or nil when n is
// not under one.
func topStatement(n *sitter.Node) *sitter.Node {
	for p := n; p != nil; p = p.Parent() {
		if parent := p.Parent(); parent != nil && parent.Kind() == "program" {
			return p
		}
	}
	return nil
}
