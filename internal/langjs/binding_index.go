package langjs

import sitter "github.com/tree-sitter/go-tree-sitter"

// bindingIndex is a module's binding write index (source index layer L2). It is
// built in one pass over the module's syntax tree on first use and is immutable
// afterwards; the tree and source of a loaded module never change.
//
// assigned holds every identifier name that is the direct target of an
// assignment or augmented assignment anywhere in the module. The answer is
// name-based and module-wide, exactly as the analyzers have always asked it: it
// does not resolve scopes, so a write to any same-named binding counts.
//
// The contract facts answer contractBindingStable with the same textual rules
// its whole-module walk used:
//   - written holds every assignment, augmented assignment or update target
//     text, plus each prefix of it that ends before a "." or "[", so a write to
//     name.x or name[i] counts as a write to name;
//   - aliased holds names that are the whole value of a variable declarator;
//   - escapes holds the spans of identifier uses passed as an argument,
//     returned or spread, which a caller may permit one by one.
type bindingIndex struct {
	assigned map[string]bool
	written  map[string]bool
	aliased  map[string]bool
	escapes  map[string][]byteSpan
}

type byteSpan struct{ start, end uint }

func (m *sourceModule) bindingWrites() *bindingIndex {
	if m.bindings == nil {
		m.bindings = buildBindingIndex(m.tree.RootNode(), m.src)
	}
	return m.bindings
}

func buildBindingIndex(root *sitter.Node, src []byte) *bindingIndex {
	idx := &bindingIndex{assigned: map[string]bool{}, written: map[string]bool{}, aliased: map[string]bool{}, escapes: map[string][]byteSpan{}}
	cursor := root.Walk()
	defer cursor.Close()
	for {
		n := cursor.Node()
		switch kind := n.Kind(); kind {
		case "assignment_expression", "augmented_assignment_expression":
			if left := n.ChildByFieldName("left"); left != nil {
				if left.Kind() == "identifier" {
					idx.assigned[left.Utf8Text(src)] = true
				}
				idx.addWrite(left.Utf8Text(src))
			}
		case "update_expression":
			if arg := n.ChildByFieldName("argument"); arg != nil {
				idx.addWrite(arg.Utf8Text(src))
			}
		case "identifier":
			if p := n.Parent(); p != nil {
				switch p.Kind() {
				case "arguments", "return_statement", "spread_element":
					name := n.Utf8Text(src)
					idx.escapes[name] = append(idx.escapes[name], byteSpan{n.StartByte(), n.EndByte()})
				case "variable_declarator":
					if v := p.ChildByFieldName("value"); v != nil && v.StartByte() == n.StartByte() {
						idx.aliased[n.Utf8Text(src)] = true
					}
				}
			}
		}
		if cursor.GotoFirstChild() {
			continue
		}
		for !cursor.GotoNextSibling() {
			if !cursor.GotoParent() {
				return idx
			}
		}
	}
}

func (idx *bindingIndex) addWrite(text string) {
	idx.written[text] = true
	for i := 0; i < len(text); i++ {
		if text[i] == '.' || text[i] == '[' {
			idx.written[text[:i]] = true
		}
	}
}

// contractStable reports whether name is never reassigned, written through,
// aliased or let escape except at the permitted nodes.
func (idx *bindingIndex) contractStable(name string, allowed []*sitter.Node) bool {
	if idx.assigned[name] || idx.written[name] || idx.aliased[name] {
		return false
	}
	for _, use := range idx.escapes[name] {
		permitted := false
		for _, item := range allowed {
			if item != nil && use.start == item.StartByte() && use.end == item.EndByte() {
				permitted = true
			}
		}
		if !permitted {
			return false
		}
	}
	return true
}
