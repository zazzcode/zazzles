package langpy

import sitter "github.com/tree-sitter/go-tree-sitter"

// pythonBindingIndex is a module's binding write index for receiver typing
// (step 1D). Like the JS index it is name-based and module-wide, so a name
// reused in two functions counts as written twice and stays untyped.
type pythonBindingIndex struct {
	writes  map[string]int  // assignment-like writes per identifier
	lists   map[string]bool // the single write is a list literal
	aliased map[string]bool // the whole right side of an assignment, or global/nonlocal
	dynamic bool            // exec, eval, globals, locals, vars or setattr is called
}

func (m *pythonModule) bindingIndex() *pythonBindingIndex {
	if m.bindings == nil {
		m.bindings = buildPythonBindingIndex(m)
	}
	return m.bindings
}

func buildPythonBindingIndex(m *pythonModule) *pythonBindingIndex {
	idx := &pythonBindingIndex{writes: map[string]int{}, lists: map[string]bool{}, aliased: map[string]bool{}}
	pyWalk(m.tree.RootNode(), func(n *sitter.Node) {
		switch n.Kind() {
		case "assignment", "augmented_assignment":
			if left := pyField(n, "left"); left != nil {
				idx.addTargets(m, left, n.Kind() == "assignment" && pyField(n, "right") != nil && pyField(n, "right").Kind() == "list")
			}
			if right := pyField(n, "right"); right != nil && right.Kind() == "identifier" {
				idx.aliased[pyText(m, right)] = true
			}
		case "for_statement", "for_in_clause":
			if left := pyField(n, "left"); left != nil {
				idx.addTargets(m, left, false)
			}
		case "as_pattern", "with_item", "named_expression", "except_clause":
			idx.addPatternNames(m, n)
		case "global_statement", "nonlocal_statement":
			for i := uint(0); i < n.NamedChildCount(); i++ {
				idx.aliased[pyText(m, n.NamedChild(i))] = true
			}
		case "call":
			switch pyText(m, pyField(n, "function")) {
			case "exec", "eval", "globals", "locals", "vars", "setattr":
				idx.dynamic = true
			}
		}
	})
	return idx
}

func (idx *pythonBindingIndex) addTargets(m *pythonModule, left *sitter.Node, list bool) {
	if left.Kind() == "identifier" {
		name := pyText(m, left)
		idx.writes[name]++
		idx.lists[name] = list && idx.writes[name] == 1
		return
	}
	// Tuple, list, attribute and subscript targets: every identifier inside counts as written.
	pyWalk(left, func(n *sitter.Node) {
		if n.Kind() == "identifier" {
			idx.writes[pyText(m, n)] += 2
		}
	})
}

func (idx *pythonBindingIndex) addPatternNames(m *pythonModule, n *sitter.Node) {
	pyWalk(n, func(c *sitter.Node) {
		if c.Kind() == "identifier" && c.Parent() != nil && c.Parent().Kind() != "call" && c.Parent().Kind() != "attribute" {
			idx.writes[pyText(m, c)] += 2
		}
	})
}

// list reports whether name is a module-stable local list: written exactly once,
// from a list literal, never aliased, in a module without dynamic writes.
func (idx *pythonBindingIndex) list(name string) bool {
	return !idx.dynamic && idx.writes[name] == 1 && idx.lists[name] && !idx.aliased[name]
}
