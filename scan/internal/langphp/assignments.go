package langphp

import sitter "github.com/tree-sitter/go-tree-sitter"

// phpVariableScope returns the function, method, closure or file whose
// variables n names.
func phpVariableScope(n *sitter.Node) *sitter.Node {
	for p := n.Parent(); p != nil; p = p.Parent() {
		switch p.Kind() {
		case "function_definition", "method_declaration", "anonymous_function", "anonymous_function_creation_expression", "arrow_function":
			return p
		}
		n = p
	}
	return n
}

// phpReachingWrites returns the writes of the variable use that can reach
// it within its variable scope: the nearest earlier assignment statement in
// one of the use's enclosing blocks (nil when there is none), and, in source
// order, each later write that does not dominate the use, such as an
// assignment in a branch or a compound assignment. A write before the
// dominating assignment is overwritten and is not returned.
func phpReachingWrites(m *phpModule, use *sitter.Node) (dominating *sitter.Node, branch []*sitter.Node) {
	name, scope := phpText(m, use), phpVariableScope(use)
	var writes []*sitter.Node
	phpWalk(scope, func(n *sitter.Node) {
		if n.Kind() != "assignment_expression" && n.Kind() != "augmented_assignment_expression" {
			return
		}
		if n.EndByte() > use.StartByte() || phpText(m, phpField(n, "left")) != name || phpVariableScope(n).Id() != scope.Id() {
			return
		}
		writes = append(writes, n)
	})
	for i := len(writes) - 1; i >= 0; i-- {
		w := writes[i]
		if w.Kind() == "assignment_expression" && phpDominatingInitializer(phpField(w, "left"), use) != nil {
			return w, writes[i+1:]
		}
	}
	return nil, writes
}
