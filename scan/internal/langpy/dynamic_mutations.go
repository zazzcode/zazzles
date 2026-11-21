package langpy

import (
	sitter "github.com/tree-sitter/go-tree-sitter"
)

// Mutation indexing is conservative across lexical bindings of the same name.
// Registry-builder locals use the explicitly modeled setdefault/append operations;
// mutation of module registries, member functions or imported lookups is unsupported.
func (s *pythonSet) indexStaticMutations() {
	s.staticInvalid = map[string]bool{}
	for _, file := range s.files {
		m := s.modules[file]
		if m == nil {
			continue
		}
		assignments := map[string]int{}
		mark := func(name string) {
			target, key := s.resolve(m, name, 0)
			for depth := 0; target != nil && depth < 8; depth++ {
				s.staticInvalid[target.file+":"+key] = true
				v := target.vars[key]
				if v == nil || v.Kind() != "identifier" {
					break
				}
				next, k := s.resolve(target, pyText(target, v), 0)
				if next == target && k == key {
					break
				}
				target, key = next, k
			}
			s.staticInvalid[m.file+":"+name] = true
		}
		pyWalk(m.tree.RootNode(), func(n *sitter.Node) {
			if n.Kind() == "assignment" || n.Kind() == "augmented_assignment" {
				left := n.ChildByFieldName("left")
				if left == nil {
					return
				}
				if left.Kind() == "identifier" {
					name := pyText(m, left)
					global := m.vars[name]
					if global != nil {
						// Count only module-scope assignments; a global write inside a function
						// is conservatively invalidated as well.
						top := true
						for p := n.Parent(); p != nil; p = p.Parent() {
							if p.Kind() == "function_definition" {
								top = false
								break
							}
						}
						if top {
							assignments[name]++
							if assignments[name] > 1 {
								s.staticInvalid[m.file+":"+name] = true
							}
						}
					}
					if m.funcs[name] != nil || m.imports[name].node != nil {
						s.staticInvalid[m.file+":"+name] = true
					}
				} else {
					root := left
					for root != nil && (root.Kind() == "subscript" || root.Kind() == "attribute") {
						if root.Kind() == "attribute" {
							root = root.ChildByFieldName("object")
						} else {
							root = root.ChildByFieldName("value")
						}
					}
					if root != nil {
						name := pyText(m, root)
						if m.vars[name] != nil || m.imports[name].node != nil {
							mark(name)
							mark(pyText(m, left))
						}
					}
				}
			}
			if n.Kind() != "call" {
				return
			}
			callee := n.ChildByFieldName("function")
			if callee != nil && callee.Kind() == "identifier" {
				name := pyText(m, callee)
				target, key := s.resolve(m, name, 0)
				if (target == nil || target.funcs[key] == nil) && name != "print" && name != "len" && name != "str" {
					for _, arg := range pyArgs(n) {
						if arg.Kind() == "identifier" && m.vars[pyText(m, arg)] != nil {
							mark(pyText(m, arg))
						}
					}
				}
			}
			fn := n.ChildByFieldName("function")
			if fn == nil {
				return
			}
			if fn.Kind() == "attribute" {
				obj := fn.ChildByFieldName("object")
				root := obj
				for root != nil && (root.Kind() == "subscript" || root.Kind() == "attribute") {
					if root.Kind() == "attribute" {
						root = root.ChildByFieldName("object")
					} else {
						root = root.ChildByFieldName("value")
					}
				}
				if root != nil && m.vars[pyText(m, root)] != nil {
					method := pyText(m, fn.ChildByFieldName("attribute"))
					switch method {
					case "append", "extend", "insert", "pop", "clear", "update", "setdefault", "remove", "sort", "reverse":
						mark(pyText(m, root))
					}
				}
			}
		})
	}
}
