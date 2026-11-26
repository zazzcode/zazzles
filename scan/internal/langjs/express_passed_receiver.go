package langjs

import sitter "github.com/tree-sitter/go-tree-sitter"

// An Express application passed to a function of another module.
//
// `routes(app, db)` in the server file, with `module.exports = (app, db) => {
// app.get(...) }` in the routes file, registers routes on a parameter. The
// parameter is a receiver when a call in a scanned module passes a verified,
// unshadowed module-level receiver at that position, and the callee resolves to
// exactly one function. The rule names no application and no file layout.

// passReceivers marks such parameters before routes are read.
func (s *moduleSet) passReceivers(selected []string) {
	for _, file := range selected {
		m, err := s.load(file)
		if err != nil {
			continue
		}
		if len(m.receivers) == 0 || m.tree.RootNode().HasError() {
			continue
		}
		walkCalls(m.tree.RootNode(), func(call *sitter.Node) {
			fn, args := unwrapTS(call.ChildByFieldName("function")), call.ChildByFieldName("arguments")
			if fn == nil || args == nil || fn.Kind() != "identifier" || callHasSpread(call) {
				return
			}
			for i := uint(0); i < args.NamedChildCount(); i++ {
				arg := args.NamedChild(i)
				if arg.Kind() != "identifier" || !m.receivers[arg.Utf8Text(m.src)] || shadowed(call, arg.Utf8Text(m.src), m.src) {
					continue
				}
				targets := s.functionsOf(m, fn)
				if len(targets) != 1 || targets[0].m == m {
					continue
				}
				tm, target := targets[0].m, targets[0].n
				params := parameterPatterns(target)
				if int(i) >= len(params) || params[i] == nil || params[i].Kind() != "identifier" {
					continue
				}
				name := params[i].Utf8Text(tm.src)
				// A module-level binding of the same name would become a receiver too.
				if topLevelBinding(tm, name) {
					continue
				}
				if tm.passedReceivers == nil {
					tm.passedReceivers = map[uintptr]map[string]bool{}
				}
				if tm.passedReceivers[target.Id()] == nil {
					tm.passedReceivers[target.Id()] = map[string]bool{}
				}
				tm.passedReceivers[target.Id()][name] = true
				tm.receivers[name] = true
			}
		})
	}
}

// instanceMethods lists the functions a handler expression names when the flow's
// own resolution cannot: a member of an object constructed from a class or
// constructor function of the repository (handler.show), or a name bound once,
// inside a function, to such a member (const check = handler.check).
func (s *moduleSet) instanceMethods(m *sourceModule, n *sitter.Node) []originRef {
	member := n
	if n.Kind() == "identifier" {
		defs := s.nameDefs(m, n)
		if len(defs) != 1 || defs[0].imp != nil || defs[0].param != nil || defs[0].ref.n == nil || len(defs[0].ref.fields) > 0 {
			return nil
		}
		if at := defs[0].at; at == nil || at.Parent() == nil || at.Parent().Parent() == nil || at.Parent().Parent().Kind() == "program" {
			return nil // a module-level name is resolved by the flow's own rule
		}
		member = unwrapTS(defs[0].ref.n)
	}
	if member == nil || member.Kind() != "member_expression" {
		return nil
	}
	obj := unwrapTS(member.ChildByFieldName("object"))
	if obj == nil || obj.Kind() != "identifier" {
		return nil
	}
	constructed := false
	for _, d := range s.nameDefs(m, obj) {
		if d.ref.n == nil || unwrapTS(d.ref.n).Kind() != "new_expression" {
			return nil
		}
		constructed = true
	}
	if !constructed {
		return nil
	}
	return s.functionsOf(m, member)
}
