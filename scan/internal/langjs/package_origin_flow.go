package langjs

import (
	"fmt"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

// Database package operations in code the flow does not otherwise enter.
//
// A method of an instance of the application's own class, and the expression a
// loop iterates, are walked on a copy of the flow. Only database package
// operations are kept from that walk. The flow itself, the records of every
// other family and the shared storage and token facts stay exactly as they were.

// maxStoreSideWalks bounds the side walks of one flow.
const maxStoreSideWalks = 12

// storeSide runs a walk on a copy of the flow and keeps the database package
// operations it records.
func (f *flow) storeSide(run func(child *flow)) {
	if f.set == nil || !f.set.storeActive || f.client != nil || f.helpers == nil || f.helpers.sideWalks >= maxStoreSideWalks {
		return
	}
	f.helpers.sideWalks++
	child := *f
	child.report = nil
	child.env = copyValues(f.env)
	child.context = append([]analysis.Evidence{}, f.context...)
	child.gaps = append([]analysis.Gap{}, f.gaps...)
	child.uses, child.returns, child.heapWrites, child.conditions, child.witness, child.setterValue = nil, nil, nil, nil, nil, nil
	child.facts = newInputFacts()
	stack := map[string]bool{}
	for key := range f.helpers.stack {
		stack[key] = true
	}
	child.helpers = &helperExpansion{budget: 8, stack: stack, sideWalks: f.helpers.sideWalks, aliases: f.helpers.aliases, aliasWalk: f.helpers.aliasWalk}
	restore := f.set.sharedFlowState()
	run(&child)
	restore()
	f.helpers.sideWalks = child.helpers.sideWalks
	for _, u := range child.uses {
		if _, ok := storeKinds[u.Kind]; !ok {
			continue
		}
		recorded := false
		for _, old := range f.uses {
			recorded = recorded || (old.Kind == u.Kind && old.Sink.Span == u.Sink.Span)
		}
		if binding, _ := f.set.storeBinding(u); len(binding) > 0 && !recorded {
			f.uses = append(f.uses, u)
		}
	}
}

// storeKinds are the candidate kinds of the database packages.
var storeKinds = func() map[string]bool {
	out := map[string]bool{}
	for _, p := range storePackages {
		out[p.kind] = true
	}
	return out
}()

// sharedFlowState returns a function that puts back the facts a flow writes to
// its module set, so a side walk leaves none.
func (s *moduleSet) sharedFlowState() func() {
	writes := map[string]int{}
	for key, list := range s.storageWrites {
		writes[key] = len(list)
	}
	hadWrites := s.storageWrites != nil
	own := map[string]bool{}
	for key := range s.ownAPI {
		own[key] = true
	}
	hadOwn := s.ownAPI != nil
	producers, tokens := len(s.producers), len(s.signedTokens)
	return func() {
		if !hadWrites {
			s.storageWrites = nil
		}
		for key, list := range s.storageWrites {
			if n, ok := writes[key]; !ok {
				delete(s.storageWrites, key)
			} else if len(list) > n {
				s.storageWrites[key] = list[:n]
			}
		}
		if !hadOwn {
			s.ownAPI = nil
		}
		for key := range s.ownAPI {
			if !own[key] {
				delete(s.ownAPI, key)
			}
		}
		s.producers, s.signedTokens = s.producers[:producers], s.signedTokens[:tokens]
	}
}

// storeMethodCall follows a call of a method the flow cannot resolve to the
// method of the application's own class or object that it names, for database
// package operations only.
func (f *flow) storeMethodCall(n, fn *sitter.Node, values []value) {
	if f.set == nil || !f.set.storeActive || f.helpers == nil || fn.Kind() != "member_expression" || callHasSpread(n) || !requestDeps(values) {
		return
	}
	if hm, helper := f.set.resolveCall(f.module, n); hm != nil && helper != nil {
		return
	}
	targets := f.set.functionsOf(f.module, fn)
	if len(targets) != 1 {
		return
	}
	hm, helper := targets[0].m, targets[0].n
	params, ok := functionParameters(helper, hm.src)
	if !ok || len(values) > len(params) {
		return
	}
	key := fmt.Sprintf("%s:%d", hm.file, helper.StartByte())
	if f.helpers.stack[key] {
		return
	}
	f.storeSide(func(child *flow) {
		child.helpers.stack[key] = true
		child.context = append(child.context, hm.evidence("helper_definition", helper), f.module.evidence("helper_call", n))
		child.module = hm
		child.env = map[string]value{}
		child.request, child.response, child.redirectResponse = "", "", ""
		child.depth = f.depth + 1
		args := n.ChildByFieldName("arguments")
		for i, p := range params {
			if i >= len(values) {
				child.env[p.name] = value{}
				continue
			}
			if arg := args.NamedChild(uint(i)); f.request != "" && arg != nil && arg.Kind() == "identifier" && arg.Utf8Text(f.module.src) == f.request {
				child.request = p.name
			}
			child.env[p.name] = child.transfer(values[i], "parameter_binding", p.node)
		}
		child.statements(helper.ChildByFieldName("body"))
	})
}

// storeIterable walks the expression a for-of or for-await loop iterates, which
// the flow does not evaluate, for database package operations.
func (f *flow) storeIterable(loop *sitter.Node) {
	right := loop.ChildByFieldName("right")
	if right == nil {
		return
	}
	found := false
	walkCalls(right, func(*sitter.Node) { found = true })
	if !found {
		return
	}
	f.storeSide(func(child *flow) { child.eval(right) })
}

// noteStoreAlias keeps a renamed destructured property, { key: local }, which
// the flow does not bind. Only database package operations read it.
func (f *flow) noteStoreAlias(local string, v value) {
	if f.helpers == nil || f.client != nil || f.set == nil || !f.set.storeActive {
		return
	}
	if f.helpers.aliases == nil {
		f.helpers.aliases = map[string]value{}
	}
	f.helpers.aliases[f.module.file+":"+local] = v
}

// storeAliasCall walks a call again with the renamed properties bound, when the
// call names one and the flow found no request value in it.
func (f *flow) storeAliasCall(n *sitter.Node) {
	if f.helpers == nil || f.helpers.aliasWalk || len(f.helpers.aliases) == 0 {
		return
	}
	bound := map[string]value{}
	var walk func(*sitter.Node)
	walk = func(c *sitter.Node) {
		if c.Kind() == "identifier" || c.Kind() == "shorthand_property_identifier" {
			name := c.Utf8Text(f.module.src)
			if v, ok := f.helpers.aliases[f.module.file+":"+name]; ok {
				if _, known := f.env[name]; !known {
					bound[name] = v
				}
			}
		}
		for i := uint(0); i < c.NamedChildCount(); i++ {
			// A nested call is walked when the flow reaches it.
			if child := c.NamedChild(i); child.Kind() != "call_expression" && !isFunction(child) {
				walk(child)
			}
		}
	}
	if args := n.ChildByFieldName("arguments"); args != nil {
		walk(args)
	}
	if len(bound) == 0 {
		return
	}
	f.storeSide(func(child *flow) {
		child.helpers.aliasWalk = true
		for name, v := range bound {
			child.env[name] = v
		}
		child.eval(n)
	})
}

// storeClosureCall reads an argument that is a call, without arguments, of a
// function written inside the current function: find(criteria()). Such a
// function reads the variables around it, so its body is walked with the
// current bindings, and what it returns is the argument.
func (f *flow) storeClosureCall(n, args *sitter.Node) {
	if args == nil || f.helpers == nil || f.set == nil {
		return
	}
	for i := uint(0); i < args.NamedChildCount(); i++ {
		arg := unwrapTS(args.NamedChild(i))
		if arg == nil || arg.Kind() != "call_expression" {
			continue
		}
		callee, inner := unwrapTS(arg.ChildByFieldName("function")), arg.ChildByFieldName("arguments")
		if callee == nil || callee.Kind() != "identifier" || inner == nil || inner.NamedChildCount() != 0 {
			continue
		}
		targets := f.set.functionsOf(f.module, callee)
		if len(targets) != 1 || targets[0].m != f.module {
			continue
		}
		closure := targets[0].n
		// Only a function nested in a function: a module-level one is a helper.
		nested := false
		for p := closure.Parent(); p != nil; p = p.Parent() {
			nested = nested || scopeFunction(p)
		}
		if !nested {
			continue
		}
		if pkg, _ := f.set.storeOrigin(f.module, n); pkg == "" {
			return
		}
		position := int(i)
		f.storeSide(func(child *flow) {
			child.statements(closure.ChildByFieldName("body"))
			var returned value
			for _, r := range child.returns {
				returned = combine(returned, r)
			}
			child.uses = nil
			values := make([]value, args.NamedChildCount())
			values[position] = returned
			if requestDeps(values) {
				child.recordStore(n, args, values)
			}
		})
		return
	}
}
