package langjs

import (
	"strconv"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

// A keyed lookup `store[key]` on a server-held store returns what the server
// wrote into it, not the key. The key may be request data (a session token) while
// the stored value (the logged-in user record) is not.
//
// A reference is a server-held store only when it is
//   - `this.X` inside a method of a const object literal whose property X is
//     initialized to an empty `{}` / `Object.create(null)`, or
//   - an identifier bound by a module-level const initialized the same way and not
//     shadowed in the flow;
//
// and the store is "clean": every reference to it in its module is a property
// access (`store[k]`, `store.k`), so it is never aliased, passed, returned, spread
// or filled by a bulk call such as Object.assign. A write to the store anywhere
// in the analyzed flow (including expanded helpers) keeps key taint, because the
// write may put request data into the value read back.
//
// Values written by other requests are second-order flows this analyzer does not
// model for any sink; they are not introduced here.

// storeWritten records that the current flow wrote into the store with this id.
func (h *helperExpansion) storeWritten(id string) {
	if h.storeWrites == nil {
		h.storeWrites = map[string]bool{}
	}
	h.storeWrites[id] = true
}

func emptyStoreLiteral(m *sourceModule, n *sitter.Node) bool {
	if n == nil {
		return false
	}
	switch n.Kind() {
	case "object":
		return n.NamedChildCount() == 0
	case "call_expression":
		fn, args := n.ChildByFieldName("function"), n.ChildByFieldName("arguments")
		return fn != nil && args != nil && fn.Utf8Text(m.src) == "Object.create" &&
			args.NamedChildCount() == 1 && args.NamedChild(0).Kind() == "null"
	}
	return false
}

func isConstDeclaration(m *sourceModule, decl *sitter.Node) bool {
	for p := decl; p != nil; p = p.Parent() {
		if p.Kind() == "lexical_declaration" {
			kw := p.Child(0)
			return kw != nil && kw.Utf8Text(m.src) == "const"
		}
		if p.Kind() == "program" || p.Kind() == "statement_block" {
			return false
		}
	}
	return false
}

// enclosingMethodObject returns the object literal whose method contains n, with
// `this` bound to that literal. Arrow functions keep the outer `this`.
func enclosingMethodObject(n *sitter.Node) *sitter.Node {
	for p := n.Parent(); p != nil; p = p.Parent() {
		switch p.Kind() {
		case "arrow_function":
			continue
		case "method_definition":
			if o := p.Parent(); o != nil && o.Kind() == "object" {
				return o
			}
			return nil
		case "function_expression", "function":
			if pair := p.Parent(); pair != nil && pair.Kind() == "pair" {
				if o := pair.Parent(); o != nil && o.Kind() == "object" && pair.ChildByFieldName("value") != nil &&
					pair.ChildByFieldName("value").StartByte() == p.StartByte() {
					return o
				}
			}
			return nil
		case "function_declaration", "generator_function_declaration", "class_body", "program":
			return nil
		}
	}
	return nil
}

// storeOf resolves a reference to a candidate server-held store. shadowed names
// identifiers that are local bindings of the current flow.
func (m *sourceModule) storeOf(ref *sitter.Node, shadowed func(string) bool) (id string, decl *sitter.Node, name string, viaThis bool) {
	if ref == nil || m.tree == nil {
		return
	}
	switch ref.Kind() {
	case "member_expression":
		obj, prop := ref.ChildByFieldName("object"), ref.ChildByFieldName("property")
		if obj == nil || prop == nil || obj.Kind() != "this" {
			return
		}
		lit := enclosingMethodObject(ref)
		if lit == nil || lit.Parent() == nil || lit.Parent().Kind() != "variable_declarator" || !isConstDeclaration(m, lit) {
			return
		}
		name = prop.Utf8Text(m.src)
		for i := uint(0); i < lit.NamedChildCount(); i++ {
			pair := lit.NamedChild(i)
			if pair.Kind() != "pair" {
				continue
			}
			if k := pair.ChildByFieldName("key"); k != nil && k.Utf8Text(m.src) == name && emptyStoreLiteral(m, pair.ChildByFieldName("value")) {
				return m.file + ":" + strconv.Itoa(int(pair.StartByte())), pair, name, true
			}
		}
	case "identifier":
		name = ref.Utf8Text(m.src)
		if shadowed != nil && shadowed(name) {
			return
		}
		root := m.tree.RootNode()
		for i := uint(0); i < root.NamedChildCount(); i++ {
			top := root.NamedChild(i)
			if top.Kind() == "export_statement" && top.NamedChildCount() > 0 {
				top = top.NamedChild(top.NamedChildCount() - 1)
			}
			if top.Kind() != "lexical_declaration" || !isConstDeclaration(m, top) {
				continue
			}
			for j := uint(0); j < top.NamedChildCount(); j++ {
				d := top.NamedChild(j)
				if d.Kind() != "variable_declarator" {
					continue
				}
				if nm := d.ChildByFieldName("name"); nm != nil && nm.Kind() == "identifier" && nm.Utf8Text(m.src) == name && emptyStoreLiteral(m, d.ChildByFieldName("value")) {
					return m.file + ":" + strconv.Itoa(int(d.StartByte())), d, name, false
				}
			}
		}
	}
	return
}

// storeClean reports whether every reference to the store in its module is a
// property access on it.
func (m *sourceModule) storeClean(decl *sitter.Node, name string, viaThis bool) bool {
	clean := true
	walkNodes(m.tree.RootNode(), func(n *sitter.Node) {
		if !clean {
			return
		}
		isRef := false
		switch {
		case viaThis && n.Kind() == "member_expression":
			o, p := n.ChildByFieldName("object"), n.ChildByFieldName("property")
			isRef = o != nil && p != nil && o.Kind() == "this" && p.Utf8Text(m.src) == name
		case !viaThis && n.Kind() == "identifier" && n.Utf8Text(m.src) == name:
			isRef = n.StartByte() < decl.StartByte() || n.StartByte() >= decl.EndByte()
			if nm := decl.ChildByFieldName("name"); nm != nil && nm.StartByte() == n.StartByte() {
				isRef = false
			}
		case !viaThis && n.Kind() == "shorthand_property_identifier" && n.Utf8Text(m.src) == name:
			clean = false
			return
		}
		if !isRef {
			return
		}
		p := n.Parent()
		if p == nil || (p.Kind() != "member_expression" && p.Kind() != "subscript_expression") {
			clean = false
			return
		}
		if o := p.ChildByFieldName("object"); o == nil || o.StartByte() != n.StartByte() || o.EndByte() != n.EndByte() {
			clean = false
		}
	})
	return clean
}

func (f *flow) storeShadowed(name string) bool {
	_, ok := f.env[name]
	return ok
}

// noteStoreWrite records an assignment whose target lies inside a server-held
// store (`store[k] = v`, `store.k.x = v`). Call it for every unmodeled
// property/subscript write.
func (f *flow) noteStoreWrite(left *sitter.Node) {
	if f.helpers == nil || f.module == nil {
		return
	}
	for n := left; n != nil && (n.Kind() == "member_expression" || n.Kind() == "subscript_expression"); n = n.ChildByFieldName("object") {
		if id, _, _, _ := f.module.storeOf(n.ChildByFieldName("object"), f.storeShadowed); id != "" {
			f.helpers.storeWritten(id)
		}
	}
}

// keyedStoreRead reports whether the subscript read n is a lookup into a clean
// server-held store that nothing in this flow has written to, on a base that
// carries no request data. The caller then drops the key's dependencies and
// gaps from the looked-up value (the key is still evaluated for its own uses).
func (f *flow) keyedStoreRead(n *sitter.Node, base value) bool {
	if n == nil || n.Kind() != "subscript_expression" || len(base.deps) != 0 || f.module == nil || f.helpers == nil {
		return false
	}
	id, decl, name, viaThis := f.module.storeOf(n.ChildByFieldName("object"), f.storeShadowed)
	if id == "" || f.helpers.storeWrites[id] {
		return false
	}
	return f.module.storeClean(decl, name, viaThis)
}

// keyedStorePrefix marks the storage key of a server-held store entry read.
const keyedStorePrefix = "keyed_store:"

// keyedStoreValue returns the stored state a verified keyed store read yields.
// The request-derived key only selects an entry, so it is not a dependency.
// Writes by other requests (for example a login copying a user row into the
// store) are second-order flows that are not modeled: the read is recorded as
// a storage read with no linked writer. Every family then treats the value as
// stored data of unresolved origin: the claim stays visible as Review (no
// input_source evidence), never request-derived through the key and never clean.
func (f *flow) keyedStoreValue(n *sitter.Node, base value) (value, bool) {
	if !f.keyedStoreRead(n, base) {
		return value{}, false
	}
	id, _, _, _ := f.module.storeOf(n.ChildByFieldName("object"), f.storeShadowed)
	read := f.module.evidence("keyed_store_read", n)
	return value{deps: []analysis.Dependency{{
		StorageKey: keyedStorePrefix + id,
		Source:     f.module.evidence("storage_read", n),
		Transfers:  []analysis.Evidence{read},
	}}}, true
}
