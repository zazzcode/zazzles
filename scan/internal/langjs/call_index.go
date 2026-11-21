package langjs

import (
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
)

// Call index (source index layer L3, step 1D): each JS/TS call site resolves
// once per module to a resolution kind. Receiver types come only from bindings
// the binding index shows are never reassigned or written through (spec D-8);
// anything else is unresolved with a reason, never guessed from a method name.

type callKind uint8

const (
	callUnresolved    callKind = iota
	callDirect                 // definition in the same module
	callImported               // definition in another in-repository module
	callKnownClass             // method on a typed receiver (for example a Sequelize model)
	callBuiltinMethod          // method on an unbound, unshadowed language builtin
	callPackageMember          // member of a module imported from outside the repository
)

var callKindNames = [...]string{"unresolved", "direct", "imported", "method_on_known_class", "builtin_method", "package_member"}

func (k callKind) String() string { return callKindNames[k] }

// callResolution is one call site's entry. Receiver is a type key such as
// "module:os", "builtin:JSON" or "sequelize_model"; Reason explains an
// unresolved site.
type callResolution struct {
	Kind             callKind
	Receiver, Method string
	Reason           string
}

// jsBuiltinObjects are global objects whose methods the effect table may name.
var jsBuiltinObjects = map[string]bool{"JSON": true, "Math": true, "Date": true, "Number": true, "String": true, "Object": true, "Array": true}

func (s *moduleSet) callResolution(m *sourceModule, call *sitter.Node) callResolution {
	if m.calls == nil {
		m.calls = map[uintptr]callResolution{}
	}
	if r, ok := m.calls[call.Id()]; ok {
		return r
	}
	r := s.resolveCallSite(m, call)
	m.calls[call.Id()] = r
	return r
}

func (s *moduleSet) resolveCallSite(m *sourceModule, call *sitter.Node) callResolution {
	if call.Kind() != "call_expression" {
		return callResolution{Reason: "not_a_call"}
	}
	if hm, def := s.resolveCall(m, call); def != nil {
		if hm == m {
			return callResolution{Kind: callDirect}
		}
		return callResolution{Kind: callImported}
	}
	fn := call.ChildByFieldName("function")
	if fn == nil || fn.Kind() != "member_expression" {
		return callResolution{Reason: "dynamic_callee"}
	}
	object, property := fn.ChildByFieldName("object"), fn.ChildByFieldName("property")
	if object == nil || property == nil {
		return callResolution{Reason: "dynamic_callee"}
	}
	method := property.Utf8Text(m.src)
	switch object.Kind() {
	case "identifier":
	case "new_expression":
		// new Date().toISOString(): the receiver is a fresh builtin instance.
		ctor := object.ChildByFieldName("constructor")
		if ctor != nil && ctor.Kind() == "identifier" && s.unboundBuiltin(m, call, ctor.Utf8Text(m.src)) {
			return callResolution{Kind: callBuiltinMethod, Receiver: "builtin:" + ctor.Utf8Text(m.src) + "#instance", Method: method}
		}
		return callResolution{Reason: "unknown_receiver"}
	default:
		return callResolution{Reason: "dynamic_callee"}
	}
	root := object.Utf8Text(m.src)
	if m.cachedShadowed(call, root) {
		return callResolution{Reason: "shadowed"}
	}
	writes := m.bindingWrites()
	if writes.assigned[root] || writes.written[root] {
		return callResolution{Reason: "dynamic_write"}
	}
	if s.modelIdentity(m, root, 0) != "" {
		return callResolution{Kind: callKnownClass, Receiver: "sequelize_model", Method: method}
	}
	if imp, ok := m.imports[root]; ok {
		if s.importModule(m, imp.module) != nil {
			return callResolution{Reason: "unknown_import_member"}
		}
		if imp.name != "*" && imp.name != "default" {
			return callResolution{Reason: "unknown_import_member"}
		}
		return callResolution{Kind: callPackageMember, Receiver: "module:" + strings.TrimPrefix(imp.module, "node:"), Method: method}
	}
	if s.unboundBuiltin(m, call, root) {
		return callResolution{Kind: callBuiltinMethod, Receiver: "builtin:" + root, Method: method}
	}
	return callResolution{Reason: "unknown_receiver"}
}

// unboundBuiltin reports whether name refers to the global builtin object: it is
// listed, has no module binding, is never written and is not shadowed here.
func (s *moduleSet) unboundBuiltin(m *sourceModule, call *sitter.Node, name string) bool {
	if !jsBuiltinObjects[name] || m.cachedShadowed(call, name) {
		return false
	}
	if _, ok := m.imports[name]; ok || m.funcs[name] != nil || topVariable(m, name) != nil {
		return false
	}
	writes := m.bindingWrites()
	return !writes.assigned[name] && !writes.written[name]
}
