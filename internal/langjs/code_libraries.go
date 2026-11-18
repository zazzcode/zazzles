package langjs

import (
	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
	"regexp"
	"strings"
)

// sandboxInstanceBinding accepts only an immutable local constructed from the
// named imported class. An arbitrary object with a run/evaluate method is not
// an interpreter binding.
func sandboxInstanceBinding(m *sourceModule, call, fn *sitter.Node) []analysis.Evidence {
	if fn.Kind() != "member_expression" {
		return nil
	}
	obj, method := fn.ChildByFieldName("object"), fn.ChildByFieldName("property")
	if obj == nil || method == nil || obj.Kind() != "identifier" {
		return nil
	}
	if method.Utf8Text(m.src) != "run" && method.Utf8Text(m.src) != "evaluate" {
		return nil
	}
	available := false
	for _, imp := range m.imports {
		available = available || imp.module == "vm2" || imp.module == "expr-eval"
	}
	if !available {
		return nil
	}
	local := obj.Utf8Text(m.src)
	if bindingReassigned(m, local) {
		return nil
	}
	init := unwrapTS(localInitializer(m, call, local))
	if init == nil || init.Kind() != "new_expression" {
		return nil
	}
	ctor := init.ChildByFieldName("constructor")
	if ctor == nil || ctor.Kind() != "identifier" {
		return nil
	}
	imp, ok := m.imports[ctor.Utf8Text(m.src)]
	if !ok || shadowed(call, ctor.Utf8Text(m.src), m.src) {
		return nil
	}
	if imp.module == "vm2" && (imp.name == "VM" || imp.name == "NodeVM") && method.Utf8Text(m.src) == "run" || imp.module == "expr-eval" && imp.name == "Parser" && method.Utf8Text(m.src) == "evaluate" {
		return []analysis.Evidence{m.evidence("sink_binding", imp.declaration), m.evidence("sink_binding", init), m.evidence("sink_binding", fn)}
	}
	return nil
}

func (f *flow) metaNavigation(n *sitter.Node) bool {
	if f.web == nil && f.client == nil || n.Kind() != "jsx_self_closing_element" && n.Kind() != "jsx_opening_element" {
		return false
	}
	tag := n.ChildByFieldName("name")
	if tag == nil || tag.Utf8Text(f.module.src) != "meta" {
		return false
	}
	refresh := false
	var content *sitter.Node
	for i := uint(0); i < n.NamedChildCount(); i++ {
		attr := n.NamedChild(i)
		if attr.Kind() != "jsx_attribute" || attr.NamedChildCount() < 2 {
			continue
		}
		name, arg := attr.NamedChild(0).Utf8Text(f.module.src), attr.NamedChild(1)
		if arg.Kind() == "jsx_expression" && arg.NamedChildCount() == 1 {
			arg = arg.NamedChild(0)
		}
		if name == "content" {
			content = arg
		}
		if name == "httpEquiv" || name == "http-equiv" {
			s, _ := stringLiteral(arg, f.module.src)
			refresh = strings.EqualFold(s, "refresh")
		}
	}
	if refresh && content != nil {
		f.recordInterpreter(n, content, f.eval(content), "redirect", "meta.refresh", "browser-navigation-v1", []analysis.Evidence{f.module.evidence("sink_binding", tag)}, 0)
		return true
	}
	return false
}

// vmSandboxEvaluator follows only the exact fixed program f(x), when f is a
// verified evaluator import and x is a recorded field of that same context.
// Other fixed VM programs keep request context data outside the code claim.
func (f *flow) vmSandboxEvaluator(call, args *sitter.Node, binding []analysis.Evidence) bool {
	if args.NamedChildCount() < 2 {
		return false
	}
	code, ok := stringLiteral(args.NamedChild(0), f.module.src)
	if !ok {
		return false
	}
	match := sandboxInvocation.FindStringSubmatch(code)
	if match == nil {
		return false
	}
	context := unwrapTS(args.NamedChild(1))
	if context.Kind() == "identifier" {
		if bindingReassigned(f.module, context.Utf8Text(f.module.src)) {
			return false
		}
		context = unwrapTS(localInitializer(f.module, call, context.Utf8Text(f.module.src)))
	}
	if context == nil || context.Kind() != "object" {
		return false
	}
	local := ""
	for i := uint(0); i < context.NamedChildCount(); i++ {
		item := context.NamedChild(i)
		if item.Kind() == "shorthand_property_identifier" && item.Utf8Text(f.module.src) == match[1] {
			local = match[1]
		}
		if item.Kind() == "pair" {
			key, val := item.ChildByFieldName("key"), item.ChildByFieldName("value")
			if key != nil && val != nil && key.Utf8Text(f.module.src) == match[1] && val.Kind() == "identifier" {
				local = val.Utf8Text(f.module.src)
			}
		}
	}
	imp, ok := f.module.imports[local]
	if !ok || imp.module != "notevil" || imp.name != "eval" && imp.name != "default" && imp.name != "*" || shadowed(call, local, f.module.src) {
		return false
	}
	v := f.eval(args.NamedChild(1)).fields[match[2]]
	if len(v.deps) == 0 {
		return false
	}
	binding = append(binding, f.module.evidence("sink_binding", imp.declaration), f.module.evidence("sandbox_program", args.NamedChild(0)))
	f.recordInterpreter(call, args.NamedChild(1), v, "code", "notevil.eval", "js-safe-eval-libs-v1", binding, 0)
	return true
}

var sandboxInvocation = regexp.MustCompile(`^\s*([A-Za-z_$][\w$]*)\(\s*([A-Za-z_$][\w$]*)\s*\)\s*;?\s*$`)

func interpreterMemberMutated(m *sourceModule, name string) bool {
	// Only interpreter-shaped calls need this whole-module pass; cache it once.
	if !strings.Contains(name, "eval") && !strings.Contains(name, "Function") && !strings.Contains(name, "runIn") && !strings.Contains(name, "Script") && !strings.Contains(name, "compile") && !strings.Contains(name, "evaluate") && !strings.Contains(name, "setTimeout") && !strings.Contains(name, "setInterval") && !strings.Contains(name, "setImmediate") {
		return false
	}
	if m.interpreterMutations == nil {
		m.interpreterMutations = map[string]bool{}
		walkNodes(m.tree.RootNode(), func(n *sitter.Node) {
			if n.Kind() != "assignment_expression" && n.Kind() != "augmented_assignment_expression" {
				return
			}
			left := n.ChildByFieldName("left")
			if left == nil {
				return
			}
			key := left.Utf8Text(m.src)
			if left.Kind() == "subscript_expression" {
				obj, index := left.ChildByFieldName("object"), left.ChildByFieldName("index")
				if obj != nil {
					if prop, ok := stringLiteral(index, m.src); ok {
						key = obj.Utf8Text(m.src) + "." + prop
					}
				}
			}
			m.interpreterMutations[key] = true
			if key == "window.eval" || key == "globalThis.eval" {
				m.interpreterMutations["eval"] = true
				m.interpreterMutations["window.eval"] = true
				m.interpreterMutations["globalThis.eval"] = true
			}
		})
	}
	return m.interpreterMutations[name]
}
