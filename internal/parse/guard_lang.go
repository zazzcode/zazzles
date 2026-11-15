package parse

import (
	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
)

// guardLang returns the guard engine adapter for a JavaScript or TypeScript module.
func (m *sourceModule) guardLang() guardLang {
	return guardLang{
		src:      m.src,
		blocks:   map[string]bool{"statement_block": true, "program": true},
		function: func(n *sitter.Node) bool { return isFunction(n) || n.Kind() == "function_declaration" },
		exits:    m.jsAlwaysExits,
		binding: func(n *sitter.Node) (*sitter.Node, *sitter.Node) {
			if n.Kind() != "variable_declarator" {
				return nil, nil
			}
			id, v := n.ChildByFieldName("name"), n.ChildByFieldName("value")
			if id == nil || id.Kind() != "identifier" {
				return nil, nil
			}
			return id, v
		},
		writes: func(n *sitter.Node) []*sitter.Node {
			switch n.Kind() {
			case "assignment_expression", "augmented_assignment_expression":
				if left := n.ChildByFieldName("left"); left != nil {
					return []*sitter.Node{left}
				}
			}
			return nil
		},
	}
}

// jsAlwaysExits reports a statement that cannot fall through: a return, a
// throw, a process.exit call on the Node global, a block containing one, or an
// if/else whose every branch exits.
func (m *sourceModule) jsAlwaysExits(n *sitter.Node) bool {
	if n == nil {
		return false
	}
	switch n.Kind() {
	case "return_statement", "throw_statement":
		return true
	case "expression_statement":
		return n.NamedChildCount() == 1 && m.nodeProcessExit(n.NamedChild(0))
	case "statement_block":
		for i := uint(0); i < n.NamedChildCount(); i++ {
			if m.jsAlwaysExits(n.NamedChild(i)) {
				return true
			}
		}
	case "if_statement":
		alt := n.ChildByFieldName("alternative")
		if alt != nil && alt.NamedChildCount() > 0 {
			return m.jsAlwaysExits(n.ChildByFieldName("consequence")) && m.jsAlwaysExits(alt.NamedChild(alt.NamedChildCount()-1))
		}
	}
	return false
}

// nodeProcessExit recognizes process.exit(...) when `process` is the Node
// global rather than a local, parameter or module-level binding.
func (m *sourceModule) nodeProcessExit(call *sitter.Node) bool {
	if call.Kind() != "call_expression" {
		return false
	}
	fn := call.ChildByFieldName("function")
	if fn == nil || fn.Kind() != "member_expression" {
		return false
	}
	obj, prop := fn.ChildByFieldName("object"), fn.ChildByFieldName("property")
	if obj == nil || prop == nil || obj.Kind() != "identifier" || obj.Utf8Text(m.src) != "process" || prop.Utf8Text(m.src) != "exit" {
		return false
	}
	_, imported := m.imports["process"]
	return !imported && topVariable(m, "process") == nil && !shadowed(call, "process", m.src)
}

// jsHelperCallSites lists the calls to a locally declared helper made from the
// supplied handler bodies of the same module, excluding the helper itself.
func jsHelperCallSites(m *sourceModule, context []analysis.Evidence, helper *sitter.Node) []*sitter.Node {
	name := localFunctionName(m, helper)
	if name == "" {
		return nil
	}
	var sites []*sitter.Node
	for _, e := range context {
		if e.Kind != "handler" && e.Kind != "path_handler" {
			continue
		}
		if body := nodeAt(m.tree.RootNode(), e.Span.StartByte, e.Span.EndByte); body != nil && e.Span.File == m.file {
			walkCalls(body, func(c *sitter.Node) {
				if fn := c.ChildByFieldName("function"); fn != nil && fn.Kind() == "identifier" && fn.Utf8Text(m.src) == name && !(c.StartByte() >= helper.StartByte() && c.EndByte() <= helper.EndByte()) {
					sites = append(sites, c)
				}
			})
		}
	}
	return sites
}

// guardLang returns the guard engine adapter for the flow's Python module; call
// terminators are verified against the flow's imports and shadowing.
func (f *pythonFlow) guardLang() guardLang {
	m := f.module
	return guardLang{
		src:      m.src,
		blocks:   map[string]bool{"block": true, "module": true},
		function: func(n *sitter.Node) bool { return n.Kind() == "function_definition" },
		exits:    f.pyAlwaysExits,
		binding: func(n *sitter.Node) (*sitter.Node, *sitter.Node) {
			if n.Kind() != "assignment" {
				return nil, nil
			}
			left, right := n.ChildByFieldName("left"), n.ChildByFieldName("right")
			if left == nil || right == nil || left.Kind() != "identifier" {
				return nil, nil
			}
			return left, right
		},
		writes: func(n *sitter.Node) []*sitter.Node {
			var field string
			switch n.Kind() {
			case "assignment", "augmented_assignment", "for_statement":
				field = "left"
			case "named_expression":
				field = "name"
			default:
				return nil
			}
			if target := n.ChildByFieldName(field); target != nil {
				return []*sitter.Node{target}
			}
			return nil
		},
	}
}

// pythonExitCalls are the verified calls that end the request: they never fall through.
var pythonExitCalls = map[string]bool{"flask.abort": true, "werkzeug.exceptions.abort": true, "sys.exit": true, "fastapi.HTTPException": true}

// pyAlwaysExits reports a block that cannot fall through: a return, a raise, an
// abort call or an if/else whose every branch exits.
func (f *pythonFlow) pyAlwaysExits(n *sitter.Node) bool {
	if n == nil {
		return false
	}
	switch n.Kind() {
	case "return_statement", "raise_statement":
		return true
	case "expression_statement":
		for i := uint(0); i < n.NamedChildCount(); i++ {
			if c := n.NamedChild(i); c.Kind() == "call" && pythonExitCalls[f.qualified(pyText(f.module, c.ChildByFieldName("function")))] {
				return true
			}
		}
	case "block":
		for i := uint(0); i < n.NamedChildCount(); i++ {
			if f.pyAlwaysExits(n.NamedChild(i)) {
				return true
			}
		}
	case "if_statement":
		alt := n.ChildByFieldName("alternative")
		return alt != nil && f.pyAlwaysExits(n.ChildByFieldName("consequence")) && f.pyAlwaysExits(alt.ChildByFieldName("body"))
	}
	return false
}

// pyHelperCallSites lists the calls to a local helper made from the route
// handler of the same module.
func (f *pythonFlow) pyHelperCallSites(helper *sitter.Node) []*sitter.Node {
	m := f.module
	if helper == nil || f.route.fn == nil || helper.StartByte() == f.route.fn.StartByte() || f.route.module != m {
		return nil
	}
	id := helper.ChildByFieldName("name")
	if id == nil {
		return nil
	}
	name := pyText(m, id)
	var sites []*sitter.Node
	pyWalk(f.route.fn, func(n *sitter.Node) {
		if n.Kind() == "call" {
			if fn := n.ChildByFieldName("function"); fn != nil && fn.Kind() == "identifier" && pyText(m, fn) == name {
				sites = append(sites, n)
			}
		}
	})
	return sites
}
