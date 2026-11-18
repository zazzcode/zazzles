package parse

import (
	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
)

// guardLang returns the guard engine adapter for a JavaScript or TypeScript module.
func (m *sourceModule) guardLang() GuardLang {
	return GuardLang{
		Src:      m.src,
		Blocks:   map[string]bool{"statement_block": true, "program": true},
		Function: func(n *sitter.Node) bool { return isFunction(n) || n.Kind() == "function_declaration" },
		Exits:    m.jsAlwaysExits,
		Binding: func(n *sitter.Node) (*sitter.Node, *sitter.Node) {
			if n.Kind() != "variable_declarator" {
				return nil, nil
			}
			id, v := n.ChildByFieldName("name"), n.ChildByFieldName("value")
			if id == nil || id.Kind() != "identifier" {
				return nil, nil
			}
			return id, v
		},
		Writes: func(n *sitter.Node) []*sitter.Node {
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
