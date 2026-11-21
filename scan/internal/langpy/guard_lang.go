package langpy

import (
	sitter "github.com/tree-sitter/go-tree-sitter"

	"github.com/zazzcode/zazzles/scan/internal/parse"
)

// guardLang returns the guard engine adapter for the flow's Python module; call
// terminators are verified against the flow's imports and shadowing.
func (f *pythonFlow) guardLang() parse.GuardLang {
	m := f.module
	return parse.GuardLang{
		Src:      m.src,
		Blocks:   map[string]bool{"block": true, "module": true},
		Function: func(n *sitter.Node) bool { return n.Kind() == "function_definition" },
		Exits:    f.pyAlwaysExits,
		Binding: func(n *sitter.Node) (*sitter.Node, *sitter.Node) {
			if n.Kind() != "assignment" {
				return nil, nil
			}
			left, right := n.ChildByFieldName("left"), n.ChildByFieldName("right")
			if left == nil || right == nil || left.Kind() != "identifier" {
				return nil, nil
			}
			return left, right
		},
		Writes: func(n *sitter.Node) []*sitter.Node {
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
