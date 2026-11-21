package langjs

import (
	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

// tryStatement keeps the normal and exceptional paths separate. A catch can
// observe any prefix of the try body, so its environment joins the incoming
// bindings and the completed normal arm; try-arm guards never protect catch.
func (f *flow) tryStatement(n *sitter.Node) bool {
	before := copyValues(f.env)
	context := append([]analysis.Evidence{}, f.context...)
	request, response := f.request, f.response
	normalExit := f.statements(n.ChildByFieldName("body"))
	normal := copyValues(f.env)
	catchExit := true
	handler := n.ChildByFieldName("handler")
	if handler != nil {
		f.env = copyValues(before)
		for key, v := range normal {
			f.env[key] = combine(f.env[key], v)
		}
		f.context = append([]analysis.Evidence{}, context...)
		f.context = append(f.context, f.module.evidence("exception_precondition", handler))
		f.request, f.response = request, response
		if param := handler.ChildByFieldName("parameter"); param != nil && param.Kind() == "identifier" {
			f.env[param.Utf8Text(f.module.src)] = value{}
		}
		catchExit = f.statements(handler.ChildByFieldName("body"))
		if !normalExit {
			for key, v := range normal {
				f.env[key] = combine(f.env[key], v)
			}
		}
	} else {
		f.env = normal
	}
	f.context = context
	// A normal-arm guard is not an unconditional guard after try/catch.
	if fin := n.ChildByFieldName("finalizer"); fin != nil {
		if f.statements(fin.ChildByFieldName("body")) {
			return true
		}
	}
	return normalExit && catchExit
}
