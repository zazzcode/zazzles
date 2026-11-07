package parse

import (
	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
	"strings"
)

// Source-present controls can be judged, but calls into absent implementations
// receiving their input remain explicit gaps, including nested local helpers.
func (s *moduleSet) nodeControlHelperGaps(m *sourceModule, body *sitter.Node, names []string, depth int) []analysis.Gap {
	if depth > 5 {
		return []analysis.Gap{{Kind: "http_hook_unresolved", Detail: "control helper depth exceeded", At: spanOf(m.file, body)}}
	}
	gaps := []analysis.Gap{}
	walkCalls(body, func(call *sitter.Node) {
		args, fn := call.ChildByFieldName("arguments"), call.ChildByFieldName("function")
		if args == nil || fn == nil {
			return
		}
		relevant := false
		var inspect func(*sitter.Node)
		inspect = func(n *sitter.Node) {
			if n.Kind() == "identifier" {
				for _, name := range names {
					relevant = relevant || name != "" && n.Utf8Text(m.src) == name
				}
			}
			for i := uint(0); i < n.NamedChildCount(); i++ {
				inspect(n.NamedChild(i))
			}
		}
		inspect(args)
		if !relevant {
			return
		}
		if nativeStringOperation(m, call) || nativeHashChainCall(m, call) || len(inputPredicateEvidence(m, call)) > 0 {
			return
		}
		if fn.Utf8Text(m.src) == "JSON.parse" && !shadowed(call, "JSON", m.src) && contractBindingStable(m, "JSON") {
			return
		}
		hm, helper := s.resolveCall(m, call)
		if hm != nil && helper != nil {
			b := helper.ChildByFieldName("body")
			if b != nil {
				gaps = append(gaps, s.nodeControlHelperGaps(hm, b, parameterNames(helper, hm.src), depth+1)...)
				return
			}
		}
		// Literal string/array methods have source-backed built-in receivers.
		if fn.Kind() == "member_expression" {
			obj := fn.ChildByFieldName("object")
			p := fn.ChildByFieldName("property")
			if obj != nil && p != nil && (obj.Kind() == "array" || obj.Kind() == "string") && strings.Contains("|includes|indexOf|", "|"+p.Utf8Text(m.src)+"|") {
				return
			}
		}
		gaps = append(gaps, analysis.Gap{Kind: "http_hook_unresolved", Detail: "control calls an unavailable input helper: " + fn.Utf8Text(m.src), At: spanOf(m.file, call)})
	})
	return gaps
}
