package parse

import (
	"fmt"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
)

func parameterNames(fn *sitter.Node, src []byte) []string {
	out := []string{}
	params := fn.ChildByFieldName("parameters")
	if params == nil {
		return out
	}
	for i := uint(0); i < params.NamedChildCount(); i++ {
		p := params.NamedChild(i)
		if p.Kind() == "required_parameter" || p.Kind() == "optional_parameter" {
			p = p.ChildByFieldName("pattern")
		}
		if p != nil && p.Kind() == "identifier" {
			out = append(out, p.Utf8Text(src))
		} else {
			out = append(out, "")
		}
	}
	return out
}

func readsInput(n *sitter.Node, src []byte, names map[string]bool, fields []string) bool {
	if n == nil {
		return false
	}
	if n.Kind() == "identifier" {
		return names[n.Utf8Text(src)]
	}
	if n.Kind() == "member_expression" {
		text := n.Utf8Text(src)
		// A request's different fields are separate dependencies. Whole-body access
		// remains relevant, while a password-only operation cannot validate email.
		for name := range names {
			if strings.HasPrefix(text, name+".body.") || strings.HasPrefix(text, name+".payload.") || strings.HasPrefix(text, name+".query.") {
				for _, field := range fields {
					if text == name+".body."+field || text == name+".query."+field || text == name+".payload."+field || strings.HasPrefix(text, name+".body."+field+".") {
						return true
					}
				}
				return false
			}
		}
	}
	for i := uint(0); i < n.NamedChildCount(); i++ {
		if readsInput(n.NamedChild(i), src, names, fields) {
			return true
		}
	}
	return false
}

func (s *moduleSet) inputHelpers(m *sourceModule, n *sitter.Node, out *[]analysis.Evidence, seen map[string]bool, depth int, names map[string]bool) {
	if n == nil {
		return
	}
	// Propagate simple local aliases for context selection, never as a safety fact.
	var aliases func(*sitter.Node)
	aliases = func(node *sitter.Node) {
		if node.Kind() == "variable_declarator" {
			id := node.ChildByFieldName("name")
			v := node.ChildByFieldName("value")
			if id != nil && id.Kind() == "identifier" && readsInput(v, m.src, names, s.contextFields) {
				names[id.Utf8Text(m.src)] = true
			}
		}
		for i := uint(0); i < node.NamedChildCount(); i++ {
			aliases(node.NamedChild(i))
		}
	}
	aliases(n)
	walkCalls(n, func(call *sitter.Node) {
		args := call.ChildByFieldName("arguments")
		fn := call.ChildByFieldName("function")
		if args == nil || fn == nil || !readsInput(args, m.src, names, s.contextFields) {
			return
		}
		if predicate := inputPredicateEvidence(m, call); len(predicate) > 0 {
			*out = append(*out, predicate...)
			return
		}
		target, helper := s.resolveCall(m, call)
		if target == nil || helper == nil {
			return
		}
		key := fmt.Sprintf("%s:%d", target.file, helper.StartByte())
		if seen[key] {
			return
		}
		if depth >= 3 || len(seen) >= 24 {
			s.contextLimits = append(s.contextLimits, analysis.Gap{Kind: "helper_context_limit", Detail: "checked-input helper expansion reached its depth/count limit", At: spanOf(target.file, helper)})
			return
		}
		seen[key] = true
		*out = append(*out, target.evidence("helper_definition", helper))
		bound := map[string]bool{}
		params := parameterNames(helper, target.src)
		for i := uint(0); i < args.NamedChildCount() && int(i) < len(params); i++ {
			arg := args.NamedChild(i)
			if isFunction(arg) {
				continue
			}
			if readsInput(arg, m.src, names, s.contextFields) && params[i] != "" {
				bound[params[i]] = true
			}
		}
		// Callback definitions are supplied, but their Boolean/side-effect result is
		// not a continuation of the original input string into every downstream call.
		if len(bound) > 0 {
			s.inputHelpers(target, helper, out, seen, depth+1, bound)
		}
	})
}
