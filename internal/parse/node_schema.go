package parse

import (
	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
)

// schemaContext resolves source-present schema references and custom validators.
// Unknown library implementations are not made complete by a familiar name.
func (s *moduleSet) schemaContext(m *sourceModule, n *sitter.Node, depth int) ([]analysis.Evidence, []analysis.Gap) {
	if n == nil {
		return nil, nil
	}
	if depth > 6 {
		return nil, []analysis.Gap{{Kind: "http_schema_unresolved", Detail: "schema reference depth exceeded", At: spanOf(m.file, n)}}
	}
	out := []analysis.Evidence{}
	gaps := []analysis.Gap{}
	switch n.Kind() {
	case "string", "number", "true", "false", "null":
		return out, gaps
	case "object", "array":
		for i := uint(0); i < n.NamedChildCount(); i++ {
			v := n.NamedChild(i)
			if v.Kind() == "comment" {
				continue
			}
			if v.Kind() == "pair" {
				v = v.ChildByFieldName("value")
			}
			more, missing := s.schemaContext(m, v, depth+1)
			out = append(out, more...)
			gaps = append(gaps, missing...)
		}
		return out, gaps
	case "identifier":
		if def := topVariable(m, n.Utf8Text(m.src)); def != nil && contractBindingStable(m, n.Utf8Text(m.src)) {
			out = append(out, m.evidence("http_schema", def))
			more, missing := s.schemaContext(m, def, depth+1)
			return append(out, more...), missing
		}
	}
	hm, body, _, missing := s.handler(m, n)
	if body != nil && len(missing) == 0 {
		out = append(out, hm.evidence("http_hook", body))
		seen := map[string]bool{}
		s.includeHelpers(hm, body, &out, seen, 0)
		gaps = append(gaps, s.nodeControlHelperGaps(hm, body, parameterNames(body.Parent(), hm.src), 0)...)
		return out, gaps
	}
	gaps = append(gaps, analysis.Gap{Kind: "http_schema_unresolved", Detail: "custom schema/validator implementation is not supplied", At: spanOf(m.file, n)})
	return out, gaps
}
