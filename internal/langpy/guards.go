package langpy

import (
	"fmt"
	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
)

func pythonSourceKey(d analysis.Dependency) string {
	return fmt.Sprintf("%s:%s:%d:%s", d.Source.SHA256, d.Source.Span.File, d.Source.Span.StartByte, d.StorageKey)
}
func (f *pythonFlow) markGuard(n *sitter.Node, v pythonValue) {
	if n == nil || n.Kind() != "call" || len(v.deps) == 0 {
		return
	}
	unknown := false
	for _, g := range v.gaps {
		unknown = unknown || g.Kind == "python_call_unresolved" || g.Kind == "python_parameter_unresolved" || g.Kind == "work_limit"
	}
	if !unknown {
		return
	}
	f.context = append(f.context, f.module.evidence("unresolved_pre_use_call", n))
	for _, d := range v.deps {
		key := pythonSourceKey(d.dep)
		f.guards[key] = append(f.guards[key], f.gap("input_helper_unresolved", "A pre-use call receives this value; its enforcing or transforming effect is unmodeled", n))
	}
}
func (f *pythonFlow) guardGaps(v pythonValue) []analysis.Gap {
	var out []analysis.Gap
	seen := map[string]bool{}
	for _, d := range v.deps {
		for _, g := range f.guards[pythonSourceKey(d.dep)] {
			key := fmt.Sprintf("%s:%d:%s", g.At.File, g.At.StartByte, g.Kind)
			if !seen[key] {
				seen[key] = true
				out = append(out, g)
			}
		}
	}
	return out
}
func (f *pythonFlow) mergeGuards(b *pythonFlow) {
	for key, gaps := range b.guards {
		f.guards[key] = append(f.guards[key], gaps...)
	}
}
