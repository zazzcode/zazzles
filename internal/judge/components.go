package judge

import (
	"crypto/sha256"
	"fmt"
	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
	"slices"
)

func componentQuestions(items []analysispacks.Question) []question {
	out := make([]question, 0, len(items))
	for _, q := range items {
		out = append(out, question{name: q.Name, instructions: q.Instructions})
	}
	return out
}

func requestDigest(use analysis.CandidateUse, payload []byte) string {
	if analysispacks.ProtocolFor(use.Kind) == "" {
		return ""
	}
	return fmt.Sprintf("%x", sha256.Sum256(payload))
}

func cloneComponents(s *analysis.ComponentSelection) *analysis.ComponentSelection {
	if s == nil {
		return nil
	}
	c := *s
	c.Components = slices.Clone(s.Components)
	c.Required = slices.Clone(s.Required)
	c.Limits = slices.Clone(s.Limits)
	return &c
}

// wireComponents keeps selection identity visible without sending replay digests.
func wireComponents(m *analysispacks.Material) any {
	if m == nil || m.Selection == nil {
		return nil
	}
	ids := make([]string, 0, len(m.Selection.Components))
	for _, c := range m.Selection.Components {
		ids = append(ids, c.ID)
	}
	return map[string]any{"pack": m.Selection.Pack.ID, "components": ids}
}

func interpreterComponentQuestions(family string) []question {
	items := analysispacks.CodeQuestions()
	if family == "redirect" {
		items = analysispacks.RedirectQuestions()
	}
	out := componentQuestions(items)
	for i := range out {
		out[i].choices = analysispacks.InterpreterChoices(family, out[i].name)
	}
	return out
}
