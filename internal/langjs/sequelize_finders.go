package langjs

import (
	"strings"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/parse"
)

// sequelizeFinderBinding verifies a finder call (Model.findAll and the like) on a
// class that extends the sequelize Model, resolved through the same model
// identity the storage analysis uses. It returns nil for any other receiver.
func (s *moduleSet) sequelizeFinderBinding(use analysis.CandidateUse) []analysis.Evidence {
	m := s.modules[use.Sink.Span.File]
	if m == nil {
		return nil
	}
	call := parse.NodeAt(m.tree.RootNode(), use.Sink.Span.StartByte, use.Sink.Span.EndByte)
	if call == nil {
		return nil
	}
	fn := call.ChildByFieldName("function")
	if fn == nil || fn.Kind() != "member_expression" || !sequelizeFinderName(fn.Utf8Text(m.src)) {
		return nil
	}
	obj := fn.ChildByFieldName("object")
	if obj == nil || obj.Kind() != "identifier" || shadowed(call, obj.Utf8Text(m.src), m.src) {
		return nil
	}
	id := s.modelIdentity(m, obj.Utf8Text(m.src), 0)
	if !strings.HasPrefix(id, "sequelize:") {
		return nil
	}
	binding := append([]analysis.Evidence{}, s.modelEvidence[id]...)
	for i := range binding {
		binding[i].Kind = "sink_binding"
	}
	return append(binding, m.evidence("sink_binding", fn))
}
