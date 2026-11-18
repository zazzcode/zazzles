package parse

import (
	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
)

// assemblePathClaims completes every Node path candidate before catalog attachment.
func (s *moduleSet) assemblePathClaims(report *analysis.AnalysisReport) {
	info := newPathGuardInfo()
	s.assembleClaims(report, claimHooks{
		kind:            "path_traversal_candidate",
		checkID:         "automatic-path",
		checkKind:       "path_traversal",
		chainEvidence:   s.pathChainEvidence,
		present:         func(u *analysis.CandidateUse) bool { return u.Path != nil },
		fields:          commandFields,
		guards:          s.pathGuards(info),
		gapCovered:      s.pathGapCovered,
		chainGapCovered: s.pathModeledGap,
		complete:        pathCompleteness,
		finish: func(u *analysis.CandidateUse, c *analysis.Completeness, guards []analysis.Evidence, guardIndex []int) {
			finishPathFlows(u, c, guards, guardIndex, info, func(g analysis.Gap, d analysis.Dependency) bool { return gapTouchesDependency(g, d) })
		},
		contract: func(u *analysis.CandidateUse) *analysis.APIModel {
			return analysispacks.PathContract(u.Path.ContractID)
		},
	})
}
