package langjs

import (
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
	"github.com/zazzcode/zazzles/scan/internal/parse"
)

// assemblePathClaims completes every Node path candidate before catalog attachment.
func (s *moduleSet) assemblePathClaims(report *analysis.AnalysisReport) {
	info := parse.NewPathGuardInfo()
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
		complete:        parse.PathCompleteness,
		finish: func(u *analysis.CandidateUse, c *analysis.Completeness, guards []analysis.Evidence, guardIndex []int) {
			parse.FinishPathFlows(u, c, guards, guardIndex, info, func(g analysis.Gap, d analysis.Dependency) bool { return parse.GapTouchesDependency(g, d) })
		},
		contract: func(u *analysis.CandidateUse) *analysis.APIModel {
			return analysispacks.PathContract(u.Path.ContractID)
		},
	})
}
