package judge

import (
	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
)

// predecessorNodeUse projects only the explicitly added Node source/type
// extension out of historical baseline checks. All prior evidence, identities,
// questions, guidelines and API contracts must retain their original bytes.
func predecessorNodeUse(u analysis.CandidateUse) analysis.CandidateUse {
	if u.InputFacts != nil {
		u.InputFacts = nil
		analysispacks.Attach(&u)
	}
	return u
}
