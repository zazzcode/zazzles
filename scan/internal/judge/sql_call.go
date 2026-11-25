package judge

import (
	"fmt"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
)

// SQLCallQuestionVersion versions the package-call question. It is asked only on
// a record whose operation has no written contract, so no other record's
// request or protocol changes.
const SQLCallQuestionVersion = "sql-call-v1"

const (
	sqlCallPrefix      = resolvePrefix + "sqlcall_"
	sqlCallBlocker     = "sink_binding_unverified"
	packageImportKind  = "package_import"
	sqlBindingEvidence = "sink_binding"
)

// SQLCallChoices is the answer protocol of a package-call question.
func SQLCallChoices() []map[string]string {
	return []map[string]string{
		{"value": "executes", "description": "The package sends this argument to a database as SQL text and runs it."},
		{"value": "prepares_then_executes", "description": "The package compiles this argument as SQL text for a statement that is run later, or marks it as raw SQL text inside a query it runs."},
		{"value": "bound_only", "description": "The package receives this argument only as a bound value, never as SQL text."},
		{"value": "not_sql", "description": "The package does not treat this argument as SQL for a database: it logs, sends, stores, formats or searches text."},
		{"value": "cannot_tell", "description": "The import and the call do not show what the package does with this argument."},
	}
}

// packageSQL reports a SQL record on a package call with no written contract.
func packageSQL(u analysis.CandidateUse) bool {
	return u.Kind == "sql_query_candidate" && u.APIModel != nil && u.APIModel.ID == analysispacks.PackageSQLContract
}

// sqlCallAskable reports a package record whose binding starts at an import.
func sqlCallAskable(u analysis.CandidateUse) bool {
	return packageSQL(u) && u.Completeness != nil && len(u.Completeness.Evidence[sqlBindingEvidence]) > 1
}

// sqlCallAsk plans the package-call question for blocker g. Its citation offers
// the sink file's package imports, the callee's own and the others, each with
// the call.
func sqlCallAsk(u analysis.CandidateUse, x *wireIndex, g analysis.Gap, id string) resolutionAsk {
	blocker := g
	choices := []map[string]string{}
	for i := 0; i < len(x.evidence) && len(choices) < maxCiteChoices; i++ {
		eid := fmt.Sprintf("e%d", i)
		e := x.evidence[eid]
		if e.kind == packageImportKind || e.kind == sqlBindingEvidence && sameItem(e, u.Completeness.Evidence[sqlBindingEvidence][0]) {
			choices = append(choices, chainChoice(x, []string{eid, x.sink}))
		}
	}
	choices = append(choices, noneChoice("You answered cannot_tell, or no offered import is the one the callee comes from."))
	name := sqlCallPrefix + id
	answer := question{name: name, choices: SQLCallChoices(), instructions: fmt.Sprintf("Gap %s: the scanner has no written contract for the package this call belongs to. The dependencies in slot sql_text name the argument that carries a string built from request data. Using the import, the way the callee's value is made from it, and the call, say what the package does with that argument. Judge the documented behavior of that package's operation, not the method or variable name and not the text's appearance. Choose cannot_tell when you do not know the operation.", id)}
	return resolutionAsk{name: name, version: SQLCallQuestionVersion, gap: id, blocker: &blocker, answer: &answer,
		cite: question{name: name + citeSuffix, choices: choices, instructions: fmt.Sprintf("Cite the package import that the callee in %s comes from, with the call. Choose none when you answered cannot_tell.", name)}}
}

func sameItem(w wireItem, e analysis.Evidence) bool {
	return w.file == e.Span.File && w.start == e.Span.StartLine && w.end == e.Span.EndLine
}

// verifySQLCallCitation checks that the cited import is the callee's binding and
// that the chain ends at this record's call.
func verifySQLCallCitation(u analysis.CandidateUse, x *wireIndex, cite []string, answer string) ([]analysis.Span, string) {
	if len(cite) != 2 || cite[1] != x.sink {
		return nil, "a package-call citation names one import and this record's call"
	}
	imp, ok := x.evidence[cite[0]]
	sink, found := x.evidence[x.sink]
	if !ok || !found {
		return nil, "cited ID " + cite[0] + " was not in the request"
	}
	spans := []analysis.Span{imp.span(), sink.span()}
	if !sqlCallAskable(u) || !sameItem(imp, u.Completeness.Evidence[sqlBindingEvidence][0]) {
		return spans, "cited import " + cite[0] + " is not the callee's binding"
	}
	if answer == "bound_only" {
		return spans, "bound_only needs a tagged template or a values argument; the recorded argument is the constructed text"
	}
	return spans, ""
}

// dischargeSQLCall removes the binding blocker of a package record whose
// verified answer is that the argument runs as SQL text.
func dischargeSQLCall(u analysis.CandidateUse, a *analysis.Assessment, blockers []analysis.Gap) (remaining, discharged []analysis.Gap) {
	if !packageSQL(u) {
		return blockers, nil
	}
	for _, g := range blockers {
		resolved := false
		for i := range a.Resolutions {
			r := &a.Resolutions[i]
			if g.Kind == sqlCallBlocker && r.QuestionVersion == SQLCallQuestionVersion && r.Verified && r.Blocker != nil && *r.Blocker == g &&
				(r.Answer == "executes" || r.Answer == "prepares_then_executes") {
				r.Discharged, resolved = true, true
			}
		}
		if resolved {
			discharged = append(discharged, g)
		} else {
			remaining = append(remaining, g)
		}
	}
	return remaining, discharged
}
