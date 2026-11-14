package judge

import (
	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
)

func questionsFor(use analysis.CandidateUse) []question {
	if analysispacks.FamFamily(use.Kind) != nil {
		// Registered families own their question protocol through the embedded
		// claim components; material assembly validates the same names.
		switch use.Kind {
		case "sql_query_candidate":
			return componentQuestions(analysispacks.SQLQuestions())
		case "nosql_query_candidate":
			return componentQuestions(analysispacks.NoSQLQuestions())
		case "input_validation_candidate":
			return componentQuestions(analysispacks.ValidationQuestions())
		case "command_execution_candidate":
			return componentQuestions(analysispacks.CommandQuestions())
		case "path_traversal_candidate":
			return componentQuestions(analysispacks.PathQuestions())
		}
	}
	if use.Kind == "xss_candidate" {
		return xssQuestions
	}
	if logUse(use) {
		return logQuestions
	}
	return questions
}

func questionChoices(q question) []map[string]string {
	if q.name == "route_binding" {
		return discoveryChoices()
	}
	if c := analysispacks.ValidationChoices(q.name); c != nil {
		return c
	}
	if c := analysispacks.CommandChoices(q.name); c != nil {
		return c
	}
	if c := analysispacks.PathChoices(q.name); c != nil {
		return c
	}
	if c := xssChoices(q.name); c != nil {
		return c
	}
	if c := logChoices(q.name); c != nil {
		return c
	}
	if q.name == "injection_protection" {
		return analysispacks.InjectionChoices()
	}
	switch q.name {
	case "source_coverage", "library_coverage", "guard_coverage", "path_coverage", "all_paths_protected":
		return analysispacks.NoSQLCoverageChoices()
	}
	return choices
}
