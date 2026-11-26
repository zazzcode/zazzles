package judge

import (
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
)

func questionsFor(use analysis.CandidateUse) []question {
	if documentOperation(use) {
		return documentQuestions()
	}
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
		case analysis.PollutionKind:
			items := componentQuestions(analysispacks.PollutionQuestions())
			for i := range items {
				items[i].choices = analysispacks.PollutionChoices(items[i].name)
			}
			return items
		case "code_execution_candidate", "template_injection_candidate":
			return interpreterComponentQuestions("code")
		case "open_redirect_candidate":
			return interpreterComponentQuestions("redirect")
		case analysis.DeserializationKind:
			return interpreterComponentQuestions("deserialization")
		case "file_upload_candidate":
			return interpreterComponentQuestions("upload")
		case "ssrf_candidate":
			return componentQuestions(analysispacks.SSRFQuestions())
		case analysis.ExposureKind:
			items := componentQuestions(analysispacks.ExposureQuestions())
			for i := range items {
				items[i].choices = analysispacks.ExposureChoices(items[i].name)
			}
			return items
		case analysis.MassAssignmentKind:
			items := componentQuestions(analysispacks.MassAssignmentQuestions())
			for i := range items {
				items[i].choices = analysispacks.MassAssignmentChoices(items[i].name)
			}
			return items
		case analysis.AccountEnumerationKind, analysis.RecoveryDeliveryKind, analysis.PasswordHashKind:
			items := componentQuestions(analysispacks.AccountKindQuestions(use.Kind))
			for i := range items {
				items[i].choices = analysispacks.AccountChoices(items[i].name)
			}
			return items
		case analysis.ConfigurationKind:
			items := componentQuestions(analysispacks.ConfigurationQuestions())
			for i := range items {
				items[i].choices = analysispacks.ConfigurationChoices(items[i].name)
			}
			return items
		case analysis.AuthorizationKind:
			items := componentQuestions(analysispacks.AuthorizationQuestions())
			for i := range items {
				items[i].choices = analysispacks.AuthorizationChoices(items[i].name)
			}
			return items
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
	if q.choices != nil {
		return q.choices
	}
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
	if c := analysispacks.SSRFChoices(q.name); c != nil {
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
