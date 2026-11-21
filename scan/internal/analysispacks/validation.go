package analysispacks

func validationQuestionNames() []string {
	return []string{"field_requirement", "validation", "enforcement_coverage"}
}

// ValidationQuestions returns the standalone field-policy protocol: an
// explicit requirement, enforcement against that exact policy, and coverage.
// It asks no database API, sensitive-sink or query-protection question.
func ValidationQuestions() []Question {
	return []Question{
		{"field_requirement", "Does the supplied source or explicit requirement establish a concrete policy for the named field? established requires actual policy evidence, not a field name or a preference for stricter validation. Client-side form constraints establish intended policy but do not prove server enforcement."},
		{"validation", "Assess ONLY the complete enumerated constraints in declared_requirement.validation and the named field_policy role. Do not expand the policy from other fields, security preferences, or unrelated handler code. A required-only field with a rejecting missing/empty guard is sufficient even if stronger validation would be desirable. On the supplied source-to-use path, does server-side enforcement meet this precise field policy? sufficient requires the condition/helper and enforced rejection on every relevant path; insufficient requires a supported path bypassing or lacking the established requirement; uncertain requires missing relevant code or semantics. Do not confuse parameter binding or HTML escaping with field validation."},
		{"enforcement_coverage", "Is enough relevant server implementation present and structurally linked to assess enforcement? complete requires the actual guards/helpers, branch/return behavior and downstream constraints that can enforce this requirement; incomplete means a required definition, dispatch, model constraint or path is missing. Source comments and benchmark descriptions are not evidence of an expected answer."},
	}
}

// ValidationChoices returns the choice protocol for one field-policy question.
func ValidationChoices(name string) []map[string]string {
	switch name {
	case "field_requirement":
		return []map[string]string{{"value": "established", "description": "A concrete field policy is source-backed or explicitly supplied."}, {"value": "unknown", "description": "No concrete applicable requirement is established."}, {"value": "not_applicable", "description": "This use has no applicable field requirement."}}
	case "validation":
		return PracticeChoices()
	case "enforcement_coverage":
		return []map[string]string{{"value": "complete", "description": "Required implementation and path evidence are supplied."}, {"value": "incomplete", "description": "A required definition or path fact is missing."}}
	}
	return nil
}
