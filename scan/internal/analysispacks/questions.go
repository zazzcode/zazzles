package analysispacks

import "strings"

// Question is scanner-authored interpretation content, independent of provider transport.
type Question struct {
	Name         string `json:"name"`
	Instructions string `json:"instructions"`
}

// claimMaterial is the embedded claim-questions payload: the exact question
// protocol and its choices for one family.
type claimMaterial struct {
	Questions []Question                     `json:"questions"`
	Choices   map[string][]map[string]string `json:"choices"`
}

func sqlQuestionNames() []string {
	return []string{"validation", "protection", "injection_protection"}
}

// BaseQuestions returns the shared validation/construction facets without implying injection.
func BaseQuestions() []Question {
	return []Question{
		{"validation", "Apply the supplied analysis guidelines. A missing check is insufficient. A type or length check is insufficient when a tighter check would still meet the business need. Free-text fields are not insufficient only because they allow any character. Do not infer validation from names, comments, or absent code. Unknown check behavior is uncertain."},
		{"protection", "Apply the supplied analysis guidelines to the sink. A query, update, or insert built from the string is insufficient. A bound parameter is sufficient for statement structure even when validation is weak. A type, length, or allow-list check does not repair string-built SQL or NoSQL. Unknown flow or missing library semantics is uncertain."},
	}
}

// InjectionInstructions is the shared SQL/NoSQL injection interpretation; it is the
// NoSQL claim question text, while SQLQuestions derives its SQL-scoped variant.
const InjectionInstructions = "Can request-controlled input change executable database query syntax or selector operators on a supported path? Choose vulnerable only when the supplied source, verified library contract and relevant guard/path evidence establish that property. Choose protected for verified separation (bound SQL data, constrained scalar selectors, or effective context-specific conversions/filters); poor construction practice alone is not injection. Choose unknown for missing source, API, guard or necessary path facts. Choose not_applicable only if this is not an injection-sensitive use. For protected, establish protection on ALL feasible input paths, not merely one branch. Evaluate every output alternative: a verified Number result or numeric literal cannot carry arbitrary input text into an expression; if all alternatives have that constraint, the conditional does not introduce a raw-text bypass. A Number conversion in one ternary branch does not constrain an unconverted sibling branch. Truncation or newline removal alone does not exclude query operators/calls; assess other alternatives without borrowing the numeric guarantee. A verified native hash digest with literal hex encoding returns only hexadecimal characters; trace whether EACH interpolated value is that output or an unconverted sibling. Hex output enclosed in fixed SQL string quotes cannot supply a quote or SQL delimiter, while a raw sibling may. This is independent of hash strength and the construction-practice answer. For a structured selector value, an enforcing early-return guard rejecting non-strings excludes operator objects on its continuing path; a string's contents are data, except in executable-expression slots such as $where. Check actual dominance, mutations, bypasses and all fields. Evaluate the actual operation and slot, not category labels or source comments."

// SQLQuestions returns the SQL claim and its independent validation/construction facets.
func SQLQuestions() []Question {
	out := BaseQuestions()
	out[1].Instructions = strings.ReplaceAll(out[1].Instructions, "SQL or NoSQL", "SQL")
	return append(out, Question{"injection_protection", "Can request-controlled input change executable database query syntax on a supported path? Choose vulnerable only when the supplied source, verified library contract and relevant guard/path evidence establish that property. Choose protected for verified separation (bound SQL data or effective context-specific conversions/filters); poor construction practice alone is not injection. Choose unknown for missing source, API, guard or necessary path facts. Choose not_applicable only if this is not an injection-sensitive use. For protected, establish protection on ALL feasible input paths, not merely one branch. Evaluate every output alternative: a verified Number result or numeric literal cannot carry arbitrary input text into an expression; if all alternatives have that constraint, the conditional does not introduce a raw-text bypass. A Number conversion in one ternary branch does not constrain an unconverted sibling branch. Truncation or newline removal alone does not exclude query operators/calls; assess other alternatives without borrowing the numeric guarantee. A verified native hash digest with literal hex encoding returns only hexadecimal characters; trace whether EACH interpolated value is that output or an unconverted sibling. Hex output enclosed in fixed SQL string quotes cannot supply a quote or SQL delimiter, while a raw sibling may. This is independent of hash strength and the construction-practice answer. Evaluate the actual operation and slot, not category labels or source comments."})
}

// PracticeChoices returns the unchanged choice protocol for shared practice facets.
func PracticeChoices() []map[string]string {
	return []map[string]string{
		{"value": "sufficient", "description": "The supplied evidence establishes adequate protection or validation for the named question and use."},
		{"value": "insufficient", "description": "The supplied evidence shows a relevant protection or validation gap for this use."},
		{"value": "uncertain", "description": "Evidence, binding, flow, sink requirements or relevant code is incomplete or ambiguous."},
		{"value": "not_applicable", "description": "The question does not apply to this use; this is not a general safety claim."},
	}
}

// InjectionChoices returns the claim-specific choice protocol used by SQL and NoSQL.
func InjectionChoices() []map[string]string {
	return []map[string]string{
		{"value": "vulnerable", "description": "The supplied source and verified operation model support input changing executable query syntax or selector operators on a relevant path."},
		{"value": "protected", "description": "The supplied evidence establishes that the relevant input remains data or is constrained so it cannot change syntax/operators for this operation."},
		{"value": "unknown", "description": "Required source, library, guard, transformation, or path evidence is missing or ambiguous."},
		{"value": "not_applicable", "description": "This operation has no applicable injection question."},
	}
}

// SQLInjectionChoices keeps SQL request descriptions scoped to executable SQL.
func SQLInjectionChoices() []map[string]string {
	out := InjectionChoices()
	for _, v := range out {
		v["description"] = strings.ReplaceAll(v["description"], " or selector operators", "")
		v["description"] = strings.ReplaceAll(v["description"], "syntax/operators", "syntax")
	}
	return out
}
