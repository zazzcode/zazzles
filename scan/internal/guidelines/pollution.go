package guidelines

// PollutionGuidelines gives the write claim its own JS/TS guidance.
func PollutionGuidelines() AnalysisGuidelines {
	return AnalysisGuidelines{
		ID: "pollution-javascript", Version: "1", Languages: []string{"javascript", "typescript"},
		Body: "Assess the key-bearing operand and its reach to a later write on Object.prototype. Use the recorded operation, version and key restrictions as scanner facts. A guard only counts at the levels and on the paths it covers. A null-prototype root does not prove that nested containers also lack a prototype. An unknown type, operation or guard remains unknown. Scope the judgment to the prototype write.",
	}
}
