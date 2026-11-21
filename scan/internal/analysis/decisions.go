package analysis

// AnswerDetail preserves provider-reported choice scores for audit. Scores are
// not calibrated correctness guarantees and never replace source evidence.
type AnswerDetail struct {
	Choice        string              `json:"choice"`
	Confidence    *float64            `json:"confidence,omitempty"`
	Probabilities []ChoiceProbability `json:"probabilities,omitempty"`
}

// ChoiceProbability is a provider-reported score for one answer option.
type ChoiceProbability struct {
	Value       string  `json:"value"`
	Probability float64 `json:"probability"`
}
