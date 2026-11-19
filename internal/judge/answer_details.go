package judge

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/zazzcode/zazzles/internal/analysis"
)

func answerDetails(data []byte, selected map[string]string, expected []question) (map[string]analysis.AnswerDetail, error) {
	var envelope struct {
		Answers json.RawMessage `json:"answers"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, err
	}
	type scored struct {
		Name string `json:"name"`
		analysis.AnswerDetail
	}
	var list []scored
	if len(envelope.Answers) > 0 && envelope.Answers[0] == '[' {
		if err := json.Unmarshal(envelope.Answers, &list); err != nil {
			return nil, err
		}
	} else {
		var byName map[string]analysis.AnswerDetail
		if err := json.Unmarshal(envelope.Answers, &byName); err != nil {
			return nil, err
		}
		for name, detail := range byName {
			list = append(list, scored{Name: name, AnswerDetail: detail})
		}
	}
	allowed := map[string]map[string]bool{}
	for _, q := range expected {
		allowed[q.name] = map[string]bool{}
		for _, choice := range questionChoices(q) {
			allowed[q.name][choice["value"]] = true
		}
	}
	out := map[string]analysis.AnswerDetail{}
	for _, answer := range list {
		if strings.HasPrefix(answer.Name, resolvePrefix) {
			continue // resolution answers are recorded as Resolutions
		}
		if answer.Confidence == nil && len(answer.Probabilities) == 0 {
			continue
		}
		if answer.Choice != selected[answer.Name] || (answer.Confidence != nil && (*answer.Confidence < 0 || *answer.Confidence > 1)) {
			return nil, errors.New("invalid decision confidence metadata")
		}
		seen := map[string]bool{}
		for _, score := range answer.Probabilities {
			if !allowed[answer.Name][score.Value] || score.Probability < 0 || score.Probability > 1 || seen[score.Value] {
				return nil, errors.New("invalid decision probability metadata")
			}
			seen[score.Value] = true
		}
		out[answer.Name] = answer.AnswerDetail
	}
	return out, nil
}
