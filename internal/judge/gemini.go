package judge

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"sort"

	"github.com/zazzcode/zazzles/internal/analysis"
)

// geminiResponse adapts Google's named answers and score maps to the existing
// decoder shape. Traces retain the original response, including modality usage.
func (c *Client) geminiResponse(data []byte) ([]byte, error) {
	var raw struct {
		Model   string          `json:"model"`
		Answers json.RawMessage `json:"answers"`
		Usage   struct {
			Input  int64 `json:"total_input_tokens"`
			Output int64 `json:"total_output_tokens"`
			Total  int64 `json:"total_tokens"`
		} `json:"usage"`
	}
	if json.Unmarshal(data, &raw) != nil {
		return nil, errors.New("invalid Gemini JSON")
	}
	if raw.Model != "" && raw.Model != c.model {
		return nil, errors.New("unexpected Gemini response model")
	}
	if raw.Usage.Input < 0 || raw.Usage.Output != 0 || raw.Usage.Total < 0 {
		return nil, errors.New("invalid Gemini usage")
	}
	dec := json.NewDecoder(bytes.NewReader(raw.Answers))
	token, err := dec.Token()
	if err != nil || token != json.Delim('{') {
		return nil, errors.New("invalid Gemini answers")
	}
	answers := map[string]any{}
	for dec.More() {
		token, err = dec.Token()
		name, ok := token.(string)
		if err != nil || !ok || answers[name] != nil {
			return nil, errors.New("duplicate or invalid Gemini answer")
		}
		var a struct {
			Type          string             `json:"type"`
			Choice        string             `json:"choice"`
			Confidence    *float64           `json:"confidence"`
			Probabilities map[string]float64 `json:"probabilities"`
		}
		if dec.Decode(&a) != nil {
			return nil, errors.New("invalid Gemini answer metadata")
		}
		if a.Confidence != nil && (*a.Confidence < 0 || *a.Confidence > 1) {
			return nil, errors.New("invalid Gemini confidence")
		}
		scores := []analysis.ChoiceProbability{}
		keys := make([]string, 0, len(a.Probabilities))
		for key := range a.Probabilities {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		total := 0.0
		for _, key := range keys {
			p := a.Probabilities[key]
			if p < 0 || p > 1 {
				return nil, errors.New("invalid Gemini probability")
			}
			total += p
			scores = append(scores, analysis.ChoiceProbability{Value: key, Probability: p})
		}
		if len(keys) > 0 && (math.Abs(total-1) > .02 || a.Probabilities[a.Choice] == 0) {
			return nil, errors.New("invalid Gemini probability distribution")
		}
		answers[name] = struct {
			Type string `json:"type"`
			analysis.AnswerDetail
		}{a.Type, analysis.AnswerDetail{Choice: a.Choice, Confidence: a.Confidence, Probabilities: scores}}
	}
	if _, err = dec.Token(); err != nil {
		return nil, errors.New("invalid Gemini answer object")
	}
	return json.Marshal(map[string]any{"model": c.model, "answers": answers, "usage": map[string]int64{"input_tokens": raw.Usage.Input, "output_tokens": raw.Usage.Output, "total_tokens": raw.Usage.Total}})
}

func (c *Client) decodeGemini(data []byte, expected []question) (map[string]string, string, map[string]int64, error) {
	normalized, err := c.geminiResponse(data)
	if err != nil {
		return nil, "", nil, err
	}
	decoder := *c
	decoder.provider = "jev"
	answers, model, usage, err := decoder.decodeQuestions(normalized, expected)
	if err != nil {
		return nil, "", nil, err
	}
	// Validate metadata here too, so discovery uses the same strict decoder.
	if _, err = answerDetails(normalized, answers, expected); err != nil {
		return nil, "", nil, err
	}
	var envelope struct {
		Usage map[string]int64 `json:"usage"`
	}
	if err = json.Unmarshal(normalized, &envelope); err != nil {
		return nil, "", nil, err
	}
	usage["total_tokens"] = envelope.Usage["total_tokens"]
	return answers, model, usage, nil
}

func (c *Client) answerDetails(data []byte, selected map[string]string, expected []question) (map[string]analysis.AnswerDetail, error) {
	if c.provider == "gemini" {
		var err error
		data, err = c.geminiResponse(data)
		if err != nil {
			return nil, err
		}
	}
	return answerDetails(data, selected, expected)
}
