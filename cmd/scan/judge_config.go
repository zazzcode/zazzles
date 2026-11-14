package main

import (
	"fmt"
	"strings"
)

// judgeConfiguration resolves one scan-wide model without letting credentials
// select a provider or enable network requests.
func judgeConfiguration(provider, model string, getenv func(string) string) (string, string, error) {
	for _, name := range []string{"SCAN_OPENAI_MODEL", "SCAN_GEMINI_MODEL", "SCAN_JEV_MODEL"} {
		if strings.TrimSpace(getenv(name)) != "" {
			return "", "", fmt.Errorf("use only JUDGE_DECISION_MODEL; unset obsolete provider-specific model settings")
		}
	}
	configured := strings.TrimSpace(getenv("JUDGE_DECISION_MODEL"))
	if configured != "" {
		if model != "" && model != configured {
			return "", "", fmt.Errorf("--judge-model conflicts with JUDGE_DECISION_MODEL; configure exactly one model")
		}
		model = configured
	}
	if len(strings.Fields(model)) > 1 || strings.ContainsAny(model, ",;") {
		return "", "", fmt.Errorf("configure exactly one judge model, not a list")
	}
	if (strings.HasPrefix(model, "gemini-") && provider != "gemini") || (strings.HasPrefix(model, "gpt-") && provider != "openai") {
		return "", "", fmt.Errorf("--judge provider conflicts with selected model")
	}
	keyVar := ""
	switch provider {
	case "openai":
		keyVar = "OPENAI_API_KEY"
	case "gemini":
		keyVar = "GEMINI_API_KEY"
	case "jev":
		keyVar = "TYPESAFE_API_KEY"
	}
	key := ""
	if keyVar != "" {
		key = getenv(keyVar)
	}
	return model, key, nil
}
