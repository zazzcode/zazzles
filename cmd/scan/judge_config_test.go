package main

import (
	"strings"
	"testing"
)

func TestJudgeConfiguration(t *testing.T) {
	for _, tt := range []struct {
		name, provider, flag, env, want string
		bad                             bool
	}{
		{"gemini", "gemini", "", "gemini-decision-1", "gemini-decision-1", false},
		{"openai", "openai", "", "gpt-6-luna", "gpt-6-luna", false},
		{"default", "openai", "", "", "", false},
		{"explicit", "openai", "gpt-6-luna", "", "gpt-6-luna", false},
		{"matching", "gemini", "gemini-decision-1", "gemini-decision-1", "gemini-decision-1", false},
		{"provider mismatch", "openai", "", "gemini-decision-1", "", true},
		{"model mismatch", "openai", "gpt-other", "gpt-6-luna", "", true},
		{"comma models", "openai", "", "gpt-6-luna,gemini-decision-1", "", true},
		{"space models", "gemini", "", "gemini-decision-1 gpt-6-luna", "", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			values := map[string]string{"JUDGE_DECISION_MODEL": tt.env, "OPENAI_API_KEY": "openai-secret", "GEMINI_API_KEY": "gemini-secret", "TYPESAFE_API_KEY": "jev-secret"}
			model, key, err := judgeConfiguration(tt.provider, tt.flag, func(k string) string { return values[k] })
			if (err != nil) != tt.bad {
				t.Fatalf("error=%v", err)
			}
			if !tt.bad && (model != tt.want || key != tt.provider+"-secret") {
				t.Fatalf("wrong selection: model=%s", model)
			}
			if err != nil && strings.Contains(err.Error(), "secret") {
				t.Fatal("key leaked")
			}
		})
	}
	_, _, err := judgeConfiguration("gemini", "", func(k string) string {
		if k == "SCAN_OPENAI_MODEL" {
			return "gpt-6-luna"
		}
		return ""
	})
	if err == nil {
		t.Fatal("obsolete competing configuration accepted")
	}
}
