package judge

import (
	"encoding/json"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"strings"
	"testing"
)

func TestInjectionPolicySeparatesPracticeAndActualProtection(t *testing.T) {
	for _, tt := range []struct {
		injection, practice, want string
		missing, block            bool
	}{
		{"vulnerable", "insufficient", "confirmed_vulnerability", false, false},
		{"protected", "insufficient", "protected_for_claim", false, false},
		{"unknown", "insufficient", "needs_evidence", false, false},
		{"", "insufficient", "needs_evidence", false, false},
		{"vulnerable", "insufficient", "needs_evidence", true, false},
		{"vulnerable", "insufficient", "needs_evidence", false, true},
	} {
		c := &analysis.Completeness{ClaimKind: "injection", Required: []string{"input_source", "sink_binding", "control_flow"}, Evidence: map[string][]analysis.Evidence{"input_source": {{Text: "request value"}}, "sink_binding": {{Text: "verified API"}}, "control_flow": {{Text: "guard/path context"}}, "invoked_callable": {{Text: "handler"}}}}
		if tt.missing {
			delete(c.Evidence, "sink_binding")
		}
		if tt.block {
			c.Blockers = []analysis.Gap{{Kind: "unknown_guard"}}
		}
		a := analysis.Assessment{Status: "completed", Answers: map[string]string{"injection_protection": tt.injection, "protection": tt.practice}}
		applyPolicy(analysis.CandidateUse{Completeness: c, APIModel: &analysis.APIModel{ID: "test-contract"}}, &a)
		if a.FindingStatus != tt.want {
			t.Fatalf("case=%+v result=%+v", tt, a)
		}
	}
}

func TestInjectionQuestionAndStrictDecoding(t *testing.T) {
	u := selectedSQLUse(t)
	c, _ := New("openai", "test-model", "test-key")
	payload, err := c.payload(u)
	if err != nil {
		t.Fatal(err)
	}
	var request struct {
		Questions []struct {
			Name         string `json:"name"`
			Instructions string `json:"instructions"`
		} `json:"questions"`
	}
	if err := json.Unmarshal(payload, &request); err != nil {
		t.Fatal(err)
	}
	if len(request.Questions) != 3 || request.Questions[2].Name != "injection_protection" || !strings.Contains(request.Questions[2].Instructions, "poor construction practice alone is not injection") {
		t.Fatalf("questions=%+v", request.Questions)
	}
	good := `{"model":"test-model","answers":[{"name":"validation","type":"choice","choice":"uncertain"},{"name":"protection","type":"choice","choice":"insufficient"},{"name":"injection_protection","type":"choice","choice":"protected"}]}`
	if _, _, _, err := c.decodeQuestions([]byte(good), questionsFor(u)); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{strings.Replace(good, `injection_protection`, `protection`, 1), strings.Replace(good, `sufficient`, `safe`, 1)} {
		if _, _, _, err := c.decodeQuestions([]byte(bad), questionsFor(u)); err == nil {
			t.Fatal("invalid injection answer accepted")
		}
	}
	if _, _, _, err := c.decodeQuestions([]byte(good), questions); err == nil {
		t.Fatal("unexpected query answer accepted for legacy non-query request")
	}
}

func TestNoSQLAllPathProtectionGate(t *testing.T) {
	for _, tt := range []struct{ answer, all, want string }{
		{"vulnerable", "no", "confirmed_vulnerability"}, {"vulnerable", "yes", "needs_evidence"}, {"protected", "yes", "protected_for_claim"}, {"protected", "unknown", "needs_evidence"}, {"protected", "no", "needs_evidence"},
	} {
		use := analysis.CandidateUse{Kind: "nosql_query_candidate", APIModel: &analysis.APIModel{ID: "marsdb-collection-v1"}, Completeness: &analysis.Completeness{ClaimKind: "injection", Evidence: map[string][]analysis.Evidence{"input_source": {{Text: "value"}}, "sink_binding": {{Text: "binding"}}, "invoked_callable": {{Text: "handler"}}, "control_flow": {{Text: "paths"}}}}}
		a := analysis.Assessment{Status: "completed", Answers: map[string]string{"protection": "insufficient", "injection_protection": tt.answer, "all_paths_protected": tt.all, "source_coverage": "yes", "library_coverage": "yes", "guard_coverage": "yes", "path_coverage": "yes"}}
		applyPolicy(use, &a)
		if a.FindingStatus != tt.want {
			t.Fatalf("%+v -> %+v", tt, a)
		}
	}
}
