package judge

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
)

func xssClaim(protection string) analysis.CandidateUse {
	u := analysis.CandidateUse{Kind: "xss_candidate", XSS: &analysis.XSSFacts{Type: "reflected", OriginResolved: true, OutputContext: "html_text", Protection: protection},
		Sink: analysis.Evidence{Span: analysis.Span{File: "views/page.ejs"}}, Context: []analysis.Evidence{{Span: analysis.Span{File: "app.js"}}},
		APIModel: analysispacks.XSSContract("html-output-v1", "express"), Completeness: &analysis.Completeness{ClaimKind: "xss", Evidence: map[string][]analysis.Evidence{
			"render_source": {{Kind: "input_source"}}, "render_binding": {{Kind: "render_binding"}}, "render_context": {{Kind: "template_output"}},
		}}}
	analysispacks.Attach(&u)
	return u
}

func TestXSSPolicyEvidenceAndConsistency(t *testing.T) {
	for _, tt := range []struct{ name, protection, encoding, sanitizer, paths, verdict, want string }{
		{"raw exposure", "raw", "not_present", "absent", "no", "vulnerable", "confirmed_vulnerability"},
		{"encoding protection", "encoded", "adequate", "absent", "yes", "protected", "protected_for_claim"},
		{"sanitizer protection", "sanitized", "not_present", "effective", "yes", "protected", "protected_for_claim"},
		{"unknown transform", "unknown", "unknown", "unknown", "unknown", "vulnerable", "needs_evidence"},
		{"contradictory protection", "raw", "not_present", "absent", "yes", "protected", "needs_evidence"},
		{"contradictory exposure", "encoded", "adequate", "absent", "no", "vulnerable", "needs_evidence"},
		{"inconclusive", "raw", "unknown", "unknown", "unknown", "unknown", "needs_evidence"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			a := analysis.Assessment{Status: "completed", QuestionVersion: xssQuestionVersion, Answers: map[string]string{
				"output_context": "html_text", "encoding_adequacy": tt.encoding, "sanitizer_effectiveness": tt.sanitizer,
				"xss_all_paths_protected": tt.paths, "xss_exposure": tt.verdict}}
			applyPolicy(xssClaim(tt.protection), &a)
			if a.FindingStatus != tt.want {
				t.Fatalf("got %+v", a)
			}
		})
	}
	for _, missing := range []string{"render_source", "render_binding", "render_context", "protocol", "stored_origin"} {
		t.Run("missing "+missing, func(t *testing.T) {
			u := xssClaim("raw")
			a := analysis.Assessment{QuestionVersion: xssQuestionVersion, Answers: map[string]string{"output_context": "html_text", "encoding_adequacy": "not_present", "sanitizer_effectiveness": "absent", "xss_all_paths_protected": "no", "xss_exposure": "vulnerable"}}
			switch missing {
			case "protocol":
				a.QuestionVersion = questionVersion
			case "stored_origin":
				u.XSS.Type, u.XSS.OriginResolved = "stored", false
			default:
				delete(u.Completeness.Evidence, missing)
			}
			applyPolicy(u, &a)
			if a.FindingStatus != "needs_evidence" || len(a.BlockingGaps) == 0 {
				t.Fatalf("missing evidence did not block: %+v", a)
			}
		})
	}
}

func TestXSSPayloadAndTypedAnswers(t *testing.T) {
	use := xssClaim("raw")
	for _, provider := range []string{"openai", "jev"} {
		c, _ := New(provider, "fixture-model", "fixture-key")
		payload, err := c.payload(use)
		if err != nil || !strings.Contains(string(payload), "encoding_adequacy") || !strings.Contains(string(payload), "sanitizer_effectiveness") || !strings.Contains(string(payload), "xss_exposure") || !strings.Contains(string(payload), "## Cross-site scripting") {
			t.Fatalf("XSS protocol/guidelines missing: %s %v", payload, err)
		}
	}
	c, _ := New("openai", "fixture-model", "fixture-key")
	answers := []answer{{"choice", "output_context", "html_text"}, {"choice", "encoding_adequacy", "not_present"}, {"choice", "sanitizer_effectiveness", "absent"}, {"choice", "xss_all_paths_protected", "no"}, {"choice", "xss_exposure", "vulnerable"}}
	for _, invalid := range []bool{false, true} {
		if invalid {
			answers[4].Choice = "insufficient"
		}
		data, _ := json.Marshal(map[string]any{"model": "fixture-model", "answers": answers})
		_, _, _, err := c.decodeQuestions(data, questionsFor(use))
		if (err != nil) != invalid {
			t.Fatalf("invalid=%v err=%v", invalid, err)
		}
	}
}
