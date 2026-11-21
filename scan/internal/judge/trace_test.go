package judge

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestSavedDecisionReplayRequiresIdenticalEvidenceAndRetainsScores(t *testing.T) {
	c, _ := New("openai", "fixture-model", "never-persist-fixture-token")
	u := xssClaim("raw")
	trace, err := c.Preview(u)
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]string{"output_context": "html_text", "encoding_adequacy": "not_present", "sanitizer_effectiveness": "absent", "xss_all_paths_protected": "no", "xss_exposure": "vulnerable"}
	var answers []map[string]any
	for _, q := range questionsFor(u) {
		answers = append(answers, map[string]any{"name": q.name, "type": "choice", "choice": values[q.name], "confidence": 0.9, "probabilities": []map[string]any{{"value": values[q.name], "probability": 0.95}}})
	}
	trace.HTTPStatus = 200
	trace.Response, _ = json.Marshal(map[string]any{"model": "fixture-model", "answers": answers})
	var indented bytes.Buffer
	if err := json.Indent(&indented, trace.Request, "", "  "); err != nil {
		t.Fatal(err)
	}
	trace.Request = indented.Bytes()
	a := c.Replay(u, trace)
	if a.Status != "completed" || a.FindingStatus != "confirmed_vulnerability" || len(a.AnswerDetails) != 5 || a.AnswerDetails["xss_exposure"].Confidence == nil {
		t.Fatalf("lost response details: %+v", a)
	}
	encoded, _ := json.Marshal(trace)
	if strings.Contains(string(encoded), "never-persist-fixture-token") {
		t.Fatal("trace includes authentication")
	}
	// Keep source and claim protocol identical while changing the supplied
	// guidelines. Neither a changed document nor the old envelope may replay.
	for _, change := range []string{"body", "key"} {
		old := trace
		var request map[string]json.RawMessage
		if err := json.Unmarshal(trace.Request, &request); err != nil {
			t.Fatal(err)
		}
		var input string
		if err := json.Unmarshal(request["input"], &input); err != nil {
			t.Fatal(err)
		}
		changed := ""
		if change == "body" {
			changed = strings.Replace(input, "## Cross-site scripting", "# historical guideline text", 1)
		} else {
			changed = strings.Replace(input, `"analysis_guidelines":`, `"practice":`, 1)
		}
		if changed == input {
			t.Fatal("test did not change guideline input")
		}
		request["input"], _ = json.Marshal(changed)
		old.Request, _ = json.Marshal(request)
		if got := c.Replay(u, old); got.Status != "failed" {
			t.Fatalf("reused decision with changed guidelines %s: %+v", change, got)
		}
	}
	u.Sink.Text = "changed evidence"
	if a := c.Replay(u, trace); a.Status != "failed" {
		t.Fatal("reused a decision on changed source evidence")
	}
	trace.QuestionVersion = "old-protocol"
	if a := c.Replay(xssClaim("raw"), trace); a.Status != "failed" {
		t.Fatal("reused a different protocol")
	}
}

func TestInvalidDecisionScoresAreRejected(t *testing.T) {
	q := []question{{name: "xss_exposure"}}
	for _, body := range []string{
		`{"answers":[{"name":"xss_exposure","choice":"unknown","confidence":2}]}`,
		`{"answers":[{"name":"xss_exposure","choice":"unknown","probabilities":[{"value":"made_up","probability":0.5}]}]}`,
	} {
		if _, err := answerDetails([]byte(body), map[string]string{"xss_exposure": "unknown"}, q); err == nil {
			t.Fatal("invalid provider metadata accepted")
		}
	}
}
