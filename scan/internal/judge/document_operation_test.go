package judge

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
)

func documentUse() analysis.CandidateUse {
	ev := func(kind, file, text string, line int) analysis.Evidence {
		return analysis.Evidence{Kind: kind, Text: text, Span: analysis.Span{File: file, StartLine: line, EndLine: line, StartByte: line * 100, EndByte: line*100 + len(text)}}
	}
	sink := ev("nosql_query_candidate", "app.js", "users.findOne({ name })", 9)
	return analysis.CandidateUse{
		Kind: "nosql_query_candidate", Sink: sink, APIModel: analysispacks.NoSQLContract(analysispacks.MongoDBDocumentContract),
		InputFacts:   &analysis.InputFacts{Framework: "nextjs-pages"},
		Dependencies: []analysis.Dependency{{Source: ev("input_source", "app.js", "req.body.name", 7)}},
		Context:      []analysis.Evidence{ev("handler", "app.js", "{ const name = req.body.name; return users.findOne({ name }) }", 6), ev("authorization_context", "lib.js", "if (!ok) return", 2)},
		Completeness: &analysis.Completeness{ClaimKind: "injection", Evidence: map[string][]analysis.Evidence{"sink_binding": {
			ev("sink_binding", "db.js", "import { MongoClient } from 'mongodb'", 1), ev("sink_binding", "db.js", "users = new MongoClient(u).db().collection('users')", 2), sink}}},
	}
}

// TestDocumentOperationRequest keeps the request of a database package operation
// small: its own task and two questions, and none of the general NoSQL text.
func TestDocumentOperationRequest(t *testing.T) {
	c, err := New("openai", "gpt-6-luna", "offline-no-key")
	if err != nil {
		t.Fatal(err)
	}
	use := documentUse()
	payload, err := c.payloadForm(use, true)
	if err != nil {
		t.Fatal(err)
	}
	var request struct {
		Input     string `json:"input"`
		Questions []struct {
			Name string `json:"name"`
		} `json:"questions"`
	}
	if err := json.Unmarshal(payload, &request); err != nil {
		t.Fatal(err)
	}
	if len(request.Questions) != 2 || request.Questions[0].Name != "operation" || request.Questions[1].Name != "request_control" {
		t.Fatalf("questions: %+v", request.Questions)
	}
	var input map[string]json.RawMessage
	if err := json.Unmarshal([]byte(request.Input), &input); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"task", "query_language", "entry", "call", "receiver_path", "request_values", "source"} {
		if len(input[field]) == 0 {
			t.Errorf("request has no %s", field)
		}
	}
	if len(input) != 7 {
		t.Errorf("request has %d fields, want 7", len(input))
	}
	for _, absent := range []string{"analysis_guidelines", "compact_wire", "authorization_context", "if (!ok) return"} {
		if strings.Contains(request.Input, absent) {
			t.Errorf("request contains %q", absent)
		}
	}
	if protocolVersion(use) != analysispacks.DocumentOperationProtocol {
		t.Errorf("protocol %q", protocolVersion(use))
	}
	// Another contract of the family keeps the family's own protocol.
	other := use
	other.APIModel = analysispacks.NoSQLContract("marsdb-collection-v1")
	if protocolVersion(other) == analysispacks.DocumentOperationProtocol || len(questionsFor(other)) == 2 {
		t.Error("the protocol is selected for a record of another contract")
	}
}

// TestDocumentOperationPolicy: a request control is a finding; protected needs a
// strong data_only answer and no reading limit left to the model.
func TestDocumentOperationPolicy(t *testing.T) {
	limit := []analysis.Gap{{Kind: "unsupported_callback"}}
	for _, tt := range []struct {
		name, operation, control string
		dataOnly                 float64
		judged, blockers         []analysis.Gap
		want, injection          string
	}{
		{"operator", "database_query", "operator", 0.1, nil, nil, "confirmed_vulnerability", "vulnerable"},
		{"operator with a reading limit", "database_query", "operator", 0.1, limit, nil, "confirmed_vulnerability", "vulnerable"},
		{"written fields of a stored document", "stores_document", "written_fields", 0.1, nil, nil, "confirmed_vulnerability", "vulnerable"},
		{"strong data only", "database_query", "data_only", 0.97, nil, nil, "protected_for_claim", "protected"},
		{"weak data only", "database_query", "data_only", 0.9, nil, nil, "needs_evidence", "unknown"},
		{"data only with a reading limit", "database_query", "data_only", 0.99, limit, nil, "needs_evidence", "unknown"},
		{"cannot tell", "database_query", "cannot_tell", 0, nil, nil, "needs_evidence", "unknown"},
		{"not a database operation", "not_database_operation", "operator", 0, nil, nil, "not_applicable", "not_applicable"},
		{"stored data", "stores_document", "data_only", 0.99, nil, nil, "not_applicable", "not_applicable"},
		{"entry not established", "database_query", "operator", 0, nil, []analysis.Gap{{Kind: "unresolved_wrapper"}}, "needs_evidence", "unknown"},
	} {
		use := documentUse()
		use.Completeness.Judged, use.Completeness.Blockers = tt.judged, tt.blockers
		a := analysis.Assessment{Status: "completed", Answers: map[string]string{"operation": tt.operation, "request_control": tt.control},
			AnswerDetails: map[string]analysis.AnswerDetail{"request_control": {Choice: tt.control, Probabilities: []analysis.ChoiceProbability{{Value: "data_only", Probability: tt.dataOnly}}}}}
		applyPolicy(use, &a)
		if a.FindingStatus != tt.want || a.Answers["injection_protection"] != tt.injection {
			t.Errorf("%s: %s, injection %s; want %s, %s", tt.name, a.FindingStatus, a.Answers["injection_protection"], tt.want, tt.injection)
		}
	}
}

// TestDocumentOperationRequestGemini builds the same two questions for the
// Gemini adapter, which names them in a map.
func TestDocumentOperationRequestGemini(t *testing.T) {
	c, err := New("gemini", "gemini-decision-1", "offline-no-key")
	if err != nil {
		t.Fatal(err)
	}
	payload, err := c.payloadForm(documentUse(), true)
	if err != nil {
		t.Fatal(err)
	}
	var request struct {
		Input     string `json:"input"`
		Questions map[string]struct {
			Criteria map[string]string `json:"criteria"`
		} `json:"questions"`
	}
	if err := json.Unmarshal(payload, &request); err != nil {
		t.Fatal(err)
	}
	if len(request.Questions) != 2 || len(request.Questions["operation"].Criteria) != 4 || len(request.Questions["request_control"].Criteria) != 7 {
		t.Fatalf("questions: %+v", request.Questions)
	}
	if !strings.Contains(request.Input, "query_language") || strings.Contains(request.Input, "analysis_guidelines") {
		t.Error("the Gemini request is not the document operation request")
	}
}
