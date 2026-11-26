package judge

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
)

// sqlTextUse is a record made by SQL text recognition: the call sits inside a
// source excerpt the recorder attached; the text case has a value in slot
// sql_text, the bound case one in sql_parameters.
func sqlTextUse(bound bool) analysis.CandidateUse {
	ev := func(kind, file, text string, line, start int) analysis.Evidence {
		return analysis.Evidence{Kind: kind, Text: text, Span: analysis.Span{File: file, StartLine: line, EndLine: line, StartByte: start, EndByte: start + len(text)}}
	}
	sink := ev("sql_query_candidate", "app.js", `db.run("SELECT * FROM t WHERE id = " + id)`, 9, 300)
	slot := "sql_text"
	if bound {
		slot = "sql_parameters"
		sink = ev("sql_query_candidate", "app.js", `db.run("SELECT * FROM t WHERE id = ?", [id])`, 9, 300)
	}
	file := ev("source_excerpt", "app.js", "const db = open();\napp.get('/x', (req) => { const id = req.query.id; db.run(...) })", 1, 0)
	file.Span.EndByte = 500
	file.Span.EndLine = 12
	return analysis.CandidateUse{
		Kind: "sql_query_candidate", Sink: sink, APIModel: analysispacks.SQLContract(analysispacks.SQLTextContract),
		InputFacts:   &analysis.InputFacts{Framework: "express"},
		Dependencies: []analysis.Dependency{{SinkSlot: slot, Source: ev("input_source", "app.js", "req.query.id", 7, 330)}},
		Context: []analysis.Evidence{
			file,
			ev("handler", "app.js", "(req) => { const id = req.query.id; db.run(...) }", 8, 280),
			ev("authorization_context", "lib.js", "if (!ok) return", 2, 20),
		},
		Completeness: &analysis.Completeness{ClaimKind: "injection", Evidence: map[string][]analysis.Evidence{"sink_binding": {ev("sink_binding", "app.js", "db.run", 9, 300)}}},
	}
}

type sqlTextRequest struct {
	Input     string `json:"input"`
	Questions []struct {
		Name    string              `json:"name"`
		Choices []map[string]string `json:"choices"`
	} `json:"questions"`
}

func sqlTextBuild(t *testing.T, provider string, use analysis.CandidateUse) (sqlTextRequest, []string, map[string]json.RawMessage) {
	t.Helper()
	c, err := New(provider, "fixture-model", "offline-no-key")
	if err != nil {
		t.Fatal(err)
	}
	payload, err := c.payloadForm(use, true)
	if err != nil {
		t.Fatal(err)
	}
	var request sqlTextRequest
	if err := json.Unmarshal(payload, &request); err != nil {
		t.Fatal(err)
	}
	var input map[string]json.RawMessage
	if err := json.Unmarshal([]byte(request.Input), &input); err != nil {
		t.Fatal(err)
	}
	// Field order of the encoded input.
	dec := json.NewDecoder(strings.NewReader(request.Input))
	dec.Token()
	var order []string
	for dec.More() {
		k, _ := dec.Token()
		order = append(order, k.(string))
		var skip json.RawMessage
		dec.Decode(&skip)
	}
	return request, order, input
}

// TestSQLTextOperationRequest fixes the request shape and field order of a text
// case and of a bound case, and keeps every contract out of it.
func TestSQLTextOperationRequest(t *testing.T) {
	for _, bound := range []bool{false, true} {
		use := sqlTextUse(bound)
		request, order, input := sqlTextBuild(t, "openai", use)
		if got := strings.Join(order, ","); got != "task,query_language,entry,call,request_values,source" {
			t.Errorf("bound=%v field order %s", bound, got)
		}
		if len(request.Questions) != 2 || request.Questions[0].Name != "operation" || request.Questions[1].Name != "request_control" ||
			len(request.Questions[0].Choices) != 3 || len(request.Questions[1].Choices) != 4 {
			t.Fatalf("questions: %+v", request.Questions)
		}
		var task, language string
		json.Unmarshal(input["task"], &task)
		json.Unmarshal(input["query_language"], &language)
		if task != sqlTextTask || language != analysispacks.SQLTextLanguage {
			t.Errorf("task or language text changed: %q", task)
		}
		var values []string
		json.Unmarshal(input["request_values"], &values)
		if len(values) != 1 || values[0] != "req.query.id" {
			t.Errorf("values %v", values)
		}
		var source []struct {
			File      string `json:"file"`
			StartLine int    `json:"start_line"`
			Text      string `json:"text"`
		}
		json.Unmarshal(input["source"], &source)
		// The handler is inside the file excerpt: the file excerpt alone is sent.
		if len(source) != 1 || source[0].File != "app.js" || source[0].StartLine != 1 || !strings.Contains(source[0].Text, "req.query.id") {
			t.Errorf("source: %+v", source)
		}
		for _, absent := range []string{"analysis_guidelines", "compact_wire", "api_model", "sql-text-v1", "authorization_context", "if (!ok) return", "stored_values"} {
			if strings.Contains(request.Input, absent) {
				t.Errorf("bound=%v: request contains %q", bound, absent)
			}
		}
		if len(request.Input) > 14000 {
			t.Errorf("request is %d bytes", len(request.Input))
		}
	}
	// The Gemini and Jev adapters name the questions in a map.
	for provider, field := range map[string]string{"gemini": "input", "jev": "state"} {
		model := "fixture-model"
		if provider == "gemini" {
			model = "gemini-decision-1"
		}
		c, err := New(provider, model, "offline-no-key")
		if err != nil {
			t.Fatal(err)
		}
		payload, err := c.payloadForm(sqlTextUse(false), true)
		if err != nil {
			t.Fatal(err)
		}
		var request map[string]json.RawMessage
		json.Unmarshal(payload, &request)
		var qs map[string]struct {
			Criteria map[string]string `json:"criteria"`
		}
		json.Unmarshal(request["questions"], &qs)
		if len(request[field]) == 0 || len(qs) != 2 || len(qs["operation"].Criteria) != 3 || len(qs["request_control"].Criteria) != 4 {
			t.Errorf("%s: %s", provider, payload)
		}
	}
}

func TestSQLTextOperationStoredValues(t *testing.T) {
	use := sqlTextUse(false)
	use.Dependencies = append(use.Dependencies, analysis.Dependency{SinkSlot: "sql_text", Source: analysis.Evidence{Kind: "storage_source", Text: "session.user", Span: analysis.Span{File: "app.js", StartLine: 3}}})
	_, order, input := sqlTextBuild(t, "openai", use)
	if got := strings.Join(order, ","); got != "task,query_language,entry,call,request_values,stored_values,source" {
		t.Errorf("order %s", got)
	}
	var task string
	var values, stored []string
	json.Unmarshal(input["task"], &task)
	json.Unmarshal(input["request_values"], &values)
	json.Unmarshal(input["stored_values"], &stored)
	if task != sqlTextTask+sqlTextStoredTask || len(values) != 1 || values[0] != "req.query.id" || len(stored) != 1 || stored[0] != "session.user" {
		t.Errorf("task %q values %v stored %v", task, values, stored)
	}
	// Only stored values: request_values stays present and empty.
	use.Dependencies = use.Dependencies[1:]
	_, _, input = sqlTextBuild(t, "openai", use)
	if string(input["request_values"]) != "[]" || len(input["stored_values"]) == 0 {
		t.Errorf("request_values %s", input["request_values"])
	}
}

func TestSQLTextOperationSource(t *testing.T) {
	ev := func(kind, file string, start, end int) analysis.Evidence {
		return analysis.Evidence{Kind: kind, Text: kind + file, Span: analysis.Span{File: file, StartLine: start/10 + 1, StartByte: start, EndByte: end}}
	}
	use := sqlTextUse(false)
	use.Sink.Span = analysis.Span{File: "a.js", StartLine: 6, StartByte: 50, EndByte: 70}
	use.Context = []analysis.Evidence{
		ev("source_excerpt", "z.js", 0, 500),
		ev("helper_definition", "a.js", 200, 300),
		ev("source_excerpt", "a.js", 0, 400),       // holds the helper and the call
		ev("handler", "a.js", 40, 120),             // inside the file excerpt
		ev("referenced_definition", "b.js", 0, 50), // other file, kept
		ev("handler", "a.js", 40, 120),             // exact duplicate
		ev("invoked_callable", "m.js", 10, 90),
		ev("validation_control", "m.js", 20, 30), // inside the callable
		ev("authorization_context", "a.js", 0, 10000),
	}
	got, err := sqlTextSource(use)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range got {
		names = append(names, e.Kind+":"+e.Span.File)
	}
	// Handler and invoked callables first (none of the handlers survive: the
	// invoked callable does), then by file and start byte.
	want := "invoked_callable:m.js,source_excerpt:a.js,referenced_definition:b.js,source_excerpt:z.js"
	if strings.Join(names, ",") != want {
		t.Errorf("got %v want %s", names, want)
	}
	// The same byte range twice keeps the first.
	use.Context = []analysis.Evidence{ev("source_excerpt", "a.js", 0, 400), ev("handler", "a.js", 0, 400)}
	got, err = sqlTextSource(use)
	if err != nil || len(got) != 1 || got[0].Kind != "source_excerpt" {
		t.Errorf("equal range: %+v %v", got, err)
	}
	// Handler first even when a file excerpt sorts before it.
	use.Context = []analysis.Evidence{ev("source_excerpt", "a.js", 0, 100), ev("handler", "b.js", 0, 20), analysis.Evidence{Kind: "handler", Span: analysis.Span{File: "c.js"}}}
	use.Sink.Span = analysis.Span{File: "a.js", StartByte: 50, EndByte: 70}
	got, err = sqlTextSource(use)
	if err != nil || len(got) < 2 || got[0].Kind != "handler" {
		t.Errorf("order: %+v %v", got, err)
	}
}

// TestSQLTextOperationNoSink: with no excerpt that holds the call no request is
// built, and the record is Review through the ordinary could-not-build path.
func TestSQLTextOperationNoSink(t *testing.T) {
	use := sqlTextUse(false)
	use.Context = []analysis.Evidence{use.Context[1]} // the handler excerpt lies before the call
	use.Context[0].Span.EndByte = use.Sink.Span.StartByte
	c, err := New("openai", "fixture-model", "offline-no-key")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.payloadForm(use, true); err == nil {
		t.Fatal("a request was built without the call in the source")
	}
	// An excerpt of another file does not hold the call either.
	use = sqlTextUse(false)
	use.Context[0].Span.File = "other.js"
	use.Context = use.Context[:1]
	if _, err := c.payloadForm(use, true); err == nil {
		t.Fatal("a request was built from another file's excerpt")
	}
	// No excerpt at all.
	use = sqlTextUse(false)
	use.Context = nil
	a := c.Assess(t.Context(), use)
	if a.Status != "failed" || a.FindingStatus != "needs_evidence" || a.Protection != "uncertain" || !strings.Contains(a.Reason, "source excerpt") {
		t.Errorf("assessment: %+v", a)
	}
}

func TestSQLTextOperationPolicy(t *testing.T) {
	limit := []analysis.Gap{{Kind: "unsupported_callback"}}
	stored := analysis.Dependency{SinkSlot: "sql_text", Source: analysis.Evidence{Kind: "storage_source", Text: "session.user"}}
	for _, tt := range []struct {
		name, operation, control string
		dataOnly                 float64
		judged, blockers         []analysis.Gap
		onlyStored               bool
		want, injection          string
	}{
		{"statement text", "runs_sql", "statement_text", 0.1, nil, nil, false, "confirmed_vulnerability", "vulnerable"},
		{"name", "runs_sql", "name", 0.1, nil, nil, false, "confirmed_vulnerability", "vulnerable"},
		{"statement text with a judged limit", "runs_sql", "statement_text", 0.1, limit, nil, false, "confirmed_vulnerability", "vulnerable"},
		{"strong data only", "runs_sql", "data_only", 0.97, nil, nil, false, "protected_for_claim", "protected"},
		{"floor data only", "runs_sql", "data_only", documentProtectedFloor, nil, nil, false, "protected_for_claim", "protected"},
		{"weak data only", "runs_sql", "data_only", 0.94, nil, nil, false, "needs_evidence", "unknown"},
		{"data only with a judged limit", "runs_sql", "data_only", 0.99, limit, nil, false, "needs_evidence", "unknown"},
		{"cannot tell control", "runs_sql", "cannot_tell", 0, nil, nil, false, "needs_evidence", "unknown"},
		{"cannot tell operation", "cannot_tell", "statement_text", 0, nil, nil, false, "needs_evidence", "unknown"},
		{"not a database operation", "not_database_operation", "statement_text", 0, nil, nil, false, "not_applicable", "not_applicable"},
		{"not a database operation with only stored values", "not_database_operation", "statement_text", 0, nil, nil, true, "not_applicable", "not_applicable"},
		{"only stored values, statement text", "runs_sql", "statement_text", 0, nil, nil, true, "needs_evidence", "unknown"},
		{"only stored values, data only", "runs_sql", "data_only", 0.99, nil, nil, true, "needs_evidence", "unknown"},
		{"blocker, statement text", "runs_sql", "statement_text", 0, nil, []analysis.Gap{{Kind: "unresolved_wrapper"}}, false, "confirmed_vulnerability", "vulnerable"},
		{"blocker, not a database operation", "not_database_operation", "statement_text", 0, nil, []analysis.Gap{{Kind: "unresolved_wrapper"}}, false, "not_applicable", "not_applicable"},
		{"blocker, data only", "runs_sql", "data_only", 0.99, nil, []analysis.Gap{{Kind: "unresolved_wrapper"}}, false, "needs_evidence", "unknown"},
	} {
		use := sqlTextUse(false)
		use.Completeness.Judged, use.Completeness.Blockers = tt.judged, tt.blockers
		if tt.onlyStored {
			use.Dependencies = []analysis.Dependency{stored}
		}
		a := analysis.Assessment{Status: "completed", Answers: map[string]string{"operation": tt.operation, "request_control": tt.control},
			AnswerDetails: map[string]analysis.AnswerDetail{"request_control": {Choice: tt.control, Probabilities: []analysis.ChoiceProbability{{Value: "data_only", Probability: tt.dataOnly}}}}}
		applyPolicy(use, &a)
		if a.FindingStatus != tt.want || a.Answers["injection_protection"] != tt.injection {
			t.Errorf("%s: %s, injection %s; want %s, %s", tt.name, a.FindingStatus, a.Answers["injection_protection"], tt.want, tt.injection)
		}
		if len(tt.blockers) > 0 && tt.control == "data_only" && len(a.BlockingGaps) != len(tt.blockers) {
			t.Errorf("%s: blocking gaps %v", tt.name, a.BlockingGaps)
		}
	}
}

// TestSQLTextBoundOnlyFinding: a finding answer for a record whose request
// values are all apart from a statement text the scanner resolved whole is Review.
func TestSQLTextBoundOnlyFinding(t *testing.T) {
	answer := func(use analysis.CandidateUse) analysis.Assessment {
		a := analysis.Assessment{Status: "completed", Answers: map[string]string{"operation": "runs_sql", "request_control": "statement_text"},
			AnswerDetails: map[string]analysis.AnswerDetail{}}
		applyPolicy(use, &a)
		return a
	}
	bound := sqlTextUse(false)
	for i := range bound.Dependencies {
		bound.Dependencies[i].SinkSlot = analysispacks.SQLTextParametersSlot
	}
	if a := answer(bound); a.FindingStatus != "needs_evidence" || len(a.BlockingGaps) != 1 || a.BlockingGaps[0].Kind != "bound_parameters_only" {
		t.Fatalf("bound only: %s %v", a.FindingStatus, a.BlockingGaps)
	}
	built := bound
	built.Gaps = append([]analysis.Gap{}, analysis.Gap{Kind: "query_text_interpolated"})
	if a := answer(built); a.FindingStatus != "confirmed_vulnerability" {
		t.Fatalf("bound values beside built text: %s", a.FindingStatus)
	}
	text := sqlTextUse(false)
	for i := range text.Dependencies {
		text.Dependencies[i].SinkSlot = analysispacks.SQLTextSlot
	}
	if a := answer(text); a.FindingStatus != "confirmed_vulnerability" {
		t.Fatalf("text case: %s", a.FindingStatus)
	}
}

// TestSQLTextOperationSelection: the protocol and request belong to the contract
// sql-text-v1 alone; any other SQL record keeps its own.
func TestSQLTextOperationSelection(t *testing.T) {
	use := sqlTextUse(false)
	if !sqlTextOperation(use) || protocolVersion(use) != analysispacks.SQLTextOperationProtocol || len(questionsFor(use)) != 2 {
		t.Error("the SQL text record does not select its protocol")
	}
	if analysispacks.SQLTextOperationProtocol == analysispacks.SQLProtocol {
		t.Error("protocols collide")
	}
	for name, mutate := range map[string]func(*analysis.CandidateUse){
		"no completeness": func(u *analysis.CandidateUse) { u.Completeness = nil },
		"no dependency":   func(u *analysis.CandidateUse) { u.Dependencies = nil },
		"no model":        func(u *analysis.CandidateUse) { u.APIModel = nil },
		"another model":   func(u *analysis.CandidateUse) { u.APIModel = analysispacks.SQLContract("sequelize-raw-query-v1") },
		"another kind":    func(u *analysis.CandidateUse) { u.Kind = "nosql_query_candidate" },
	} {
		other := sqlTextUse(false)
		mutate(&other)
		if sqlTextOperation(other) || protocolVersion(other) == analysispacks.SQLTextOperationProtocol {
			t.Errorf("%s: selected the SQL text protocol", name)
		}
	}
	// A contract record keeps the contract request.
	contract := selectedSQLUse(t)
	if sqlTextOperation(contract) || protocolVersion(contract) != analysispacks.SQLProtocol {
		t.Error("a contract record selected the SQL text protocol")
	}
	c, _ := New("openai", "fixture-model", "offline-no-key")
	payload, err := c.payloadForm(contract, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"analysis_components", "sequelize-raw-query-v1", "compact_wire"} {
		if !strings.Contains(string(payload), want) {
			t.Errorf("contract request lost %s", want)
		}
	}
	if strings.Contains(string(payload), "query_language") {
		t.Error("contract request carries the SQL text request")
	}
}

func TestSQLTextOperationEquivalence(t *testing.T) {
	c, _ := New("openai", "fixture-model", "offline-no-key")
	a, err := c.EquivalenceSignature(sqlTextUse(false))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := c.EquivalenceSignature(sqlTextUse(false))
	other, _ := c.EquivalenceSignature(sqlTextUse(true))
	if a != b || a == other || len(a) != 64 {
		t.Errorf("signatures %s %s %s", a, b, other)
	}
	// Ids and unrelated context do not change the request.
	use := sqlTextUse(false)
	use.ID, use.EntryID, use.InvocationContextID = "use:x", "entry:x", "inv:x"
	use.Context = append(use.Context, analysis.Evidence{Kind: "authorization_context", Text: "x", Span: analysis.Span{File: "q.js"}})
	if got, _ := c.EquivalenceSignature(use); got != a {
		t.Error("ids or unrelated context moved the signature")
	}
}
