package judge

import (
	"encoding/json"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"strconv"
	"testing"
)

func TestTraceGraphUsesOnlyDeclaredDependencies(t *testing.T) {
	ev := func(kind string, start int) analysis.Evidence {
		return analysis.Evidence{Kind: kind, Text: kind, SHA256: "snapshot", Span: analysis.Span{File: "a.py", StartByte: start, EndByte: start + 1}}
	}
	source, param, guard, sink, unrelated := ev("input_source", 1), ev("argument_to_parameter", 2), ev("branch_precondition", 3), ev("operation", 4), ev("helper_definition", 5)
	u := analysis.CandidateUse{EntryID: "route", Sink: sink, Context: []analysis.Evidence{unrelated}, Dependencies: []analysis.Dependency{{Source: source, Transfers: []analysis.Evidence{param, guard}, SinkSlot: "sql_parameters", StorageKey: "db:users.email"}}}
	data, err := json.Marshal(wireBundle(u))
	if err != nil {
		t.Fatal(err)
	}
	var b struct {
		Trace        traceGraph          `json:"trace_graph"`
		Evidence     []analysis.Evidence `json:"evidence"`
		Dependencies []map[string]any    `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &b); err != nil {
		t.Fatal(err)
	}
	if len(b.Trace.Edges) != 3 || b.Trace.Entry != "route" || b.Dependencies[0]["storage_key"] != "db:users.email" {
		t.Fatalf("bad graph %s", data)
	}
	for _, edge := range b.Trace.Edges {
		for _, id := range []string{edge.From, edge.To} {
			found := false
			for i, e := range b.Evidence {
				if id == "e"+strconv.Itoa(i) {
					found = true
					if e.Kind == unrelated.Kind {
						t.Fatal("context proximity invented a flow edge")
					}
				}
			}
			if !found {
				t.Fatalf("unresolved reference %s", id)
			}
		}
		if edge.SinkSlot != "sql_parameters" {
			t.Fatal("lost operand slot")
		}
	}
	if b.Trace.Edges[0].Relation != "ARG_TO_PARAM" || b.Trace.Edges[1].Relation != "PATH_CONDITION:branch_precondition" || b.Trace.Edges[2].From != b.Trace.Edges[0].To {
		t.Fatal("guard became a value transformation")
	}
}
