package judge

import (
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"strings"
)

type traceEdge struct {
	From       string `json:"from"`
	To         string `json:"to"`
	Relation   string `json:"relation"`
	Dependency int    `json:"dependency"`
	SinkSlot   string `json:"sink_slot,omitempty"`
}
type traceGraph struct {
	InvocationContext string      `json:"invocation_context_id"`
	Entry             string      `json:"entry"`
	EntryKind         string      `json:"entry_kind"`
	Sink              string      `json:"sink"`
	Edges             []traceEdge `json:"edges"`
	Scope             string      `json:"scope"`
}

// buildTraceGraph projects adapter-supplied witnesses into the shared wire analysis.
// Context proximity alone never creates a call, flow or guard edge.
func buildTraceGraph(use analysis.CandidateUse, ref func(analysis.Evidence) string) traceGraph {
	entry, kind := use.EntryID, use.EntryKind
	result := traceGraph{InvocationContext: use.InvocationContextID, Entry: entry, EntryKind: kind, Sink: ref(use.Sink), Edges: []traceEdge{}, Scope: "Source-backed static dependency witnesses and supplied control edges; not an executed trace or whole-program completeness proof."}
	for i, d := range use.Dependencies {
		previous := ref(d.Source)
		for _, transfer := range d.Transfers {
			id := ref(transfer)
			relation := "TRANSFERS_TO"
			switch transfer.Kind {
			case "argument_to_parameter":
				relation = "ARG_TO_PARAM"
			case "helper_return", "return_value":
				relation = "RETURN_TO_CALL"
			case "field_projection":
				relation = "PROJECTS"
			}
			if strings.Contains(transfer.Kind, "precondition") || strings.Contains(transfer.Kind, "branch") {
				result.Edges = append(result.Edges, traceEdge{id, result.Sink, "PATH_CONDITION:" + transfer.Kind, i, d.SinkSlot})
				continue
			}
			if id != previous {
				result.Edges = append(result.Edges, traceEdge{previous, id, relation, i, d.SinkSlot})
				previous = id
			}
		}
		result.Edges = append(result.Edges, traceEdge{previous, result.Sink, "USED_BY", i, d.SinkSlot})
	}
	for _, edge := range use.ControlEdges {
		result.Edges = append(result.Edges, traceEdge{From: ref(edge.From), To: ref(edge.To), Relation: "CONTROL:" + edge.Kind, Dependency: -1})
	}
	return result
}
