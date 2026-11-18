package parse

import (
	"github.com/zazzcode/zazzles/internal/analysis"
)

func browserEntry(m *sourceModule, nodeEvidence analysis.Evidence, name, category string) analysis.EntryPoint {
	// A source-scope marker is not a callback registration/body. Relevant bounded
	// excerpts already live in each use; sending the whole module would inflate
	// otherwise bounded judge requests and imply unsupported dispatch evidence.
	nodeEvidence.Text = ""
	nodeEvidence.ModelText = ""
	instance := "browser:" + m.file + ":" + m.hash
	return analysis.EntryPoint{ID: snapshotID("entry", nodeEvidence, instance, category+":"+name), Kind: "browser", Name: name, InstanceID: instance, Location: nodeEvidence, Browser: &analysis.BrowserEntryMetadata{Category: category}}
}

func (f *flow) seedInvocation() {
	for _, input := range f.invocation.Inputs {
		switch input.Role {
		case "http.request":
			f.request = input.Parameter
		case "http.response":
			f.response = input.Parameter
		case "http.query", "http.body", "http.params", "http.headers":
			if f.parts == nil {
				f.parts = map[string]string{}
			}
			f.parts[input.Parameter] = inputRole(input.Role)
		default:
			v := value{}
			for _, source := range input.Origin.Evidence {
				source.Kind = "input_source"
				v.deps = append(v.deps, analysis.Dependency{Source: source})
			}
			if input.Origin.Kind == "unknown" {
				v.gaps = append(v.gaps, analysis.Gap{Kind: "input_origin_unknown", Detail: input.Role})
			}
			f.env[input.Parameter] = v
		}
	}
}

func browserInvocation(entry analysis.EntryPoint) analysis.InvocationContext {
	reg := snapshotID("registration", entry.Location, entry.ID, "registration")
	callable := snapshotID("callable", entry.Location, entry.Location.Span.File, "lexical-body")
	binding := snapshotID("dispatch", entry.Location, reg, "browser_source_slice:"+callable)
	return analysis.InvocationContext{ID: snapshotID("invocation", entry.Location, binding, "default"), EntryID: entry.ID, DispatchBindingID: binding}
}
