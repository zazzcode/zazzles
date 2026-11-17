package parse

import (
	"github.com/zazzcode/zazzles/internal/analysis"
)

// phpInputOrigin maps a superglobal container to its acquisition origin
// vocabulary (D-4). $_SESSION is a storage container, never a request origin.
func phpInputOrigin(container, key string) string {
	switch container {
	case "GET":
		return "http.query"
	case "POST":
		return "http.form"
	case "REQUEST":
		return "http.query_or_form"
	case "COOKIE":
		return "http.cookies"
	case "FILES":
		return "http.upload"
	case "SERVER":
		return serverKeyOrigin(key)
	case "INPUT":
		return "http.body"
	case "_SESSION":
		return "storage"
	}
	return "unknown"
}

// assemblePHPInputs builds InputFacts after storage linking finalized the
// dependencies. Facts mirror final paths; initial acquisition never certifies
// the current operand.
func (s *phpSet) assemblePHPInputs(out *analysis.AnalysisReport) {
	entries := map[string]analysis.EntryPoint{}
	for _, entry := range out.Entries {
		entries[entry.ID] = entry
	}
	for i := range out.Uses {
		u := &out.Uses[i]
		e := entries[u.EntryID]
		if e.HTTP == nil {
			continue
		}
		facts := &analysis.InputFacts{
			Version: 1, Acquisition: "http", Framework: e.HTTP.Framework, Binding: e.Location,
			Values: []analysis.InputValueFact{}, Controls: append([]analysis.Evidence{}, u.Context...),
			Gaps: phpMergeGaps(e.Gaps, u.Gaps),
		}
		if u.Completeness != nil {
			facts.Gaps = phpMergeGaps(facts.Gaps, u.Completeness.Blockers)
		}
		for j, dep := range u.Dependencies {
			origin := "unknown"
			if source, ok := s.inputs[u.InvocationContextID][dep.Source]; ok {
				origin = source.origin
			}
			if origin == "http.upload" {
				origin = phpUploadOrigin(dep)
			}
			switch dep.Source.Kind {
			case "storage_source":
				origin = "storage"
			}
			facts.Values = append(facts.Values, analysis.InputValueFact{
				Dependency: j, Origin: origin, InitialType: "unknown", SinkType: "unknown",
				Source: dep.Source, Transfers: append([]analysis.Evidence{}, dep.Transfers...),
			})
		}
		u.InputFacts = facts
	}
}

// phpUploadOrigin refines $_FILES field projections: the client-supplied name
// and the server-managed tmp_name carry different facts.
func phpUploadOrigin(dep analysis.Dependency) string {
	for _, transfer := range dep.Transfers {
		if transfer.Kind != "field_projection" {
			continue
		}
		switch transfer.Text {
		case "name", "full_path":
			return "http.upload_filename"
		case "tmp_name":
			return "http.upload_content"
		}
	}
	return "http.upload"
}
