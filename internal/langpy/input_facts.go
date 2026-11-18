package langpy

import (
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/parse"
)

type pythonInputSource struct {
	origin string
}

// recordInput indexes acquisition within its invocation, never by a globally
// shared source span: the same helper can run under different registrations.
func (f *pythonFlow) recordInput(source analysis.Evidence, container, key string) {
	if f.set.inputs == nil {
		f.set.inputs = map[string]map[analysis.Evidence]pythonInputSource{}
	}
	inputs := f.set.inputs[f.invocation.ID]
	if inputs == nil {
		inputs = map[analysis.Evidence]pythonInputSource{}
		f.set.inputs[f.invocation.ID] = inputs
	}
	origin := pythonInputOrigin(container, key)
	// Legacy parameter bindings label path captures as query parameters. Correct
	// only acquisition metadata; retain those historical binding bytes verbatim.
	if source.Kind == "input_source" && f.route.fn != nil && source.Span.File == f.route.module.file {
		params := f.route.fn.ChildByFieldName("parameters")
		if params != nil && source.Span.StartByte >= int(params.StartByte()) && source.Span.EndByte <= int(params.EndByte()) && pythonPathParameter(f.route.route.PathPattern, key) {
			origin = "http.path"
		}
		if f.route.route.Framework == "fastapi" && params != nil {
			p := parse.NodeAt(params, source.Span.StartByte, source.Span.EndByte)
			if p != nil && (f.pythonDependencyBinding(p.ChildByFieldName("value")) || f.pythonDependencyBinding(p.ChildByFieldName("type"))) {
				// Dependency results may replace even a named path capture;
				// the legacy parameter projection does not prove their origin.
				origin = "unknown"
			}
		}
	}
	inputs[source] = pythonInputSource{origin: origin}
}

func (f *pythonFlow) pythonDependencyBinding(n *sitter.Node) bool {
	if n == nil {
		return false
	}
	if n.Kind() == "call" {
		switch f.qualified(pyText(f.module, n.ChildByFieldName("function"))) {
		case "fastapi.Depends", "fastapi.Security", "fastapi.params.Depends", "fastapi.params.Security":
			return true
		}
	}
	for i := uint(0); i < n.NamedChildCount(); i++ {
		if f.pythonDependencyBinding(n.NamedChild(i)) {
			return true
		}
	}
	return false
}

func pythonPathParameter(path, key string) bool {
	if key == "" {
		return false
	}
	for _, part := range strings.Split(path, "/") {
		if part == "{"+key+"}" || part == "<"+key+">" ||
			(strings.HasPrefix(part, "<") && strings.HasSuffix(part, ":"+key+">")) ||
			(strings.HasPrefix(part, "{") && strings.HasPrefix(part, "{"+key+":")) {
			return true
		}
	}
	return false
}

func pythonInputOrigin(container, key string) string {
	switch container {
	case "args", "query", "GET", "_params":
		return "http.query"
	case "form", "POST":
		return "http.form"
	case "json", "body", "data":
		return "http.body"
	case "values":
		return "http.query_or_form"
	case "cookies":
		return "http.cookies"
	case "headers", "META":
		return "http.headers"
	case "files":
		return "http.upload"
	case "session":
		return "session"
	case "environ":
		switch key {
		case "QUERY_STRING":
			return "http.query"
		case "PATH_INFO":
			return "http.url_path"
		}
	}
	return "unknown"
}

// Assemble after claims/storage/checks have finished editing dependencies. Facts
// mirror final paths; initial acquisition never certifies the current operand.
func (s *pythonSet) assemblePythonInputs(out *analysis.AnalysisReport) {
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
			Gaps: pythonMergeGaps(e.Gaps, u.Gaps),
		}
		if u.Completeness != nil {
			facts.Gaps = pythonMergeGaps(facts.Gaps, u.Completeness.Blockers)
		}
		for j, dep := range u.Dependencies {
			origin := "unknown"
			if source, ok := s.inputs[u.InvocationContextID][dep.Source]; ok {
				origin = source.origin
			}
			if origin == "http.upload" {
				origin = s.pythonUploadOrigin(dep)
			}
			// A stored value or external response is not a fresh request value,
			// even when a request-dependent entry eventually consumes it.
			switch dep.Source.Kind {
			case "storage_source":
				origin = "storage"
			case "external_response_source":
				origin = "external_response"
			}
			facts.Values = append(facts.Values, analysis.InputValueFact{
				Dependency: j, Origin: origin, InitialType: "unknown", SinkType: "unknown",
				Source: dep.Source, Transfers: append([]analysis.Evidence{}, dep.Transfers...),
			})
		}
		u.InputFacts = facts
	}
}

func (s *pythonSet) pythonUploadOrigin(dep analysis.Dependency) string {
	for _, transfer := range dep.Transfers {
		if transfer.Kind != "field_projection" {
			continue
		}
		m := s.modules[transfer.Span.File]
		if m == nil {
			continue
		}
		n := parse.NodeAt(m.tree.RootNode(), transfer.Span.StartByte, transfer.Span.EndByte)
		if n == nil || n.Kind() != "attribute" {
			continue
		}
		switch pyText(m, n.ChildByFieldName("attribute")) {
		case "filename", "name":
			return "http.upload_filename"
		case "file", "stream":
			return "http.upload_content"
		}
	}
	return "http.upload"
}
