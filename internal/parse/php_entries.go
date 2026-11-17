package parse

import (
	"path"

	"github.com/zazzcode/zazzles/internal/analysis"
)

// phpRoutes returns one server-mapped route record per PHP file (D-2): no
// method restriction, the normalized repository path as HTTP path metadata.
func (s *phpSet) phpRoutes() []analysis.Route {
	out := []analysis.Route{}
	for _, file := range s.files {
		m := s.modules[file]
		if m == nil {
			continue
		}
		out = append(out, analysis.Route{
			ID:           "route:" + file + ":" + "FILE" + ":/" + file,
			Method:       "",
			PathPattern:  "/" + file,
			Framework:    "php",
			Registration: spanOf(file, m.tree.RootNode()),
			Handler:      analysis.Symbol{Name: path.Base(file), Kind: "file", Span: spanOf(file, m.tree.RootNode())},
			Steps:        []analysis.Step{{Kind: "server_file_mapping", Symbol: analysis.Symbol{Name: path.Base(file), Kind: "file", Span: spanOf(file, m.tree.RootNode())}}},
		})
	}
	return out
}

// analyzeEntry assembles the entry, dispatch and invocation records for one
// server-mapped PHP file, then walks its top-level scope.
func (s *phpSet) analyzeEntry(out *analysis.AnalysisReport, m *phpModule) {
	location := m.evidence("entry_registration", m.tree.RootNode())
	location.Text = ""
	instance := "php:" + m.file + ":" + m.hash
	entry := analysis.EntryPoint{ID: snapshotID("entry", location, instance, "server:/"+m.file), Kind: "http", Name: "FILE /" + m.file, InstanceID: instance, Location: location, HTTP: &analysis.HTTPEntryMetadata{SourcePath: m.file, Framework: "php", Path: "/" + m.file}}
	handler := m.evidence("invoked_callable", m.tree.RootNode())
	invocation := registerInvocation(out, entry, &handler, "server_file_mapping", nil, nil)
	work := 0
	f := &phpFlow{set: s, module: m, entry: entry, invocation: invocation, report: out, env: map[string]phpValue{}, globals: map[string]phpValue{}, context: []analysis.Evidence{handler, location}, work: &work, stack: map[string]bool{}, entryModule: m, entryModuleRoot: m.tree.RootNode()}
	f.block(m.tree.RootNode())
	out.InvocationContexts[len(out.InvocationContexts)-1] = f.invocation
	for i := range out.Entries {
		if out.Entries[i].ID == entry.ID {
			out.Entries[i].Gaps = phpMergeGaps(out.Entries[i].Gaps, f.gaps)
		}
	}
}
