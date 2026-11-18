package langjs

import (
	"sort"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/parse"
)

// automaticQueries reuses claim-scoped assembly without benchmark answer files.
func (s *moduleSet) automaticQueries(report *analysis.AnalysisReport) {
	entries := map[string]analysis.EntryPoint{}
	for _, e := range report.Entries {
		entries[e.HTTPRoute().ID] = e
	}
	for i, old := range report.Uses {
		kind := ""
		switch old.Kind {
		case "sql_query_candidate":
			kind = "sql_query"
		case "nosql_query_candidate":
			kind = "nosql_query"
		default:
			continue
		}
		entry, ok := entries[old.EntryID]
		if !ok {
			continue
		}
		fields := map[string]bool{}
		for _, d := range old.Dependencies {
			if entry.Kind == "graphql" || entry.Kind == "grpc" {
				fields[d.Source.Text] = true
				continue
			}
			parts := strings.Split(d.Source.Text, ".")
			if len(parts) > 2 {
				fields[parts[len(parts)-1]] = true
			}
			// const { email } = req.body: the field is the destructuring projection.
			if len(parts) <= 2 {
				for _, e := range d.Transfers {
					if e.Kind == "field_projection" {
						fields[e.Text] = true
					}
				}
			}
		}

		names := []string{}
		for name := range fields {
			names = append(names, name)
		}
		sort.Strings(names)
		check := analysis.Check{ID: "automatic-query", Method: entry.HTTPRoute().Method, Path: entry.HTTPRoute().PathPattern, Kind: kind, Fields: names,
			Validation: "Assess only field requirements established by the supplied code; missing business constraints remain uncertain.",
			Protection: "Untrusted input must remain data and must not change executable query syntax or selector operators. Evaluate actual transformations and enforcing guards separately from construction practice."}
		if entry.Kind == "graphql" {
			check.Method, check.Path = "", ""
			check.Selector = &analysis.EntrySelector{Kind: "graphql", Type: entry.GraphQL.Type, Field: entry.GraphQL.Field}
		}
		if entry.Kind == "grpc" {
			check.Method, check.Path = "", ""
			service := entry.GRPC.Service
			if entry.GRPC.Package != "" {
				service = entry.GRPC.Package + "." + service
			}
			check.Selector = &analysis.EntrySelector{Kind: "grpc", Service: service, Method: entry.GRPC.Method}
		}
		tmp := &analysis.AnalysisReport{Entries: []analysis.EntryPoint{entry}, Uses: []analysis.CandidateUse{old}}
		s.buildEntryChecks(tmp, []analysis.Check{check})
		for _, assembled := range tmp.Uses {
			if assembled.Kind == old.Kind {
				assembled.ID = old.ID
				report.Uses[i] = assembled
				break
			}
		}
	}
}

func (s *moduleSet) collectionBinding(use analysis.CandidateUse) []analysis.Evidence {
	m := s.modules[use.Sink.Span.File]
	if m == nil {
		return nil
	}
	call := parse.NodeAt(m.tree.RootNode(), use.Sink.Span.StartByte, use.Sink.Span.EndByte)
	if call == nil {
		return nil
	}
	fn := call.ChildByFieldName("function")
	if fn == nil {
		return nil
	}
	method := fn.ChildByFieldName("property")
	if method == nil {
		return nil
	}
	if obj := fn.ChildByFieldName("object"); obj != nil && obj.Kind() == "identifier" && !shadowed(call, obj.Utf8Text(m.src), m.src) {
		if id := s.modelIdentity(m, obj.Utf8Text(m.src), 0); strings.HasPrefix(id, "mongoose:") {
			binding := append([]analysis.Evidence{}, s.modelEvidence[id]...)
			for i := range binding {
				binding[i].Kind = "sink_binding"
			}
			return binding
		}
	}
	switch method.Utf8Text(m.src) {
	case "find", "findOne", "update", "insert", "remove":
	default:
		return nil
	}
	obj := fn.ChildByFieldName("object")
	if obj == nil {
		return nil
	}
	if shadowed(call, strings.Split(obj.Utf8Text(m.src), ".")[0], m.src) {
		return nil
	}
	parts := strings.Split(obj.Utf8Text(m.src), ".")
	target := m
	name := parts[0]
	out := []analysis.Evidence{}
	if len(parts) == 2 {
		imp, ok := m.imports[parts[0]]
		if !ok || imp.name != "*" {
			return nil
		}
		target = s.importModule(m, imp.module)
		if target == nil || !exportedName(target, parts[1]) {
			return nil
		}
		name = parts[1]
		out = append(out, m.evidence("sink_binding", imp.declaration))
	} else if len(parts) != 1 {
		return nil
	} else if imp, ok := m.imports[name]; ok && topVariable(m, name) == nil {
		// A named ES import is followed to the declaring module exactly like the
		// namespace form above; a default or namespace binding is not a collection.
		if imp.name == "*" || imp.name == "default" || bindingReassigned(m, name) {
			return nil
		}
		declaring, local, via := s.namedExport(m, imp.module, imp.name, 0)
		if declaring == nil {
			return nil
		}
		target, name = declaring, local
		out = append(out, m.evidence("sink_binding", imp.declaration))
		for _, step := range via {
			out = append(out, step.module.evidence("sink_binding", step.node))
		}
	}
	ctor := topVariable(target, name)
	if ctor == nil || ctor.Kind() != "new_expression" {
		return nil
	}
	constructor := ctor.ChildByFieldName("constructor")
	if constructor == nil {
		return nil
	}
	cp := strings.Split(constructor.Utf8Text(target.src), ".")
	if len(cp) != 2 || cp[1] != "Collection" {
		return nil
	}
	imp, ok := target.imports[cp[0]]
	if !ok || imp.module != "marsdb" || imp.name != "*" {
		return nil
	}
	out = append(out, target.evidence("sink_binding", imp.declaration), target.evidence("sink_binding", ctor.Parent()))
	return out
}

type exportStep struct {
	module *sourceModule
	node   *sitter.Node
}

// namedExport resolves the exported name of a relative module to the module and
// top-level local name that declare it, following export-clause aliases and
// `export { x } from` re-exports. It returns nil when the module is not local,
// the name is exported zero or several times, or the local binding is reassigned.
// via lists the re-export statements crossed, as evidence of the binding chain.
func (s *moduleSet) namedExport(from *sourceModule, path, exported string, depth int) (*sourceModule, string, []exportStep) {
	if depth > 3 {
		return nil, "", nil
	}
	t := s.importModule(from, path)
	if t == nil {
		return nil, "", nil
	}
	type match struct {
		local, source string
		node          *sitter.Node
	}
	var found []match
	root := t.tree.RootNode()
	for i := uint(0); i < root.NamedChildCount(); i++ {
		n := root.NamedChild(i)
		if n.Kind() != "export_statement" {
			continue
		}
		if decl := n.ChildByFieldName("declaration"); decl != nil {
			if decl.Kind() == "lexical_declaration" || decl.Kind() == "variable_declaration" {
				for j := uint(0); j < decl.NamedChildCount(); j++ {
					if id := decl.NamedChild(j).ChildByFieldName("name"); id != nil && id.Utf8Text(t.src) == exported {
						found = append(found, match{local: exported})
					}
				}
			} else if id := decl.ChildByFieldName("name"); id != nil && id.Utf8Text(t.src) == exported {
				found = append(found, match{local: exported})
			}
		}
		source := ""
		if src := n.ChildByFieldName("source"); src != nil {
			value, ok := stringLiteral(src, t.src)
			if !ok {
				return nil, "", nil
			}
			source = value
		}
		for j := uint(0); j < n.NamedChildCount(); j++ {
			clause := n.NamedChild(j)
			if clause.Kind() != "export_clause" {
				continue
			}
			for k := uint(0); k < clause.NamedChildCount(); k++ {
				spec := clause.NamedChild(k)
				id, alias := spec.ChildByFieldName("name"), spec.ChildByFieldName("alias")
				visible := alias
				if visible == nil {
					visible = id
				}
				if id != nil && visible != nil && visible.Utf8Text(t.src) == exported {
					found = append(found, match{local: id.Utf8Text(t.src), source: source, node: n})
				}
			}
		}
	}
	if len(found) != 1 {
		return nil, "", nil
	}
	f := found[0]
	if f.source != "" {
		declaring, local, via := s.namedExport(t, f.source, f.local, depth+1)
		if declaring == nil {
			return nil, "", nil
		}
		return declaring, local, append([]exportStep{{t, f.node}}, via...)
	}
	if bindingReassigned(t, f.local) {
		return nil, "", nil
	}
	if imp, ok := t.imports[f.local]; ok && topVariable(t, f.local) == nil {
		// `import { x } from './a'; export { x }` forwards another module's binding.
		if imp.name == "*" || imp.name == "default" {
			return nil, "", nil
		}
		declaring, local, via := s.namedExport(t, imp.module, imp.name, depth+1)
		if declaring == nil {
			return nil, "", nil
		}
		return declaring, local, append([]exportStep{{t, imp.declaration}}, via...)
	}
	return t, f.local, nil
}
