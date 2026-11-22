package langphp

import (
	"maps"
	"slices"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

func (s *phpSet) linkDoctrineStorage(out *analysis.AnalysisReport) {
	if len(s.symfony) == 0 {
		return
	}
	for _, id := range slices.Sorted(maps.Keys(s.doctrine.objects)) {
		object := s.doctrine.objects[id]
		if !object.managed {
			continue
		}
		for _, key := range sortedTwigFields(object.writes) {
			s.writes[key] = append(s.writes[key], object.writes[key]...)
		}
	}
	s.doctrineWriterCensus()
	s.expandFlashWrites(out)
	origins := map[analysis.Evidence]phpInputSource{}
	for _, id := range sortedTwigFields(s.inputs) {
		for e, origin := range s.inputs[id] {
			origins[e] = origin
		}
	}
	projects := s.storageProjectIndex(out)
	symfonyEntries := map[string]bool{}
	for _, entry := range out.Entries {
		symfonyEntries[entry.ID] = entry.HTTP != nil && entry.HTTP.Framework == "symfony"
	}
	kept := out.Uses[:0]
	for i := range out.Uses {
		u := &out.Uses[i]
		if !symfonyEntries[u.EntryID] {
			kept = append(kept, *u)
			continue
		}
		s.doctrineStoredEvidence(u, projects[u.EntryID])
		for _, d := range u.Dependencies {
			for _, w := range s.scopedStorageWrites(d.StorageKey, u.EntryID, projects) {
				for _, dep := range w.value.deps {
					if origin, ok := origins[dep.dep.Source]; ok {
						if s.inputs[u.InvocationContextID] == nil {
							s.inputs[u.InvocationContextID] = map[analysis.Evidence]phpInputSource{}
						}
						s.inputs[u.InvocationContextID][dep.dep.Source] = origin
					}
				}
			}
		}
		if u.XSS == nil && s.linkDoctrineOperands(u, projects) {
			continue
		}
		kept = append(kept, *u)
	}
	out.Uses = kept
}

// Keep a single store namespace for plain PHP and one for each detected
// Symfony project. Writer ownership follows its invocation, even when
// the assignment itself appears in a shared helper.
func (s *phpSet) storageProjectIndex(out *analysis.AnalysisReport) map[string]*symfonyProject {
	if len(s.symfony) == 0 {
		return nil
	}
	projects := make(map[string]*symfonyProject, len(out.Entries))
	for _, entry := range out.Entries {
		if entry.HTTP != nil {
			projects[entry.ID] = s.symfonyProjectOf(entry.HTTP.SourcePath)
		}
	}
	return projects
}

func (s *phpSet) scopedStorageWrites(key, entry string, projects map[string]*symfonyProject) []phpWrite {
	var writes []phpWrite
	switch {
	case strings.HasPrefix(key, "php-sql:"):
		writes = s.writes[key]
	case strings.HasPrefix(key, "php-session:"):
		writes = s.sessionWrites[key]
	}
	if projects == nil {
		return writes
	}
	result := make([]phpWrite, 0, len(writes))
	for _, w := range writes {
		project, known := projects[w.entry]
		if !known {
			project = s.symfonyProjectOf(w.evidence.Span.File)
		}
		if project == projects[entry] {
			result = append(result, w)
		}
	}
	return result
}

func (s *phpSet) expandFlashWrites(out *analysis.AnalysisReport) {
	const prefix = "php-session:flash."
	wildcard := s.sessionWrites[prefix+"*"]
	all := append([]phpWrite{}, wildcard...)
	for _, key := range sortedTwigFields(s.sessionWrites) {
		if strings.HasPrefix(key, prefix) && key != prefix+"*" {
			all = append(all, s.sessionWrites[key]...)
		}
	}
	keys := map[string]bool{}
	for _, u := range out.Uses {
		for _, d := range u.Dependencies {
			if strings.HasPrefix(d.StorageKey, prefix) {
				keys[d.StorageKey] = true
			}
		}
	}
	for _, key := range sortedTwigFields(keys) {
		if key == prefix+"*" {
			s.sessionWrites[key] = all
		} else if len(wildcard) > 0 {
			s.sessionWrites[key] = append(s.sessionWrites[key], wildcard...)
		}
	}
}

func (s *phpSet) doctrineWriterCensus() {
	seen := map[analysis.Span]bool{}
	for _, key := range sortedTwigFields(s.writes) {
		for _, w := range s.writes[key] {
			seen[w.evidence.Span] = true
			s.doctrine.census[key] = append(s.doctrine.census[key], analysis.StoredWrite{Evidence: w.evidence, Literal: w.value.constant})
		}
	}
	for _, file := range s.files {
		m, p := s.modules[file], s.symfonyProjectOf(file)
		if m == nil || p == nil {
			continue
		}
		f := &phpFlow{set: s, module: m, symfony: p}
		phpWalk(m.tree.RootNode(), func(fn *sitter.Node) {
			if fn.Kind() != "method_declaration" && fn.Kind() != "function_definition" {
				return
			}
			types := map[string]*phpClassDecl{}
			params := phpField(fn, "parameters")
			for i := uint(0); params != nil && i < params.NamedChildCount(); i++ {
				param := params.NamedChild(i)
				typ, name := phpField(param, "type"), phpVarName(m, phpField(param, "name"))
				if typ == nil || name == "" {
					continue
				}
				class := s.classIndex().qualify(m, strings.TrimPrefix(phpText(m, typ), "?"), typ.StartByte())
				if decl := f.symfonyClass(class); decl != nil && f.doctrineEntityDecl(decl) {
					types[name] = decl
				}
			}
			phpWalk(phpField(fn, "body"), func(n *sitter.Node) {
				switch n.Kind() {
				case "assignment_expression":
					left, right := phpField(n, "left"), phpField(n, "right")
					if left == nil || right == nil {
						return
					}
					if left.Kind() == "variable_name" && right.Kind() == "object_creation_expression" {
						typ := firstNamedChild(right)
						if typ == nil {
							return
						}
						class := s.classIndex().qualify(m, phpText(m, typ), typ.StartByte())
						if decl := f.symfonyClass(class); decl != nil && f.doctrineEntityDecl(decl) {
							types[phpVarName(m, left)] = decl
						}
					}
					if left.Kind() != "member_access_expression" {
						return
					}
					decl := types[phpVarName(m, phpField(left, "object"))]
					if decl == nil {
						return
					}
					key := f.doctrineFieldKeys(decl)[phpText(m, phpField(left, "name"))]
					s.censusWrite(key, m.evidence("storage_write_non_entry", left), doctrineLiteralNode(right), seen)
				case "member_call_expression":
					decl := types[phpVarName(m, phpField(n, "object"))]
					if decl == nil {
						return
					}
					method := phpText(m, phpField(n, "name"))
					if !strings.HasPrefix(method, "set") {
						return
					}
					setter := phpOwnMethod(decl, method)
					var fields []string
					phpWalk(phpField(setter, "body"), func(node *sitter.Node) {
						if node.Kind() != "assignment_expression" {
							return
						}
						left := phpField(node, "left")
						if phpVarName(decl.module, phpField(left, "object")) == "this" {
							fields = append(fields, phpText(decl.module, phpField(left, "name")))
						}
					})
					args := phpArgs(n)
					literal := len(args) > 0 && doctrineLiteralNode(args[0])
					for _, field := range fields {
						key := f.doctrineFieldKeys(decl)[field]
						s.censusWrite(key, m.evidence("storage_write_non_entry", n), literal, seen)
					}
				}
			})
		})
	}
}

func doctrineLiteralNode(n *sitter.Node) bool {
	if n == nil {
		return false
	}
	switch n.Kind() {
	case "string", "integer", "float", "true", "false", "null":
		return true
	}
	return false
}

func (s *phpSet) censusWrite(key string, e analysis.Evidence, literal bool, seen map[analysis.Span]bool) {
	if key == "" || seen[e.Span] {
		return
	}
	s.doctrine.census[key] = append(s.doctrine.census[key], analysis.StoredWrite{Evidence: e, Literal: literal})
	// The census establishes a source write but not a request-entry data path.
	project := s.symfonyProjectOf(e.Span.File)
	if !slices.ContainsFunc(s.writes[key], func(w phpWrite) bool {
		return s.symfonyProjectOf(w.evidence.Span.File) == project
	}) {
		s.writes[key] = append(s.writes[key], phpWrite{evidence: e})
	}
}

func (s *phpSet) doctrineStoredEvidence(u *analysis.CandidateUse, project *symfonyProject) {
	var stores []analysis.StoredWriteSet
	seen := map[string]bool{}
	for _, d := range u.Dependencies {
		key := d.StorageKey
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		var writes []analysis.StoredWrite
		for _, w := range s.doctrine.census[key] {
			if s.symfonyProjectOf(w.Evidence.Span.File) == project {
				writes = append(writes, w)
			}
		}
		if len(writes) > 0 {
			stores = append(stores, analysis.StoredWriteSet{Key: key, Writes: writes, ClosedStore: "open"})
		}
	}
	if len(stores) > 0 {
		u.StoredOrigin = &analysis.StoredOriginFacts{Stores: stores}
	}
}

// linkDoctrineOperands applies the same cross-entry write origins used by
// rendering to each typed operand path without discarding its sink controls.
func (s *phpSet) linkDoctrineOperands(u *analysis.CandidateUse, projects map[string]*symfonyProject) bool {
	indexes := make([][]int, len(u.Dependencies))
	var deps []analysis.Dependency
	var unknown []bool
	linked := false
	unlinked := false
	unchanged := false
	request := false
	for i, d := range u.Dependencies {
		writes := s.scopedStorageWrites(d.StorageKey, u.EntryID, projects)
		if d.Source.Kind != "storage_source" || len(writes) == 0 {
			indexes[i] = []int{len(deps)}
			deps = append(deps, d)
			unknown = append(unknown, false)
			unlinked = unlinked || d.Source.Kind == "storage_source"
			request = request || d.Source.Kind == "input_source"
			continue
		}
		unchanged = true
		for _, w := range writes {
			for _, src := range w.value.deps {
				if src.dep.Source.Kind != "input_source" {
					continue
				}
				if len(deps) >= 64 {
					break
				}
				next := src.dep
				next.SinkSlot, next.StorageKey = d.SinkSlot, d.StorageKey
				next.Transfers = append(append(append([]analysis.Evidence{}, next.Transfers...), d.Source), d.Transfers...)
				indexes[i] = append(indexes[i], len(deps))
				deps = append(deps, next)
				unknown = append(unknown, src.protection != "raw" && src.protection != "")
				linked = true
			}
		}
	}
	if !unchanged {
		return false
	}
	if len(deps) == 0 {
		return true
	}
	u.Dependencies = deps
	if u.Completeness != nil {
		if linked && (!unlinked || request) {
			u.Completeness.Blockers = slices.DeleteFunc(u.Completeness.Blockers, func(g analysis.Gap) bool { return g.Kind == "storage_origin_unresolved" })
		}
		for _, d := range deps {
			if d.Source.Kind == "input_source" {
				for _, role := range []string{"input_source", "query_source", "destination_source", "path_source"} {
					if _, exists := u.Completeness.Evidence[role]; exists {
						u.Completeness.Evidence[role] = phpDedupeEvidence(append(u.Completeness.Evidence[role], d.Source))
					}
				}
			}
		}
	}
	s.remapDoctrinePaths(u, indexes, unknown)
	return false
}

func (s *phpSet) remapDoctrinePaths(u *analysis.CandidateUse, indexes [][]int, unknown []bool) {
	remap := func(ids []int) []int {
		var result []int
		for _, id := range ids {
			if id >= 0 && id < len(indexes) {
				result = append(result, indexes[id]...)
			}
		}
		return result
	}
	paths := func(items []analysis.CommandPath) []analysis.CommandPath {
		var out []analysis.CommandPath
		for _, p := range items {
			for _, i := range remap([]int{p.Dependency}) {
				q := p
				q.Dependency = i
				if unknown[i] && q.Protection == "raw" {
					q.Protection = "unknown"
				}
				out = append(out, q)
			}
		}
		return out
	}
	if u.Command != nil {
		u.Command.Paths = paths(u.Command.Paths)
		for i := range u.Command.Operands {
			p := &u.Command.Operands[i]
			p.Dependencies = remap(p.Dependencies)
		}
	}
	if u.Path != nil {
		var flows []analysis.PathFlow
		for _, p := range u.Path.Paths {
			for _, i := range remap([]int{p.Dependency}) {
				q := p
				q.Dependency = i
				if unknown[i] && q.Protection == "raw" {
					q.Protection = "unknown"
				}
				flows = append(flows, q)
			}
		}
		u.Path.Paths = flows
		for i := range u.Path.Operands {
			p := &u.Path.Operands[i]
			p.Dependencies = remap(p.Dependencies)
		}
	}
	if u.Code != nil {
		u.Code.Paths = paths(u.Code.Paths)
	}
	if u.Redirect != nil {
		u.Redirect.Paths = paths(u.Redirect.Paths)
	}
	if u.Upload != nil {
		u.Upload.Paths = paths(u.Upload.Paths)
	}
	if u.Deserialization != nil {
		u.Deserialization.Paths = paths(u.Deserialization.Paths)
	}
	if u.Outbound != nil {
		u.Outbound.Paths = paths(u.Outbound.Paths)
	}
}
