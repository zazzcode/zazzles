package langphp

import (
	"cmp"
	"fmt"
	"maps"
	"slices"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
)

// phpAuthz is the subject of one entity value (D-4).
type phpAuthz struct {
	provenance string
	class      string
	selecting  []phpDep
	queryScope bool
	finder     *sitter.Node
}

type authzChange struct {
	entryID string
	change  analysis.StateChange
}

func (f *phpFlow) stampAuthz(v phpValue) {
	if v.authz == nil || v.objectID == 0 {
		return
	}
	if obj := f.doctrineObject(v, true); obj != nil && obj.authz == nil {
		obj.authz = v.authz
	}
	for name, prop := range v.props {
		for i := range prop.deps {
			prop.deps[i].authzProv = v.authz.provenance
			prop.deps[i].authzClass = v.authz.class
			prop.deps[i].authzSelecting = v.authz.selecting
		}
		v.props[name] = prop
	}
	f.writeObject(v)
}

func (f *phpFlow) authzOf(v phpValue) *phpAuthz {
	if v.authz != nil {
		return v.authz
	}
	if v.objectID == 0 || f.set.doctrine.objects == nil {
		return nil
	}
	if obj := f.set.doctrine.objects[v.objectID]; obj != nil {
		return obj.authz
	}
	return nil
}

func (f *phpFlow) bindAuthzEntity(route string, param *sitter.Node, entity phpValue, current bool) phpValue {
	if entity.objectID == 0 {
		return entity
	}
	name := phpVarName(f.module, phpField(param, "name"))
	if current {
		entity.authz = &phpAuthz{provenance: analysis.SubjectSessionUser, class: entity.class}
	} else {
		ph := name
		if !symfonyPlaceholder(route, name) {
			ph = firstRoutePlaceholder(route)
		}
		src := f.source(param, "attributes", "http.path", ph)
		entity.authz = &phpAuthz{provenance: analysis.SubjectRequestSelected, class: entity.class, selecting: src.deps}
	}
	f.stampAuthz(entity)
	return entity
}

func firstRoutePlaceholder(route string) string {
	i := strings.Index(route, "{")
	if i < 0 {
		return ""
	}
	rest := route[i+1:]
	j := strings.Index(rest, "}")
	if j < 0 {
		return ""
	}
	name := strings.TrimPrefix(rest[:j], "!")
	if k := strings.IndexAny(name, ":<"); k >= 0 {
		name = name[:k]
	}
	return name
}

func (f *phpFlow) noteCreated(v phpValue, decl *phpClassDecl) phpValue {
	if f.symfony == nil || v.authz != nil || !f.doctrineEntityDecl(decl) {
		return v
	}
	v.authz = &phpAuthz{provenance: analysis.SubjectCreated, class: decl.fqn}
	f.stampAuthz(v)
	return v
}

func (f *phpFlow) noteFinderSubject(n *sitter.Node, v phpValue, method string, values []phpValue) phpValue {
	if v.classDecl == nil {
		return v
	}
	method = strings.ToLower(method)
	prov := analysis.SubjectEnumerated
	var selecting []phpDep
	query := false
	if method != "findall" {
		if sub := f.carriedSubject(values); sub != nil && sub.provenance == analysis.SubjectRequestSelected {
			prov = analysis.SubjectRequestSelected
			selecting = sub.selecting
		} else if f.valuesHaveProvenance(values, analysis.SubjectSessionUser) {
			prov = analysis.SubjectRequestSelected
			query = true
			selecting = phpInputDeps(values)
		} else if deps := phpInputDeps(values); len(deps) > 0 {
			prov = analysis.SubjectRequestSelected
			selecting = deps
		}
	}
	v.authz = &phpAuthz{provenance: prov, class: v.class, selecting: selecting, queryScope: query, finder: n}
	f.stampAuthz(v)
	return v
}

func (f *phpFlow) carriedSubject(values []phpValue) *phpAuthz {
	for _, v := range values {
		if sub := f.authzOf(v); sub != nil {
			return sub
		}
		if sub := f.carriedSubject(fieldValues(v)); sub != nil {
			return sub
		}
	}
	return nil
}

func (f *phpFlow) valuesHaveProvenance(values []phpValue, prov string) bool {
	for _, v := range values {
		if sub := f.authzOf(v); sub != nil && sub.provenance == prov {
			return true
		}
		if f.valuesHaveProvenance(fieldValues(v), prov) {
			return true
		}
	}
	return false
}

func fieldValues(v phpValue) []phpValue {
	if len(v.fields) == 0 {
		return nil
	}
	out := make([]phpValue, 0, len(v.fields))
	for _, f := range v.fields {
		out = append(out, f)
	}
	return out
}

func phpInputDeps(values []phpValue) []phpDep {
	var out []phpDep
	for _, v := range values {
		phpEachDep(v, func(d phpDep) {
			if d.dep.Source.Kind == "input_source" {
				out = append(out, d)
			}
		})
	}
	return out
}

// phpEachDep calls fn for each dependency of v and of its fields, the
// fields in key order.
func phpEachDep(v phpValue, fn func(phpDep)) {
	for _, d := range v.deps {
		fn(d)
	}
	for _, key := range slices.Sorted(maps.Keys(v.fields)) {
		phpEachDep(v.fields[key], fn)
	}
}

func (f *phpFlow) noteAuthzProperty(object phpValue, key string, v phpValue, at *sitter.Node) {
	sub := f.authzOf(object)
	if sub == nil || at == nil {
		return
	}
	sink := f.authzSink(at)
	op := "update"
	if sub.provenance == analysis.SubjectCreated {
		op = "create"
	}
	change := analysis.StateChange{StorageKey: key, Operation: op, Span: sink.Span}
	f.addAuthzChange(change)
	facets := f.writeFacets(sub, key, v)
	if len(facets) == 0 {
		return
	}
	f.emitAuthz(sink, at, sub, change, facets, f.censusFacts(key), append([]phpDep{}, v.deps...))
}

func (f *phpFlow) noteAuthzDelete(v phpValue, at *sitter.Node) {
	sub := f.authzOf(v)
	if sub == nil || sub.provenance != analysis.SubjectRequestSelected {
		return
	}
	sink := f.authzSink(at)
	change := analysis.StateChange{Operation: "delete", Span: sink.Span}
	f.addAuthzChange(change)
	f.emitAuthz(sink, at, sub, change, []string{analysis.FacetObjectLevel}, nil, nil)
}

func (f *phpFlow) noteAuthzFile(n *sitter.Node, name string, values []phpValue) {
	if len(values) == 0 || n == nil {
		return
	}
	op := "file_write"
	if name == "unlink" || name == "rmdir" {
		op = "file_delete"
	}
	for _, d := range values[0].deps {
		if d.authzProv != analysis.SubjectRequestSelected || d.dep.StorageKey == "" {
			continue
		}
		sub := &phpAuthz{provenance: d.authzProv, class: d.authzClass, selecting: d.authzSelecting}
		sink := f.module.evidence(analysis.AuthorizationKind, n)
		change := analysis.StateChange{StorageKey: d.dep.StorageKey, Operation: op, Span: sink.Span}
		f.addAuthzChange(change)
		f.emitAuthz(sink, n, sub, change, []string{analysis.FacetObjectLevel}, f.censusFacts(d.dep.StorageKey), nil)
		return
	}
	if f.symfony == nil {
		sink := f.module.evidence(analysis.AuthorizationKind, n)
		f.notePlainOperation(n, analysis.StateChange{Operation: op, Span: sink.Span})
	}
}

func (f *phpFlow) noteAuthzOutput(sink analysis.Evidence, guardAt *sitter.Node, v phpValue) {
	if f.symfony == nil || sink.Span.File == "" {
		return
	}
	seen := map[string]bool{}
	for _, d := range v.deps {
		if seen[d.dep.StorageKey] || d.dep.StorageKey == "" {
			continue
		}
		if d.authzProv != analysis.SubjectRequestSelected && d.authzProv != analysis.SubjectEnumerated {
			continue
		}
		facts := f.censusFacts(d.dep.StorageKey)
		if len(facts) == 0 || !censusSensitive(facts[0].Roles) {
			continue
		}
		seen[d.dep.StorageKey] = true
		sub := &phpAuthz{provenance: d.authzProv, class: d.authzClass, selecting: d.authzSelecting}
		change := analysis.StateChange{StorageKey: d.dep.StorageKey, Operation: "read", Span: sink.Span}
		f.emitAuthz(sink, guardAt, sub, change, []string{analysis.FacetDataExposure}, facts, nil)
	}
}

func (f *phpFlow) writeFacets(sub *phpAuthz, key string, v phpValue) []string {
	if sub == nil || sub.provenance == analysis.SubjectSessionUser || sub.provenance == analysis.SubjectEnumerated {
		return nil
	}
	roles := f.censusRoles(key)
	role := slices.Contains(roles, analysis.RoleSource)
	derived := phpHasInput(v)
	var facets []string
	if sub.provenance == analysis.SubjectRequestSelected {
		facets = append(facets, analysis.FacetObjectLevel)
	}
	if role && (sub.provenance == analysis.SubjectRequestSelected || (sub.provenance == analysis.SubjectCreated && derived)) {
		facets = append(facets, analysis.FacetFunctionLevel)
	}
	return facets
}

func phpHasInput(v phpValue) bool {
	for _, d := range v.deps {
		if d.dep.Source.Kind == "input_source" {
			return true
		}
	}
	for _, child := range v.fields {
		if phpHasInput(child) {
			return true
		}
	}
	return false
}

func (f *phpFlow) censusRoles(key string) []string {
	fact, ok := f.censusFact(key)
	if !ok {
		return nil
	}
	return fact.Roles
}

func (f *phpFlow) censusFact(key string) (analysis.SecurityFieldFact, bool) {
	if f.symfony == nil || key == "" {
		return analysis.SecurityFieldFact{}, false
	}
	field, ok := f.set.securityFields(f.symfony)[key]
	if !ok {
		return analysis.SecurityFieldFact{}, false
	}
	return analysis.SecurityFieldFact{StorageKey: key, Roles: append([]string{}, field.roles...), Evidence: append([]analysis.Evidence{}, field.evidence...)}, true
}

func (f *phpFlow) censusFacts(key string) []analysis.SecurityFieldFact {
	fact, ok := f.censusFact(key)
	if !ok {
		return []analysis.SecurityFieldFact{}
	}
	return []analysis.SecurityFieldFact{fact}
}

func censusSensitive(roles []string) bool {
	return slices.Contains(roles, analysis.RoleCredential) || slices.Contains(roles, analysis.RoleLoginIdentifier) || slices.Contains(roles, analysis.RoleSource)
}

func (f *phpFlow) authzSink(at *sitter.Node) analysis.Evidence {
	if f.authzSite != nil && f.authzSiteModule != nil {
		return f.authzSiteModule.evidence(analysis.AuthorizationKind, f.authzSite)
	}
	return f.module.evidence(analysis.AuthorizationKind, at)
}

func (f *phpFlow) emitAuthz(sink analysis.Evidence, at *sitter.Node, sub *phpAuthz, change analysis.StateChange, facets []string, fields []analysis.SecurityFieldFact, extra []phpDep) {
	if sub == nil || sink.Span.File == "" || f.report == nil {
		return
	}
	if len(facets) == 0 && !(sub.class == "" && change.Operation != "") {
		return
	}
	id := fmt.Sprintf("use:%s:%s:%d:%s:%s", f.invocation.ID, sink.Span.File, sink.Span.StartByte, analysis.AuthorizationKind, change.StorageKey+"/"+change.Operation)
	for _, u := range f.report.Uses {
		if u.ID == id {
			return
		}
	}
	guards := f.authzGuards
	if guards == nil {
		guards = f.dominatingGuards(at, sub)
	}
	if guards == nil {
		guards = []analysis.AuthorizationGuard{}
	}
	if facets == nil {
		facets = []string{}
	}
	if fields == nil {
		fields = []analysis.SecurityFieldFact{}
	}
	deps := []analysis.Dependency{}
	seen := map[string]bool{}
	addDep := func(d phpDep) {
		key := d.dep.Source.Kind + ":" + d.dep.Source.Span.File + ":" + fmt.Sprint(d.dep.Source.Span.StartByte) + ":" + d.dep.StorageKey
		if seen[key] {
			return
		}
		seen[key] = true
		deps = append(deps, d.dep)
	}
	for _, d := range sub.selecting {
		if d.container == "attributes" {
			d.dep.Source.ModelText = "route placeholder"
		}
		addDep(d)
	}
	for _, d := range extra {
		addDep(d)
	}
	facts := &analysis.AuthorizationFacts{
		Facets: facets, SubjectClass: sub.class, SubjectProvenance: sub.provenance,
		Operation: change, SecurityFields: fields, Guards: guards,
		MethodSafe: authzMethodSafe(f.entry, change.Operation),
	}
	u := analysis.CandidateUse{
		ID: id, EntryID: f.entry.ID, InvocationContextID: f.invocation.ID,
		Kind: analysis.AuthorizationKind, Sink: sink, Dependencies: deps,
		Context: phpDedupeEvidence(f.context), Gaps: append([]analysis.Gap{}, f.gaps...),
		Assessment:    analysis.Assessment{Status: "not_run"},
		Authorization: facts,
		APIModel:      analysispacks.AuthorizationContract(analysispacks.PHPAuthorizationOperation),
		Completeness:  f.authzCompleteness(sink, sub, facts),
	}
	f.report.Uses = append(f.report.Uses, u)
}

func authzMethodSafe(entry analysis.EntryPoint, op string) string {
	if op == "read" || entry.HTTP == nil {
		return "no"
	}
	switch entry.HTTP.Method {
	case "", "GET", "HEAD":
		return "yes"
	default:
		return "no"
	}
}

func (f *phpFlow) authzCompleteness(sink analysis.Evidence, sub *phpAuthz, facts *analysis.AuthorizationFacts) *analysis.Completeness {
	selection := []analysis.Evidence{}
	for _, d := range sub.selecting {
		selection = append(selection, d.dep.Source)
	}
	if len(selection) == 0 && sink.Span.File != "" {
		selection = []analysis.Evidence{sink}
	}
	access := []analysis.Evidence{}
	if f.entry.Access != nil {
		access = append(access, f.entry.Access.Sources...)
	}
	if len(access) == 0 {
		access = []analysis.Evidence{f.entry.Location}
	}
	binding := sink
	binding.Kind = "sink_binding"
	blockers := []analysis.Gap{}
	if f.entry.Access != nil {
		for _, g := range f.entry.Access.Gaps {
			if analysis.AuthorizationBlockingGap(g.Kind, false) {
				blockers = append(blockers, g)
			}
		}
	}
	for _, g := range facts.Guards {
		for _, gap := range g.Gaps {
			if analysis.AuthorizationBlockingGap(gap.Kind, false) {
				blockers = append(blockers, gap)
			}
		}
	}
	onlyCensus := len(facts.Facets) == 1 && (facts.Facets[0] == analysis.FacetFunctionLevel || facts.Facets[0] == analysis.FacetDataExposure)
	if onlyCensus && f.symfony != nil {
		for _, g := range f.set.securityGaps(f.symfony) {
			if g.Kind == analysis.SecurityFieldsUnresolved {
				blockers = append(blockers, g)
			}
		}
	}
	return &analysis.Completeness{
		ClaimKind: "authorization",
		Required:  []string{"subject_selection", "protected_operation", "entry_access", "control_flow"},
		Scope:     "One protected operation, its subject and the guards that dominate it.",
		Evidence: map[string][]analysis.Evidence{
			"subject_selection":   selection,
			"protected_operation": {sink},
			"entry_access":        access,
			"control_flow":        append([]analysis.Evidence{sink}, f.context...),
			"sink_binding":        {binding},
		},
		Blockers: blockers,
		Coverage: []analysis.Gap{},
	}
}

func (f *phpFlow) addAuthzChange(c analysis.StateChange) {
	if f.entry.ID == "" {
		return
	}
	for _, e := range f.set.authzChanges {
		if e.entryID == f.entry.ID && e.change.StorageKey == c.StorageKey && e.change.Operation == c.Operation && e.change.Span == c.Span {
			return
		}
	}
	f.set.authzChanges = append(f.set.authzChanges, authzChange{entryID: f.entry.ID, change: c})
}

func (s *phpSet) finishAuthorization(out *analysis.AnalysisReport) {
	if out == nil {
		return
	}
	byEntry := map[string][]analysis.StateChange{}
	for _, c := range s.authzChanges {
		byEntry[c.entryID] = append(byEntry[c.entryID], c.change)
	}
	entries := make(map[string]*analysis.EntryPoint, len(out.Entries))
	for i := range out.Entries {
		e := &out.Entries[i]
		entries[e.ID] = e
		if changes := byEntry[e.ID]; len(changes) > 0 {
			e.StateChanges = changes
		}
	}
	writers := map[string][]string{}
	for id, changes := range byEntry {
		seen := map[string]bool{}
		for _, c := range changes {
			if c.StorageKey == "" || c.Operation == "read" || seen[c.StorageKey] {
				continue
			}
			seen[c.StorageKey] = true
			writers[c.StorageKey] = append(writers[c.StorageKey], id)
		}
	}
	name := func(id string) string {
		if e := entries[id]; e != nil {
			return e.Name
		}
		return ""
	}
	for _, ids := range writers {
		slices.SortFunc(ids, func(a, b string) int {
			return cmp.Or(strings.Compare(name(a), name(b)), strings.Compare(a, b))
		})
	}
	type writerKey struct{ entryID, storageKey string }
	guardKinds := map[writerKey][]string{}
	for _, u := range out.Uses {
		if u.Authorization == nil || u.Authorization.Operation.StorageKey == "" {
			continue
		}
		key := writerKey{u.EntryID, u.Authorization.Operation.StorageKey}
		for _, g := range u.Authorization.Guards {
			if g.Kind != "" && !slices.Contains(guardKinds[key], g.Kind) {
				guardKinds[key] = append(guardKinds[key], g.Kind)
			}
		}
	}
	for i := range out.Uses {
		u := &out.Uses[i]
		if u.Authorization == nil {
			continue
		}
		facts := u.Authorization
		if facts.Operation.Operation != "read" && facts.Operation.StorageKey != "" {
			var peers []analysis.PeerAccess
			for _, id := range writers[facts.Operation.StorageKey] {
				if len(peers) == 8 {
					break
				}
				if id == u.EntryID {
					continue
				}
				var access analysis.EntryAccess
				if e := entries[id]; e != nil && e.Access != nil {
					access = *e.Access
				}
				peers = append(peers, analysis.PeerAccess{
					Entry: name(id), Access: access, GuardKinds: guardKinds[writerKey{id, facts.Operation.StorageKey}],
				})
			}
			if len(peers) > 0 {
				facts.PeerAccess = peers
			}
		}
	}
}

// linkServerSideRequests runs after use ids are final. An address-guarded
// candidate lists every ssrf use id; those uses are not modified.
func (s *phpSet) linkServerSideRequests(out *analysis.AnalysisReport) {
	if out == nil {
		return
	}
	var ssrf []string
	for _, u := range out.Uses {
		if u.Kind == "ssrf_candidate" {
			ssrf = append(ssrf, u.ID)
		}
	}
	if len(ssrf) == 0 {
		return
	}
	for i := range out.Uses {
		facts := out.Uses[i].Authorization
		if facts == nil || !slices.ContainsFunc(facts.Guards, func(g analysis.AuthorizationGuard) bool { return g.Kind == analysis.GuardAddress }) {
			continue
		}
		facts.ServerSideRequests = append([]string{}, ssrf...)
	}
}
