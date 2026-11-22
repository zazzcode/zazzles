package langphp

import (
	"fmt"
	"slices"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
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
		entity.deps = append(entity.deps, src.deps...)
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
	var walk func(v phpValue)
	walk = func(v phpValue) {
		for _, d := range v.deps {
			if d.dep.Source.Kind == "input_source" {
				out = append(out, d)
			}
		}
		for _, f := range v.fields {
			walk(f)
		}
	}
	for _, v := range values {
		walk(v)
	}
	return out
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

func (f *phpFlow) notePlainSQL(n *sitter.Node, text phpValue) {
	if f.symfony != nil || n == nil {
		return
	}
	constant, ok := phpSQLText(text)
	if !ok {
		return
	}
	up := strings.ToUpper(constant)
	op := ""
	switch {
	case strings.Contains(up, "INSERT"):
		op = "create"
	case strings.Contains(up, "UPDATE"):
		op = "update"
	case strings.Contains(up, "DELETE"):
		op = "delete"
	default:
		return
	}
	sink := f.module.evidence(analysis.AuthorizationKind, n)
	f.notePlainOperation(n, analysis.StateChange{Operation: op, Span: sink.Span})
}

func (f *phpFlow) notePlainOperation(n *sitter.Node, change analysis.StateChange) {
	guards := f.dominatingGuards(n, nil)
	if len(guards) != 1 || guards[0].Kind != analysis.GuardAddress {
		return
	}
	f.addAuthzChange(change)
	f.emitAuthz(f.module.evidence(analysis.AuthorizationKind, n), n, &phpAuthz{}, change, nil, nil, nil)
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
	if f.authzSite != nil && f.entryModule != nil {
		return f.entryModule.evidence(analysis.AuthorizationKind, f.authzSite)
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
		Completeness:  f.authzCompleteness(sink, sub, facts),
	}
	f.report.Uses = append(f.report.Uses, u)
}

func authzMethodSafe(entry analysis.EntryPoint, op string) string {
	if op == "read" || entry.Kind == "FILE" || entry.HTTP == nil {
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
	blockers := []analysis.Gap{}
	if f.entry.Access != nil {
		for _, g := range f.entry.Access.Gaps {
			if authzBlockingGap(g.Kind) {
				blockers = append(blockers, g)
			}
		}
	}
	for _, g := range facts.Guards {
		for _, gap := range g.Gaps {
			if authzBlockingGap(gap.Kind) {
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
		},
		Blockers: blockers,
		Coverage: []analysis.Gap{},
	}
}

func authzBlockingGap(kind string) bool {
	switch kind {
	case "access_rule_unresolved", "access_rule_condition_unmodeled", "voter_unmodeled", "access_expression_unmodeled", "authenticator_unmodeled", "guard_unclassified", "symfony_config_unread":
		return true
	default:
		return false
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
	names := map[string]string{}
	for i := range out.Entries {
		e := &out.Entries[i]
		names[e.ID] = e.Name
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
	var ssrf []string
	for _, u := range out.Uses {
		if u.Kind == "ssrf_candidate" {
			ssrf = append(ssrf, u.ID)
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
			ids := append([]string{}, writers[facts.Operation.StorageKey]...)
			slices.SortFunc(ids, func(a, b string) int { return strings.Compare(names[a], names[b]) })
			for _, id := range ids {
				if id == u.EntryID || len(peers) >= 8 {
					continue
				}
				peers = append(peers, analysis.PeerAccess{
					Entry: names[id], Access: entryAccessOf(out, id), GuardKinds: guardKinds(out, id, facts.Operation.StorageKey),
				})
			}
			if len(peers) > 0 {
				facts.PeerAccess = peers
			}
		}
		if slices.ContainsFunc(facts.Guards, func(g analysis.AuthorizationGuard) bool { return g.Kind == analysis.GuardAddress }) && len(ssrf) > 0 {
			facts.ServerSideRequests = append([]string{}, ssrf...)
		}
	}
}

func entryAccessOf(out *analysis.AnalysisReport, id string) analysis.EntryAccess {
	for _, e := range out.Entries {
		if e.ID == id && e.Access != nil {
			return *e.Access
		}
	}
	return analysis.EntryAccess{}
}

func guardKinds(out *analysis.AnalysisReport, entryID, key string) []string {
	var outKinds []string
	seen := map[string]bool{}
	for _, u := range out.Uses {
		if u.EntryID != entryID || u.Authorization == nil || u.Authorization.Operation.StorageKey != key {
			continue
		}
		for _, g := range u.Authorization.Guards {
			if g.Kind != "" && !seen[g.Kind] {
				seen[g.Kind] = true
				outKinds = append(outKinds, g.Kind)
			}
		}
	}
	return outKinds
}
