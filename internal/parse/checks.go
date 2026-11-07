package parse

import (
	"fmt"
	"strings"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
)

func (s *moduleSet) buildEntryChecks(report *analysis.AnalysisReport, checks []analysis.Check) {
	selected := []analysis.CandidateUse{}
	for _, check := range checks {
		s.contextLimits = nil
		s.contextFields = check.Fields
		context, chainGaps := s.chainEvidence(report, check)
		if len(context) == 0 {
			report.Gaps = append(report.Gaps, analysis.Gap{Kind: "check_context_unresolved", Detail: check.ID + ": selected invocation evidence was not resolved"})
			continue
		}
		if check.Kind == "sql_query" || check.Kind == "nosql_query" {
			candidateKind := "sql_query_candidate"
			if check.Kind == "nosql_query" {
				candidateKind = "nosql_query_candidate"
			}
			matched := 0
			for _, old := range report.Uses {
				if old.Kind != candidateKind || !checkRoute(report, old.EntryID, check) {
					continue
				}
				matched++
				use := old
				use.ID += "/" + check.ID
				use.Check = &check
				use.Context = append(context, use.Context...)
				use.Completeness = &analysis.Completeness{ClaimKind: "injection", Required: []string{"input_source", candidateKind, "invoked_callable", "sink_binding"}, Evidence: evidenceRoles(use.Context), Blockers: append([]analysis.Gap{}, chainGaps...), Coverage: []analysis.Gap{}, Scope: "injection claim over the supplied route, relevant request values, verified operation contract and guard/transfer context"}
				use.Completeness.Evidence[candidateKind] = []analysis.Evidence{use.Sink}
				for _, d := range use.Dependencies {
					if fieldDependency(d, check.Fields) {
						use.Completeness.Evidence["input_source"] = append(use.Completeness.Evidence["input_source"], d.Source)
					}
				}
				controlComplete := false
				var completeBodies []analysis.Evidence
				for _, e := range old.Context {
					if e.Kind != "handler" {
						continue
					}
					module := s.modules[e.Span.File]
					if module == nil {
						continue
					}
					body := nodeAt(module.tree.RootNode(), e.Span.StartByte, e.Span.EndByte)
					if body == nil {
						continue
					}
					edges, missing := controlContext(module, body)
					use.ControlEdges = append(use.ControlEdges, edges...)
					use.Completeness.Blockers = append(use.Completeness.Blockers, missing...)
					controlComplete = len(missing) == 0
					if controlComplete {
						completeBodies = append(completeBodies, e)
					}
					use.Completeness.Evidence["control_flow"] = []analysis.Evidence{e}
				}
				binding := s.queryBinding(use)
				sqlContract := "sequelize-raw-query-v1"
				if check.Kind == "nosql_query" {
					binding = s.collectionBinding(use)
				} else if sqlJS := s.sqlJSBinding(use); len(sqlJS) > 0 {
					binding, sqlContract = sqlJS, "sqljs-statement-v1"
				}
				if len(binding) > 0 {
					if check.Kind == "nosql_query" {
						use.APIModel = analysispacks.NoSQLContract("marsdb-collection-v1")
						if module := s.modules[use.Sink.Span.File]; module != nil {
							call := nodeAt(module.tree.RootNode(), use.Sink.Span.StartByte, use.Sink.Span.EndByte)
							if call != nil {
								fn := call.ChildByFieldName("function")
								if fn != nil {
									obj := fn.ChildByFieldName("object")
									if obj != nil && strings.HasPrefix(s.modelIdentity(module, obj.Utf8Text(module.src), 0), "mongoose:") {
										use.APIModel = analysispacks.NoSQLContract("mongoose-model-query-v1")
									}
								}
							}
						}
					} else {
						use.APIModel = analysispacks.SQLContract(sqlContract)
					}
					use.Context = append(use.Context, binding...)
					use.Completeness.Evidence["sink_binding"] = binding
					s.mongooseQueryContext(&use)
				}
				for _, g := range use.Gaps {
					switch g.Kind {
					case "unsupported_control_flow":
						if controlComplete {
							use.Completeness.Coverage = append(use.Completeness.Coverage, g)
						} else {
							use.Completeness.Blockers = append(use.Completeness.Blockers, g)
						}
					case "branch_exit":
						covered := false
						{
							for _, body := range completeBodies {
								if g.At.File == body.Span.File && g.At.StartByte >= body.Span.StartByte && g.At.EndByte <= body.Span.EndByte {
									covered = true
								}
							}
						}
						if covered {
							use.Completeness.Coverage = append(use.Completeness.Coverage, g)
						} else {
							use.Completeness.Blockers = append(use.Completeness.Blockers, g)
						}
					case "middleware_unresolved", "query_text_interpolated", "query_document_unvalidated", "input_validation_absent", "input_validation_unresolved", "input_validation_middleware", "validation_insufficient_for_sink", "validation_type_only", "sink_must_bind_free_text", "validation_free_text_bound":
						// Query shape and missing validation stay visible. They do not
						// convert a clear insufficient protection answer into an abstention.
						use.Completeness.Coverage = append(use.Completeness.Coverage, g)

					case "unknown_value":
						// Unknown result-model/options metadata is not a dependency of SQL text.
						if gapTouchesSQLSource(g, use, check.Fields) {
							use.Completeness.Blockers = append(use.Completeness.Blockers, g)
						} else {
							use.Completeness.Coverage = append(use.Completeness.Coverage, g)
						}
					case "unknown_transfer":
						if gapTouchesSQLSource(g, use, check.Fields) {
							use.Completeness.Blockers = append(use.Completeness.Blockers, g)
						} else {
							use.Completeness.Coverage = append(use.Completeness.Coverage, g)
						}
					case "sink_binding_unverified":
						if len(binding) == 0 {
							use.Completeness.Blockers = append(use.Completeness.Blockers, g)
						} else {
							use.Completeness.Coverage = append(use.Completeness.Coverage, g)
						}
					default:
						use.Completeness.Blockers = append(use.Completeness.Blockers, g)
					}
				}
				use.Completeness.Blockers = append(use.Completeness.Blockers, s.contextLimits...)
				s.refineQueryEvidence(&use)
				selected = append(selected, use)
			}
			if matched == 0 {
				selected = append(selected, missingSQLSink(report, check, context, chainGaps))
			}
		} else if check.Kind == "account_creation" {
			use := s.registrationCheck(report, check, context, chainGaps)
			use.Completeness.Blockers = append(use.Completeness.Blockers, s.contextLimits...)
			selected = append(selected, use)
		}
	}
	for _, old := range report.Uses {
		if old.Kind == "input_validation_candidate" {
			selected = append(selected, old)
		}
	}
	report.Uses = selected
}

// missingSQLSink keeps a declared SQL check visible when discovery found no query.
// An empty use list would be indistinguishable from a protected route.
func missingSQLSink(report *analysis.AnalysisReport, c analysis.Check, context []analysis.Evidence, chainGaps []analysis.Gap) analysis.CandidateUse {
	var route analysis.Route
	blockers := append([]analysis.Gap{}, chainGaps...)
	for _, e := range report.Entries {
		if e.HTTPRoute().Method != c.Method || e.HTTPRoute().PathPattern != c.Path {
			continue
		}
		route = e.HTTPRoute()
		for _, g := range e.Gaps {
			switch g.Kind {
			case "helper_call_limit", "recursive_helper", "work_limit":
				blockers = append(blockers, g)
			}
		}
	}
	gap := analysis.Gap{Kind: "sql_sink_missing", Detail: c.ID + ": declared SQL check produced no candidate sink", At: route.Registration}
	blockers = append(blockers, gap)
	return analysis.CandidateUse{
		ID:           fmt.Sprintf("check:%s:%s:missing-sink", route.ID, c.ID),
		EntryID:      route.ID,
		Kind:         "sql_sink_missing",
		Check:        &c,
		Context:      context,
		Gaps:         []analysis.Gap{gap},
		Assessment:   analysis.Assessment{Status: "not_run"},
		Completeness: &analysis.Completeness{Required: []string{"input_source", "sql_query_candidate", "invoked_callable", "sink_binding"}, Evidence: evidenceRoles(context), Blockers: blockers, Coverage: []analysis.Gap{}, Scope: "declared SQL check produced no candidate sink in the supported handler and helper slice"},
	}
}

func checkRoute(report *analysis.AnalysisReport, id string, c analysis.Check) bool {
	for _, e := range report.Entries {
		if e.ID == id && (e.Kind == "graphql" || e.Kind == "grpc") {
			return c.NormalizedSelector().Matches(e)
		}
		if e.HTTPRoute().ID == id {
			return e.HTTPRoute().Method == c.Method && e.HTTPRoute().PathPattern == c.Path
		}
	}
	return false
}

func gapTouchesSQLSource(g analysis.Gap, use analysis.CandidateUse, fields []string) bool {
	for _, d := range use.Dependencies {
		if !fieldDependency(d, fields) {
			continue
		}
		for _, e := range append([]analysis.Evidence{d.Source}, d.Transfers...) {
			// Enclosing concatenations include sibling operands; only an actual
			// transfer on this source's path makes a call-result gap relevant.
			if e.Kind != "input_source" && e.Kind != "call_argument_dependency" {
				continue
			}
			if g.At.File == e.Span.File && g.At.StartByte >= e.Span.StartByte && g.At.EndByte <= e.Span.EndByte {
				return true
			}
		}
	}
	return false
}

func (s *moduleSet) registrationCheck(report *analysis.AnalysisReport, c analysis.Check, context []analysis.Evidence, gaps []analysis.Gap) analysis.CandidateUse {
	var route analysis.Route
	for _, e := range report.Entries {
		if e.HTTPRoute().Method == c.Method && e.HTTPRoute().PathPattern == c.Path {
			route = e.HTTPRoute()
			break
		}
	}
	use := analysis.CandidateUse{ID: fmt.Sprintf("check:%s:%s", route.ID, c.ID), EntryID: route.ID, Kind: "account_creation_candidate", Check: &c, Context: context, Dependencies: []analysis.Dependency{}, Gaps: []analysis.Gap{}, Assessment: analysis.Assessment{Status: "not_run"}}
	use.Completeness = &analysis.Completeness{Required: []string{"invoked_callable", "persistence_mapping", "model_constraints"}, Evidence: evidenceRoles(context), Blockers: append([]analysis.Gap{}, gaps...), Coverage: []analysis.Gap{}, Scope: "registration middleware and generated persistence under the declared framework model"}
	m := s.modules[route.Registration.File]
	generated, models := s.persistenceEvidence(m, c.Path)
	use.Context = append(use.Context, generated...)
	use.Context = append(use.Context, models...)
	use.Completeness.Evidence["persistence_mapping"] = generated
	use.Completeness.Evidence["model_constraints"] = models
	if len(generated) > 0 {
		use.Sink = generated[len(generated)-1]
	} else {
		use.Completeness.Blockers = append(use.Completeness.Blockers, analysis.Gap{Kind: "persistence_unresolved", Detail: "no supported framework creation mapping for this route", At: route.Registration})
	}
	// Each supported middleware body contributes explicit branch/successor edges.
	for _, e := range context {
		if e.Kind != "invoked_callable" {
			continue
		}
		module := s.modules[e.Span.File]
		if module == nil {
			continue
		}
		body := nodeAt(module.tree.RootNode(), e.Span.StartByte, e.Span.EndByte)
		if body == nil {
			continue
		}
		edges, missing := controlContext(module, body)
		use.ControlEdges = append(use.ControlEdges, edges...)
		use.Completeness.Blockers = append(use.Completeness.Blockers, missing...)
		use.Completeness.Evidence["control_flow"] = append(use.Completeness.Evidence["control_flow"], e)
	}
	use.Completeness.Required = append(use.Completeness.Required, "control_flow")
	use.Gaps = append(use.Gaps, use.Completeness.Blockers...)
	return use
}

func (s *moduleSet) queryBinding(use analysis.CandidateUse) []analysis.Evidence {
	m := s.modules[use.Sink.Span.File]
	if m == nil {
		return nil
	}
	call := nodeAt(m.tree.RootNode(), use.Sink.Span.StartByte, use.Sink.Span.EndByte)
	if call == nil {
		return nil
	}
	fn := call.ChildByFieldName("function")
	if fn == nil {
		return nil
	}
	obj := fn.ChildByFieldName("object")
	if obj == nil {
		return nil
	}
	name := obj.Utf8Text(m.src)
	parts := strings.Split(name, ".")
	if shadowed(call, parts[0], m.src) {
		return nil
	}
	target := m
	if len(parts) == 2 {
		imp, ok := m.imports[parts[0]]
		if !ok || imp.name != "*" {
			return nil
		}
		target = s.importModule(m, imp.module)
		if target == nil {
			return nil
		}
		name = parts[1]
		if !exportedName(target, name) {
			return nil
		}
	}
	return sequelizeBinding(target, name, 0)
}

// buildChecks evaluates each registration independently, including missing-sink
// and persistence checks. Scope and helper limits cannot leak from sibling entries.
func (s *moduleSet) buildChecks(report *analysis.AnalysisReport, checks []analysis.Check) {
	selected := []analysis.CandidateUse{}
	for _, check := range checks {
		for _, entry := range report.Entries {
			selector := check.NormalizedSelector()
			if !selector.Matches(entry) {
				continue
			}
			contexts := []analysis.InvocationContext{}
			for _, ctx := range report.InvocationContexts {
				if ctx.EntryID == entry.ID && selector.MatchesContext(report, ctx) {
					contexts = append(contexts, ctx)
				}
			}
			for _, ctx := range contexts {
				scoped := *report
				scopedEntry := entry
				for _, b := range report.DispatchBindings {
					if b.ID == ctx.DispatchBindingID {
						for _, reg := range report.Registrations {
							if reg.ID == b.RegistrationID {
								scopedEntry.Location = reg.Origin
							}
						}
					}
				}
				scoped.Entries = []analysis.EntryPoint{scopedEntry}
				scoped.Uses = nil
				scoped.Gaps = nil
				for _, u := range report.Uses {
					if u.EntryID == entry.ID && (u.InvocationContextID == ctx.ID || u.InvocationContextID == "") {
						scoped.Uses = append(scoped.Uses, u)
					}
				}
				if entry.Kind == "http" {
					legacy := check
					legacy.Method = entry.HTTP.Method
					legacy.Path = entry.HTTP.Path
					s.buildEntryChecks(&scoped, []analysis.Check{legacy})
					for i := range scoped.Uses {
						if scoped.Uses[i].Check != nil && scoped.Uses[i].Check.ID == check.ID {
							copy := check
							scoped.Uses[i].Check = &copy
							scoped.Uses[i].InvocationContextID = ctx.ID
						}
					}
				} else if (entry.Kind == "graphql" || entry.Kind == "grpc") && s.modules[entry.Location.Span.File] != nil && (check.Kind == "sql_query" || check.Kind == "nosql_query") {
					if len(scoped.Uses) == 0 {
						scoped.Gaps = append(scoped.Gaps, analysis.Gap{Kind: "check_operation_missing", Detail: check.ID + ": no supported operation in " + entry.ID, At: entry.Location.Span})
					} else {
						s.buildEntryChecks(&scoped, []analysis.Check{check})
					}
				} else {
					applyContextCheck(&scoped, check, entry, ctx)
				}
				for _, u := range scoped.Uses {
					if u.Kind != "input_validation_candidate" {
						selected = append(selected, u)
					}
				}
				report.Gaps = append(report.Gaps, scoped.Gaps...)
			}
		}
	}
	for _, u := range report.Uses {
		if u.Kind == "input_validation_candidate" {
			selected = append(selected, u)
		}
	}
	report.Uses = selected
}

// applyContextCheck carries declared requirements onto existing evidence only.
// Unsupported or zero-use contexts retain coverage gaps rather than invented sinks.
func applyContextCheck(r *analysis.AnalysisReport, check analysis.Check, entry analysis.EntryPoint, ctx analysis.InvocationContext) {
	selected := []analysis.CandidateUse{}
	for _, old := range r.Uses {
		if old.EntryID != entry.ID || old.InvocationContextID != ctx.ID || old.Kind != check.Kind+"_candidate" {
			continue
		}
		use := old
		use.ID += "/" + check.ID
		copy := check
		use.Check = &copy
		use.Assessment = analysis.Assessment{Status: "not_run"}
		if old.Completeness != nil {
			c := *old.Completeness
			c.Required = append([]string(nil), c.Required...)
			c.Blockers = append([]analysis.Gap(nil), c.Blockers...)
			c.Evidence = map[string][]analysis.Evidence{}
			for role, items := range old.Completeness.Evidence {
				c.Evidence[role] = append([]analysis.Evidence(nil), items...)
			}
			use.Completeness = &c
		} else {
			use.Completeness = &analysis.Completeness{Required: []string{"entry_registration", "dispatch_binding", "invoked_callable", "input_source", "sink_binding"}, Evidence: evidenceRoles(use.Context), Blockers: []analysis.Gap{{Kind: "check_evidence_unresolved", Detail: "operation claim completeness was not established"}}}
		}
		sources := []analysis.Evidence{}
		for _, d := range use.Dependencies {
			if fieldDependency(d, check.Fields) {
				sources = append(sources, d.Source)
			}
		}
		use.Completeness.Evidence["input_source"] = sources
		selected = append(selected, use)
	}
	if len(selected) == 0 {
		r.Gaps = append(r.Gaps, analysis.Gap{Kind: "check_operation_missing", Detail: check.ID + ": no supported operation matched in entry " + entry.ID + " context " + ctx.ID, At: entry.Location.Span})
	}
	r.Uses = selected
}

func checkContextMatches(r *analysis.AnalysisReport, c analysis.Check, u analysis.CandidateUse) bool {
	for _, ctx := range r.InvocationContexts {
		if ctx.ID == u.InvocationContextID {
			return c.NormalizedSelector().MatchesContext(r, ctx)
		}
	}
	return false
}
