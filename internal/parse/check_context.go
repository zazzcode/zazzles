package parse

import (
	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
)

func nodeAt(n *sitter.Node, start, end int) *sitter.Node {
	for i := uint(0); i < n.NamedChildCount(); i++ {
		c := n.NamedChild(i)
		if int(c.StartByte()) <= start && int(c.EndByte()) >= end {
			if found := nodeAt(c, start, end); found != nil {
				return found
			}
		}
	}
	if int(n.StartByte()) == start && int(n.EndByte()) == end {
		return n
	}
	return nil
}

// includeHelpers includes definitions even for pre-use calls that return no value,
// since such helpers can validate or mutate the request in place.
func (s *moduleSet) includeHelpers(m *sourceModule, n *sitter.Node, out *[]analysis.Evidence, seen map[string]bool, depth int) {
	names := map[string]bool{}
	for _, field := range s.contextFields {
		names[field] = true
	}
	fn := n
	if n != nil && n.Kind() == "statement_block" {
		fn = n.Parent()
	}
	if fn != nil {
		params := parameterNames(fn, m.src)
		if len(params) > 0 && params[0] != "" {
			names[params[0]] = true
		}
	}
	if n != nil && n.Kind() == "program" {
		var setters func(*sitter.Node)
		setters = func(node *sitter.Node) {
			if node.Kind() == "pair" {
				key := node.ChildByFieldName("key")
				v := node.ChildByFieldName("value")
				if key != nil && v != nil {
					for _, field := range s.contextFields {
						if key.Utf8Text(m.src) == field {
							for i := uint(0); i < v.NamedChildCount(); i++ {
								method := v.NamedChild(i)
								id := method.ChildByFieldName("name")
								if id != nil && id.Utf8Text(m.src) == "set" {
									params := parameterNames(method, m.src)
									if len(params) > 0 {
										names[params[0]] = true
									}
								}
							}
						}
					}
				}
			}
			for i := uint(0); i < node.NamedChildCount(); i++ {
				setters(node.NamedChild(i))
			}
		}
		setters(n)
	}
	s.inputHelpers(m, n, out, seen, depth, names)
}

func (s *moduleSet) chainEvidence(report *analysis.AnalysisReport, check analysis.Check) ([]analysis.Evidence, []analysis.Gap) {
	context := []analysis.Evidence{}
	gaps := []analysis.Gap{}
	middlewareFiles := map[string]bool{}
	seen := map[string]bool{}
	for _, entry := range report.Entries {
		if (entry.Kind == "graphql" || entry.Kind == "grpc") && check.NormalizedSelector().Matches(entry) {
			for _, u := range report.Uses {
				if u.EntryID != entry.ID {
					continue
				}
				context = append(context, u.Context...)
				for _, e := range u.Context {
					if e.Kind != "handler" {
						continue
					}
					m := s.modules[e.Span.File]
					if m == nil {
						continue
					}
					body := nodeAt(m.tree.RootNode(), e.Span.StartByte, e.Span.EndByte)
					if body == nil {
						continue
					}
					params, _ := functionParameters(body.Parent(), m.src)
					if entry.Kind == "grpc" && len(params) > 0 {
						gaps = append(gaps, s.inputHelperGaps(m, body, params[0].name, check.Fields)...)
					} else if len(params) > 1 {
						gaps = append(gaps, s.inputHelperGaps(m, body, params[1].name, check.Fields)...)
					}
					s.includeHelpers(m, body, &context, seen, 0)
				}
			}
			continue
		}
		r := entry.HTTPRoute()
		if r.Method != check.Method || r.PathPattern != check.Path {
			continue
		}
		if c := s.nodeHTTP[entry.ID]; c != nil && r.Framework != "express" {
			extra, missing := s.nativeHTTPChain(c)
			context = append(context, extra...)
			gaps = append(gaps, missing...)
			continue
		}
		m := s.modules[r.Registration.File]
		if m == nil {
			continue
		}
		call := nodeAt(m.tree.RootNode(), r.Registration.StartByte, r.Registration.EndByte)
		if call == nil {
			continue
		}
		if !middlewareFiles[m.file] {
			middlewareFiles[m.file] = true
			global, missing := s.middlewareContext(m, r)
			context = append(context, global...)
			gaps = append(gaps, missing...)
		}
		calls, priorGaps := s.httpPredecessors(m, entry, call)
		gaps = append(gaps, priorGaps...)
		calls = append(calls, call)
		for _, call := range calls {
			context = append(context, m.evidence("route_registration", call))
			args := call.ChildByFieldName("arguments")
			if args == nil {
				continue
			}
			for i := uint(1); i < args.NamedChildCount(); i++ {
				arg := args.NamedChild(i)
				if adapter := s.authenticationAdapter(m, arg); len(adapter) > 0 {
					context = append(context, adapter...)
					continue
				}
				context = append(context, s.wrapperContext(m, arg)...)
				hm, body, req, more := s.handler(m, arg)
				gaps = append(gaps, more...)
				if body == nil {
					continue
				}
				context = append(context, hm.evidence("invoked_callable", body))
				gaps = append(gaps, s.inputHelperGaps(hm, body, req, check.Fields)...)
				s.includeHelpers(hm, body, &context, seen, 0)
			}
		}
	}
	return context, gaps
}

func fieldDependency(d analysis.Dependency, fields []string) bool {
	return analysis.MatchesFields(d, fields)
}

func evidenceRoles(context []analysis.Evidence) map[string][]analysis.Evidence {
	out := map[string][]analysis.Evidence{}
	for _, e := range context {
		out[e.Kind] = append(out[e.Kind], e)
	}
	return out
}
