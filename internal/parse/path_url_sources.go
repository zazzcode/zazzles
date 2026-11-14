package parse

import (
	"regexp"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
)

// requestURLMembers are the Express request members that carry the URL path. The
// shared acquisition models only body, query, params, headers and cookies, so these
// are admitted for path claims alone.
var requestURLMembers = map[string]bool{"path": true, "url": true, "originalUrl": true, "baseUrl": true, "file": true, "files": true}

// withRequestURLPaths runs the handler a second time with the request URL members
// as sources and keeps only the path-traversal candidates that pass found. A
// candidate present in both passes is replaced by the second, which is a superset.
// Every other family's uses are those of the first pass, so their evidence is unchanged.
func (s *moduleSet) withRequestURLPaths(first flow, m, hm *sourceModule, body *sitter.Node, call *sitter.Node, seeds registrationSeeds, context []analysis.Evidence, e analysis.EntryPoint, parts map[string]string, r analysis.Route) []analysis.CandidateUse {
	if first.pathOnly {
		return first.uses
	}
	needed := first.request != "" && regexp.MustCompile(`\b`+regexp.QuoteMeta(first.request)+`\.(path|url|originalUrl|baseUrl|file|files)\b`).MatchString(string(hm.src[body.StartByte():body.EndByte()]))
	if first.request != "" {
		walkCalls(body, func(call *sitter.Node) {
			fn := call.ChildByFieldName("function")
			for fn != nil && fn.Kind() == "parenthesized_expression" && fn.NamedChildCount() == 1 {
				fn = fn.NamedChild(0)
			}
			if fn != nil && fn.Kind() == "member_expression" {
				if p := fn.ChildByFieldName("property"); p != nil && p.Utf8Text(hm.src) == "render" {
					needed = true
				}
			}
			if fn != nil && isFunction(fn) {
				needed = true
			}
			if _, _, ok := unzipperBufferCall(hm, call); ok {
				needed = true
			}
		})
	}
	if !needed {
		return first.uses
	}
	second := flow{pathOnly: true, module: first.module, set: s, entry: first.entry, invocation: first.invocation, registration: first.registration, request: first.request,
		constants: seeds, env: map[string]value{}, context: append([]analysis.Evidence{}, first.context[:2]...), helpers: &helperExpansion{budget: 24, stack: map[string]bool{}}, facts: newInputFacts(), parts: parts, urlSources: true}
	second.context = append(second.context, context...)
	second.gaps = append([]analysis.Gap{}, e.Gaps...)
	second.seedInvocation()
	for name, node := range seeds {
		second.env[name] = second.eval(node)
	}
	second.gaps = append(second.gaps, analysis.Gap{Kind: "middleware_unresolved", Detail: "effective middleware/guard chain is not modeled", At: r.Registration})
	if r.Framework == "express" {
		s.noteMiddlewareFields(&second, m, call)
	}
	second.statements(body)
	out := append([]analysis.CandidateUse{}, first.uses...)
	for _, u := range second.uses {
		if u.Kind != "path_traversal_candidate" {
			continue
		}
		replaced := false
		for i := range out {
			if out[i].ID == u.ID {
				out[i], replaced = u, true
			}
		}
		if !replaced {
			out = append(out, u)
		}
	}
	return out
}
