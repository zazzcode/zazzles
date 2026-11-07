package parse

import (
	"fmt"
	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
	"strings"
)

// nodeDiscoveryAlternatives shares parsed modules and handler resolution with
// ordinary analysis. It is run only for explicitly requested discovery.
func (s *moduleSet) nodeDiscoveryAlternatives(m *sourceModule, proposals []analysis.DiscoveryProposal, cap int) []analysis.DiscoveryProposal {
	walkCalls(m.tree.RootNode(), func(call *sitter.Node) {
		if len(proposals) >= cap {
			return
		}
		fn, args := call.ChildByFieldName("function"), call.ChildByFieldName("arguments")
		if fn == nil || args == nil || args.NamedChildCount() == 0 {
			return
		}
		routeShape := false
		for i := uint(0); i < args.NamedChildCount(); i++ {
			a := args.NamedChild(i)
			if text, ok := stringLiteral(a, m.src); ok && strings.HasPrefix(text, "/") {
				routeShape = true
			}
			if a.Kind() == "object" && property(a, "handler", m.src) != nil {
				routeShape = true
			}
		}
		if !routeShape {
			return
		}
		var h *sitter.Node
		for i := uint(0); i < args.NamedChildCount(); i++ {
			a := args.NamedChild(i)
			if a.Kind() == "object" {
				if v := property(a, "handler", m.src); v != nil {
					h = v
				}
			} else if isFunction(a) || a.Kind() == "identifier" {
				h = a
			}
		}
		if h == nil {
			return
		}
		hm, body, _, gaps := s.handler(m, h)
		if body == nil || len(gaps) > 0 {
			return
		}
		reg := m.evidence("discovery_registration", call)
		handler := hm.evidence("discovery_handler", body)
		id := snapshotID("discovery", reg, handler.SHA256, fmt.Sprintf("%s:%d", handler.Span.File, handler.Span.StartByte))
		middleware := []analysis.Evidence{}
		for i := uint(0); i < args.NamedChildCount(); i++ {
			a := args.NamedChild(i)
			if a.StartByte() == h.StartByte() {
				continue
			}
			mm, mb, _, g := s.handler(m, a)
			if mb != nil && len(g) == 0 {
				middleware = append(middleware, mm.evidence("discovery_middleware", mb))
			}
		}
		context := []analysis.Evidence{}
		if wm, wrapper := s.resolveCall(m, call); wm != nil && wrapper != nil {
			context = append(context, wm.evidence("discovery_wrapper", wrapper))
		}
		proposals = append(proposals, analysis.DiscoveryProposal{ID: id, Registration: reg, Handler: handler, Context: context, Middleware: middleware, State: "provisional", Reason: "Syntactic registration/handler alternative; runtime binding has not been independently established."})
	})
	return proposals
}
