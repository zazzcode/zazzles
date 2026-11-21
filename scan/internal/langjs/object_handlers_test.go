package langjs

import (
	"testing"
)

// TestObjectLiteralHandlers (close-findings-gaps AC9, D-29): a handler that
// is a shorthand method, a function-valued property or an arrow function of
// an exported object literal resolves; a computed key, spread or reassigned
// export stays unresolved_handler.
func TestObjectLiteralHandlers(t *testing.T) {
	r := analyzeFixture(t, "javascript/object-handlers")
	regs := map[string]string{}
	for _, reg := range r.Registrations {
		regs[reg.ID] = reg.Origin.Text
	}
	got := map[string]string{}
	for _, b := range r.DispatchBindings {
		route := regs[b.RegistrationID]
		if b.Resolution == "resolved" {
			got[route] = "resolved"
			continue
		}
		for _, g := range b.Gaps {
			if g.Kind == "unresolved_handler" {
				got[route] = "unresolved_handler"
			}
		}
	}
	for route, want := range map[string]string{
		"app.get('/chat', routes.chat.get)": "resolved", "app.put('/chat', routes.chat.add)": "resolved", "app.delete('/chat', routes.chat.remove)": "resolved",
		"app.get('/computed', routes.computed.list)": "unresolved_handler", "app.get('/spread', routes.spread.list)": "unresolved_handler", "app.get('/patched', routes.patched.list)": "unresolved_handler",
	} {
		if got[route] != want {
			t.Errorf("%s: %q, want %q (all: %v)", route, got[route], want, got)
		}
	}
	xss := 0
	for _, u := range r.Uses {
		if u.Kind == "xss_candidate" && u.Sink.Span.File == "routes.js" && (u.Sink.Span.StartLine == 4 || u.Sink.Span.StartLine == 7) {
			xss++
		}
	}
	if xss != 2 {
		t.Fatalf("the resolved handlers' bodies are analyzed: %d rendering claims", xss)
	}
}
