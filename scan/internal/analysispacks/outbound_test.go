package analysispacks_test

import (
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
	"github.com/zazzcode/zazzles/scan/internal/pipeline"
)

func TestOutboundComponentSelection(t *testing.T) {
	for _, fixture := range []string{"javascript/outbound", "typescript/outbound", "python/outbound"} {
		r, err := pipeline.Analyze(fixtureRoot(fixture), "")
		if err != nil {
			t.Fatal(err)
		}
		found := 0
		for _, u := range r.Uses {
			if u.Kind != "outbound_http_candidate" {
				continue
			}
			found++
			if u.Components == nil || u.Components.Failure != "" || u.Components.Pack.ID != "pack.outbound" {
				t.Fatalf("selection: %+v", u.Components)
			}
			if !analysispacks.ObservationOnly(u.Kind) || analysispacks.ProtocolFor(u.Kind) != "" {
				t.Fatal("observation gained protocol")
			}
			m, err := analysispacks.ForUse(u)
			if err != nil {
				t.Fatal(err)
			}
			if len(m.Questions) != 0 || len(m.Choices) != 0 {
				t.Fatal("observation gained questionnaire")
			}
			python := strings.HasPrefix(fixture, "python")
			if (m.Contract != nil) != python {
				t.Fatal("contract scope drift")
			}
			if len(u.Components.Components) > analysispacks.MaxComponents {
				t.Fatal("component limit")
			}
			if !python {
				if u.APIModel != nil {
					t.Fatal("shape gained trusted model")
				}
				gaps := map[string]bool{}
				for _, g := range u.Gaps {
					gaps[g.Kind] = true
				}
				if !gaps["sink_binding_unverified"] || !gaps["external_response_unresolved"] {
					t.Fatal("original gaps lost")
				}
			} else {
				// A Python observation remains only for a second-order destination;
				// a request-derived destination is an SSRF claim.
				for _, d := range u.Dependencies {
					if d.Source.Kind == "input_source" {
						t.Fatalf("request value in a Python observation destination: %+v", d)
					}
				}
				if u.Outbound == nil || u.Outbound.DestinationOrigin != analysis.DestinationExternalData {
					t.Fatalf("Python observation origin: %+v", u.Outbound)
				}
			}
		}
		// The verified fetch with a request destination is an SSRF claim in JS/TS;
		// all three request-derived Python calls are.
		want := 4
		if strings.HasPrefix(fixture, "python") {
			want = 1
		}
		if found != want {
			t.Fatalf("%s count=%d want%d", fixture, found, want)
		}
	}
}

func TestOutboundBindingScope(t *testing.T) {
	for _, file := range []string{"server.js", "server.ts", "app.py"} {
		u := analysis.CandidateUse{Kind: "outbound_http_candidate", Sink: analysis.Evidence{Span: analysis.Span{File: file}}}
		if file != "app.py" {
			// Even a valid Python contract and package-like identity cannot certify JS.
			u.APIModel = analysispacks.OutboundContract("requests")
			if _, err := analysispacks.Select(u); err == nil {
				t.Fatal("JS borrowed Python contract")
			}
		} else {
			if _, err := analysispacks.Select(u); err == nil {
				t.Fatal("Python without demonstrated contract accepted")
			}
			u.APIModel = analysispacks.OutboundContract("requests")
			if _, err := analysispacks.Select(u); err == nil {
				t.Fatal("missing binding accepted")
			}
			u.Context = []analysis.Evidence{{Kind: "sink_binding"}}
			if _, err := analysispacks.Select(u); err != nil {
				t.Fatal(err)
			}
			u.APIModel.Library = "unknown-client"
			if _, err := analysispacks.Select(u); err == nil {
				t.Fatal("unsupported library accepted")
			}
		}
	}
}
