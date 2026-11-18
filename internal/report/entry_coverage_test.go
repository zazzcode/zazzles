package report

import (
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/pipeline"
)

func TestEntryProtectionCoverage(t *testing.T) {
	for _, fixture := range []string{"javascript/graphql", "javascript/grpc"} {
		t.Run(fixture, func(t *testing.T) {
			r, err := pipeline.Analyze("../parse/testdata/"+fixture, "")
			if err != nil {
				t.Fatal(err)
			}
			originalUses := len(r.Uses)
			// Parsed candidates test actual adapters; catalog additions exercise the separate
			// presenter boundary for alternatives and transport relationships.
			e := r.Entries[0]
			var binding analysis.DispatchBinding
			for _, b := range r.DispatchBindings {
				if b.CallableID != "" {
					binding = b
					for _, entry := range r.Entries {
						if entry.ID == b.EntryID {
							e = entry
							break
						}
					}
					break
				}
			}
			if binding.ID == "" {
				t.Fatal("expected parsed target")
			}
			alternative := binding
			alternative.ID += "-alternative"
			alternative.Alternative = "second supported target"
			for _, b := range r.DispatchBindings {
				if b.CallableID != "" && b.CallableID != binding.CallableID {
					alternative.CallableID = b.CallableID
					break
				}
			}
			if alternative.CallableID == binding.CallableID {
				t.Fatal("second callable missing")
			}
			unresolved := binding
			unresolved.ID += "-unknown"
			unresolved.CallableID = ""
			unresolved.Resolution = "unresolved"
			unresolved.Alternative = "unknown remainder"
			unresolved.Gaps = []analysis.Gap{{Kind: "acceptance_unknown_alternative", Detail: "Runtime target remains unknown", At: e.Location.Span}}
			r.DispatchBindings = append(r.DispatchBindings, alternative, unresolved)
			// A transport relationship is metadata, never a second invocation of each resolver.
			for i := range r.Entries {
				if r.Entries[i].ID == e.ID {
					r.Entries[i].Transports = []analysis.TransportAssociation{{Kind: "http", Evidence: []analysis.Evidence{e.Location}}, {Kind: "websocket", Evidence: []analysis.Evidence{e.Location}}}
				}
			}
			if err := r.Catalog().Validate(); err != nil {
				t.Fatal(err)
			}
			saved, html, run := dynamicBundle(t, r)
			if len(saved.Uses) != originalUses || len(saved.Findings) != originalUses || len(run["results"].([]any)) != originalUses {
				t.Fatal("alternatives/transports duplicated uses")
			}
			if !strings.Contains(html, "acceptance_unknown_alternative") || !strings.Contains(html, "Runtime target remains unknown") || !strings.Contains(html, "unknown remainder") {
				t.Fatal("unresolved alternative hidden")
			}
			if !strings.Contains(strings.ToLower(html), "dispatch") {
				t.Fatal("dispatch disclosure missing")
			}
			for _, f := range saved.Findings {
				if f.Status == "protected_for_claim" {
					t.Fatal("unassessed SQL catalog acquired protection")
				}
			}
		})
	}
}
