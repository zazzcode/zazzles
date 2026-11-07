package main

import (
	"context"
	"fmt"
	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/judge"
	"github.com/zazzcode/zazzles/internal/parse"
	"io"
)

type discoveryOptions struct {
	Enabled bool
	Limit   int
}

func runNodeDiscovery(root, entry string, r *analysis.AnalysisReport, c *judge.Client, limit int, traces string, stderr io.Writer) bool {
	proposals := r.Discovery
	verifier, err := parse.NewDiscoveryVerifier(root, r)
	if err != nil {
		r.Gaps = append(r.Gaps, analysis.Gap{Kind: "discovery_failed", Detail: err.Error()})
		return true
	}
	r.Discovery = nil
	failed, attempted := false, 0
	for _, p := range proposals {
		p = verifier.Verify(p)
		if p.State != "verified_existing" && p.State != "rejected" {
			if attempted >= limit {
				p.ModelStatus = "not_run"
				p.Reason = "discovery request limit reached; binding remains provisional"
			} else {
				attempted++
				var tr judge.DecisionTrace
				p, tr = c.DiscoverTrace(context.Background(), p)
				if traces != "" {
					if err := writeTrace(traces, p.ID, tr); err != nil {
						fmt.Fprintf(stderr, "scan: discovery trace not saved: %v\n", err)
						failed = true
					}
				}
				if p.ModelChoice != "" {
					verifier.Refresh()
					p = verifier.Verify(p)
				}
			}
		}
		if p.State != "verified_existing" {
			failed = true
			r.Gaps = append(r.Gaps, analysis.Gap{Kind: "discovery_unverified", Detail: p.Reason, At: p.Registration.Span})
		}
		r.Discovery = append(r.Discovery, p)
	}
	if len(proposals) == 1000 {
		failed = true
		r.Gaps = append(r.Gaps, analysis.Gap{Kind: "discovery_inventory_limit", Detail: "discovery syntax inventory reached its 1000-alternative bound"})
	}
	r.Limitations = append(r.Limitations, fmt.Sprintf("Model-assisted Node acquisition discovery: %d attempts (cap %d), %d source alternatives. Proposals are separate from vulnerability findings. Verified-existing records reuse static bindings; unfamiliar wrappers remain provisional. This bounded inventory is not complete framework or application coverage.", attempted, limit, len(proposals)))
	return failed
}
