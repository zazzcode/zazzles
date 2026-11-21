package judge

import (
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
	"testing"
)

// A model answer of same_site_relative or parsed_origin_check yields Protected
// only when the recorded predicate facts show no permitted bypass form.
func TestP2RedirectPredicatePolicy(t *testing.T) {
	safe := `!(typeof to==='string' && to.startsWith('/') && !to.startsWith('//') && !to.includes('\\'))`
	for _, tt := range []struct{ name, body, restriction, want string }{
		{"relative control", `const to=req.query.to;if(` + safe + `)return;res.redirect(to)`, "same_site_relative", "protected_for_claim"},
		{"regex excluding both", `const to=req.query.to;if(!/^\/[^/\\]/.test(to))return;res.redirect(to)`, "same_site_relative", "protected_for_claim"},
		{"parsed origin control", `const to=req.query.to;if(new URL(to,'https://site.example').origin!=='https://site.example')return;res.redirect(to)`, "parsed_origin_check", "protected_for_claim"},
		{"parsed url control", `const to=req.query.to;const u=new URL(to,'https://site.example');if(u.host!=='site.example')return;res.redirect(u.href)`, "parsed_origin_check", "protected_for_claim"},
		{"lab regex permits backslash", `const to=req.query.to;if(!/^\/[^/]/.test(to))return;res.redirect(to)`, "same_site_relative", "needs_evidence"},
		{"leading slash only", `const to=req.query.to;if(!to.startsWith('/'))return;res.redirect(to)`, "same_site_relative", "needs_evidence"},
		{"no backslash test", `const to=req.query.to;if(!(to.startsWith('/') && !to.startsWith('//')))return;res.redirect(to)`, "same_site_relative", "needs_evidence"},
		{"no double-slash test", `const to=req.query.to;if(!(to.startsWith('/') && !to.includes('\\')))return;res.redirect(to)`, "same_site_relative", "needs_evidence"},
		{"origin prefix without slash", `const to=req.query.to;if(!to.startsWith('https://site.example'))return;res.redirect(to)`, "parsed_origin_check", "needs_evidence"},
		{"parsed origin against request value", `const to=req.query.to;if(new URL(to,'https://site.example').origin!==req.headers.origin)return;res.redirect(to)`, "parsed_origin_check", "needs_evidence"},
		{"decode after check", `const to=req.query.to;if(` + safe + `)return;res.redirect(decodeURIComponent(to))`, "same_site_relative", "needs_evidence"},
		{"reassigned after check", `let to=req.query.to;if(` + safe + `)return;to=req.query.other;res.redirect(to)`, "same_site_relative", "needs_evidence"},
		{"check one variable redirect another", `const a=req.query.a,b=req.query.b;if(!(a.startsWith('/') && !a.startsWith('//') && !a.includes('\\')))return;res.redirect(b)`, "same_site_relative", "needs_evidence"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			u, _ := familyFixtureUse(t, map[string]string{"server.js": `const express=require('express');const app=express();app.get('/x',(req,res)=>{` + tt.body + `;res.end()});`}, "open_redirect_candidate")
			a := analysis.Assessment{Status: "completed", QuestionVersion: analysispacks.RedirectProtocol, Answers: map[string]string{"destination_control": "path_only", "destination_restriction": tt.restriction, "protection_coverage": "complete"}}
			applyPolicy(u, &a)
			if a.FindingStatus != tt.want {
				t.Fatalf("got %s want %s facts=%q gaps=%+v", a.FindingStatus, tt.want, u.Completeness.ModelFacts, a.BlockingGaps)
			}
			if a.FindingStatus == "protected_for_claim" && a.Protection != "sufficient" {
				t.Errorf("protection %s", a.Protection)
			}
		})
	}
}
