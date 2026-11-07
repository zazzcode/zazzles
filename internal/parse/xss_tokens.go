package parse

import (
	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
)

// signedToken is a value passed to a verified jsonwebtoken sign call. A browser
// reads its claims by path, so a claim links to the model field at that same path.
type signedToken struct {
	value value
	sink  analysis.Evidence
}

func (f *flow) noteTokenSigning(fn, args *sitter.Node) {
	if fn.Kind() != "member_expression" || args.NamedChildCount() == 0 {
		return
	}
	obj, prop := fn.ChildByFieldName("object"), fn.ChildByFieldName("property")
	if obj == nil || prop == nil || prop.Utf8Text(f.module.src) != "sign" || f.module.imports[obj.Utf8Text(f.module.src)].module != "jsonwebtoken" {
		return
	}
	if v := f.eval(args.NamedChild(0)); hasModelRows(v, 0) {
		f.set.signedTokens = append(f.set.signedTokens, signedToken{v, f.module.evidence("token_signing", fn)})
	}
}

// tokenClaimCall reports a verified browser JWT decode. The claims are server data,
// never browser input, so their origin must be linked before any claim is made.
func (f *flow) tokenClaimCall(n, fn *sitter.Node) (value, bool) {
	name := fn.Utf8Text(f.module.src)
	imp, ok := f.module.imports[name]
	if !ok || imp.module != "jwt-decode" || shadowed(n, name, f.module.src) {
		return value{}, false
	}
	return value{deps: []analysis.Dependency{{Source: f.module.evidence("token_claim", n), Transfers: []analysis.Evidence{}}}}, true
}

// linkTokenClaims joins a decoded claim to the signed model field at the same path.
// Every signing site must agree on the origin set being non-empty; an unmatched claim
// stays unresolved and blocks the rendering claim.
func (s *moduleSet) linkTokenClaims(report *analysis.AnalysisReport) {
	for i := range report.Uses {
		u := &report.Uses[i]
		if u.Kind != "xss_candidate" || u.XSS == nil {
			continue
		}
		var deps []analysis.Dependency
		claims, linked := 0, 0
		for _, d := range u.Dependencies {
			if d.Source.Kind != "token_claim" {
				deps = append(deps, d)
				continue
			}
			claims++
			found := false
			for _, t := range s.signedTokens {
				for _, o := range s.fieldOrigins(t.value, d.ResponseField) {
					o.Transfers = append(append(append([]analysis.Evidence{}, o.Transfers...), t.sink, d.Source), d.Transfers...)
					deps = append(deps, o)
					found = true
				}
			}
			if found {
				linked++
			} else {
				deps = append(deps, d)
			}
		}
		if claims == 0 {
			continue
		}
		u.XSS.Type, u.XSS.OriginResolved = "cross_tier", linked > 0
		if linked == 0 {
			u.Gaps = append(u.Gaps, analysis.Gap{Kind: "token_origin_unresolved", Detail: "No signed model field is established for this token claim.", At: u.Sink.Span})
			continue
		}
		u.Dependencies = deps
		f := flow{set: s}
		if u.Sink.Kind == "angular_output" {
			u.XSS.Protection, u.XSS.ProtectionReason, u.XSS.Paths = f.angularPathProtection(value{deps: deps}, u.XSS.OutputContext)
		}
	}
}
