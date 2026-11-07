package parse

import (
	"sort"
	"strings"

	"github.com/zazzcode/zazzles/internal/analysis"
)

// linkCrossTierXSS links a browser output that reads an API response field to the
// one server route whose JSON response provides that field. The browser path is
// joined to the server origin; unmatched, ambiguous or constant fields stay Review.
func (s *moduleSet) linkCrossTierXSS(report *analysis.AnalysisReport) {
	for i := range report.Uses {
		u := &report.Uses[i]
		x := u.XSS
		if u.Kind != "xss_candidate" || x == nil || x.Type != "cross_tier" || x.OriginResolved || x.ResponsePath == "" {
			continue
		}
		if x.ResponseMethod == "" {
			continue
		}
		var matched []jsonProducer
		routes := map[string]bool{}
		for _, p := range s.producers {
			if strings.EqualFold(p.route.Method, x.ResponseMethod) && routePatternMatch(p.route.PathPattern, x.ResponsePath) {
				matched = append(matched, p)
				routes[p.route.ID] = true
			}
		}
		_, restRoute := s.restOrigins(x.ResponsePath, "")
		restRoute = restRoute && strings.EqualFold(x.ResponseMethod, "GET")
		if len(routes) > 1 || (len(routes) == 0 && !restRoute) {
			detail := "No server JSON response matches " + x.ResponseMethod + " " + x.ResponsePath + "."
			if len(routes) > 1 {
				detail = "More than one server route matches " + x.ResponseMethod + " " + x.ResponsePath + "."
			}
			u.Gaps = append(u.Gaps, analysis.Gap{Kind: "response_producer_unresolved", Detail: detail, At: u.Sink.Span})
			continue
		}
		// Each browser path has its own field; one sink can read several from a response.
		var resolved, unresolved []analysis.Dependency
		for _, d := range u.Dependencies {
			if d.Source.Kind != "api_response" {
				resolved = append(resolved, d)
				continue
			}
			field := d.ResponseField
			if field == "" {
				field = x.ResponseField
			}
			var origins []analysis.Dependency
			if field != "" && field != "*" {
				for _, p := range matched {
					for _, o := range s.fieldOrigins(p.value, field) {
						o.Transfers = append(append([]analysis.Evidence{}, o.Transfers...), p.sink)
						origins = append(origins, o)
					}
				}
				if len(matched) == 0 && restRoute {
					origins, _ = s.restOrigins(x.ResponsePath, field)
				}
			}
			if len(origins) == 0 {
				unresolved = append(unresolved, d)
				continue
			}
			for _, o := range origins {
				o.Transfers = append(append(append([]analysis.Evidence{}, o.Transfers...), d.Source), d.Transfers...)
				resolved = append(resolved, o)
			}
		}
		linked := 0
		for _, d := range resolved {
			if d.Source.Kind != "unresolved_source" {
				linked++
			}
		}
		if linked == 0 {
			kind, detail := "response_field_unresolved", "The producing route does not establish request-derived data in response field "+x.ResponseField+"."
			if x.ResponseField == "" || x.ResponseField == "*" {
				detail = "The browser value's response field is not a single established JSON path."
			}
			u.Gaps = append(u.Gaps, analysis.Gap{Kind: kind, Detail: detail, At: u.Sink.Span})
			continue
		}
		if len(resolved) > 64 {
			resolved = resolved[:64]
			u.Gaps = append(u.Gaps, analysis.Gap{Kind: "dependency_limit", Detail: "more than 64 linked cross-tier paths; remaining paths unexamined", At: u.Sink.Span})
		}
		f := flow{set: s}
		protection, reason, paths := x.Protection, x.ProtectionReason, x.Paths
		if x.Protection != "encoded" && x.Protection != "sanitized" || u.Sink.Kind == "angular_output" {
			if u.Sink.Kind == "angular_output" {
				protection, reason, paths = f.angularPathProtection(value{deps: resolved}, x.OutputContext)
			} else {
				var protections []string
				protection, reason, protections = f.xssPathProtection(value{deps: resolved}, x.OutputContext, false)
				paths = xssPaths(protections, nil)
			}
		}
		// An unlinked sibling field cannot be protected by, or hide, a linked unsafe path.
		if len(unresolved) > 0 && protection != "raw" && protection != "ineffective" {
			u.Gaps = append(u.Gaps, analysis.Gap{Kind: "response_field_unresolved", Detail: "A sibling response field has no established origin.", At: u.Sink.Span})
			continue
		}
		u.Dependencies = append(resolved, unresolved...)
		x.Protection, x.ProtectionReason, x.Paths = protection, reason, paths
		x.OriginResolved = true
		for id := range routes {
			x.RelatedEntries = append(x.RelatedEntries, id)
		}
		sort.Strings(x.RelatedEntries)
	}
}

// routePatternMatch compares a server route pattern with a client request path;
// a parameter segment on either side matches one segment of the other.
func routePatternMatch(server, client string) bool {
	a := strings.Split(strings.Trim(server, "/"), "/")
	b := strings.Split(strings.Trim(client, "/"), "/")
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if strings.HasPrefix(a[i], ":") || strings.HasPrefix(b[i], ":") {
			continue
		}
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
