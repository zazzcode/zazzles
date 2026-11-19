package langjs

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
			// A Pages Router API route (ALL) answers every method.
			if (strings.EqualFold(p.route.Method, x.ResponseMethod) || (p.route.Method == "ALL" && p.route.Framework == "nextjs-pages")) && routePatternMatch(p.route.PathPattern, x.ResponsePath) {
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

// linkOwnAPIOrigins resolves each own-API response dependency (a server
// helper's fetch of this repository's route) to the origin of the value the
// producing route returns for the read field: storage, request or another
// origin. The request value that selected the row stays selector context.
// When no single route or field origin is established the dependency reverts
// to the call's arguments with unknown_transfer, the flow it had before.
func (s *moduleSet) linkOwnAPIOrigins(report *analysis.AnalysisReport) {
	if len(s.ownAPI) == 0 {
		return
	}
	for i := range report.Uses {
		u := &report.Uses[i]
		var deps []analysis.Dependency
		changed := false
		moved := map[int][]int{}
		for old, d := range u.Dependencies {
			start := len(deps)
			call, ok := s.ownAPI[ownAPIKey(d.Source)]
			if !ok || d.Source.Kind != "api_response" {
				deps = append(deps, d)
			} else {
				changed = true
				origins := s.ownAPIFieldOrigins(call.path, d.ResponseField)
				if len(origins) == 0 {
					origins = call.fallback.deps
					if len(origins) > 0 && !call.precise {
						u.Gaps = append(u.Gaps, analysis.Gap{Kind: "unknown_transfer", Detail: "call may transform or discard its arguments: own API response field " + d.ResponseField + " of GET " + call.path + " has no established origin", At: d.Source.Span})
					}
				}
				for _, o := range origins {
					o.SinkSlot = d.SinkSlot
					o.Transfers = append(append(append([]analysis.Evidence{}, o.Transfers...), d.Source), d.Transfers...)
					deps = append(deps, o)
				}
			}
			for k := start; k < len(deps); k++ {
				moved[old] = append(moved[old], k)
			}
		}
		if changed {
			u.Dependencies = deps
			remapDependencies(u, moved)
			// Rendering a stored row field through the API is stored output
			// whose writer is not linked; it stays Review like any stored read.
			if x := u.XSS; x != nil && allStoredReads(deps) {
				x.Type, x.OriginResolved = "stored", false
			}
		}
	}
}

// remapDependencies rewrites the dependency indexes of a use's facts after a
// dependency was replaced by zero or more resolved origins. A per-path fact is
// repeated for each origin; a dropped dependency drops its paths.
func remapDependencies(u *analysis.CandidateUse, moved map[int][]int) {
	ints := func(in []int) []int {
		out := []int{}
		for _, i := range in {
			out = append(out, moved[i]...)
		}
		return out
	}
	if p := u.Path; p != nil {
		for k := range p.Operands {
			p.Operands[k].Dependencies = ints(p.Operands[k].Dependencies)
		}
		var flows []analysis.PathFlow
		for _, f := range p.Paths {
			for _, n := range moved[f.Dependency] {
				f.Dependency = n
				flows = append(flows, f)
			}
		}
		p.Paths = flows
	}
	if c := u.Command; c != nil {
		for k := range c.Operands {
			c.Operands[k].Dependencies = ints(c.Operands[k].Dependencies)
		}
		c.Paths = commandPaths(c.Paths, moved)
	}
	if o := u.Outbound; o != nil {
		o.Paths = commandPaths(o.Paths, moved)
	}
	if x := u.XSS; x != nil && len(x.Paths) > 0 {
		var paths []analysis.XSSPath
		for _, p := range x.Paths {
			for _, n := range moved[p.Dependency] {
				p.Dependency = n
				paths = append(paths, p)
			}
		}
		x.Paths = paths
	}
}

func commandPaths(in []analysis.CommandPath, moved map[int][]int) []analysis.CommandPath {
	var out []analysis.CommandPath
	for _, p := range in {
		for _, n := range moved[p.Dependency] {
			p.Dependency = n
			out = append(out, p)
		}
	}
	return out
}

// ownAPIFieldOrigins returns the origins the one GET route matching path gives
// response field field. A stored row field whose writers are not modeled is a
// storage read of that field.
func (s *moduleSet) ownAPIFieldOrigins(path, field string) []analysis.Dependency {
	if field == "" || field == "*" {
		return nil
	}
	routes := map[string]bool{}
	var matched []jsonProducer
	for _, p := range s.producers {
		if (strings.EqualFold(p.route.Method, "GET") || p.route.Method == "ALL" && p.route.Framework == "nextjs-pages") && routePatternMatch(p.route.PathPattern, path) {
			matched = append(matched, p)
			routes[p.route.ID] = true
		}
	}
	if len(routes) > 1 {
		// The URL template names one dynamic route; a static sibling such as
		// /api/flags/count needs a literal the template does not give.
		routes, matched = map[string]bool{}, shapeMatches(matched, path)
		for _, p := range matched {
			routes[p.route.ID] = true
		}
	}
	if len(routes) != 1 {
		return nil
	}
	var out []analysis.Dependency
	for _, p := range matched {
		for _, o := range responseField(p.value, field) {
			o.Transfers = append(append([]analysis.Evidence{}, o.Transfers...), p.sink)
			out = append(out, o)
		}
	}
	return out
}

// responseField is the origin of one field of a route's JSON response value.
// A value the handler built in place keeps its dependencies (a request echo
// stays a request origin); a model row's column is a storage read of that
// column. Second-order writers of the column are not followed here: whether a
// write reaches it is judged from the write-set evidence, not linked by rule.
func responseField(v value, field string) []analysis.Dependency {
	segments := strings.Split(strings.ReplaceAll(field, "[]", ".[]"), ".")
	for _, segment := range segments {
		if segment == "" || segment == "[]" && v.model != "" {
			continue
		}
		if next, ok := v.fields[segment]; ok {
			v = next
			continue
		}
		if v.model == "" || v.read == nil {
			return nil
		}
		read := *v.read
		read.Kind = "storage_read"
		// No storage key: linking the column's writers would be a verdict on
		// second-order origin, which the write-set evidence leaves to the model.
		return []analysis.Dependency{{Source: read, Transfers: []analysis.Evidence{}}}
	}
	var out []analysis.Dependency
	for _, d := range v.deps {
		if d.StorageKey != "" {
			d.Source.Kind, d.StorageKey = "storage_read", ""
		}
		out = append(out, d)
	}
	return out
}

// shapeMatches keeps the producers whose route aligns segment for segment with
// path: a client placeholder with a route parameter, a literal with an equal
// literal.
func shapeMatches(in []jsonProducer, path string) []jsonProducer {
	b := strings.Split(strings.Trim(path, "/"), "/")
	var out []jsonProducer
	for _, p := range in {
		a := strings.Split(strings.Trim(p.route.PathPattern, "/"), "/")
		if len(a) != len(b) {
			continue
		}
		ok := true
		for i := range a {
			param, placeholder := strings.HasPrefix(a[i], ":"), strings.HasPrefix(b[i], ":")
			if param != placeholder || !param && a[i] != b[i] {
				ok = false
				break
			}
		}
		if ok {
			out = append(out, p)
		}
	}
	return out
}

func allStoredReads(deps []analysis.Dependency) bool {
	if len(deps) == 0 {
		return false
	}
	for _, d := range deps {
		if d.Source.Kind != "storage_read" {
			return false
		}
	}
	return true
}
