package langjs

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/parse"
)

// Next.js practice tier: source-established observations of framework
// misconfiguration and boundary mistakes. None uses a model request and none is
// a vulnerability finding; each states what the source establishes.

var secretName = regexp.MustCompile(`(?i)(SECRET|PASSWORD|PASSWD|PRIVATE|TOKEN|API_?KEY|ACCESS_?KEY|SIGNING)`)
var publicEnvRead = regexp.MustCompile(`process\.env\.(NEXT_PUBLIC_[A-Z0-9_]+)`)

type practiceSet struct {
	out  *analysis.AnalysisReport
	seen map[string]bool
}

func (p *practiceSet) add(check, title, status, detail, entry string, evidence ...analysis.Evidence) {
	key := check + "|" + entry + "|" + detail
	for _, e := range evidence {
		key += fmt.Sprintf("|%s:%d", e.Span.File, e.Span.StartByte)
	}
	if p.seen[key] {
		return
	}
	p.seen[key] = true
	id := parse.SnapshotID("practice", firstEvidence(evidence), check, key)
	p.out.Practice = append(p.out.Practice, analysis.PracticeObservation{ID: id, Check: check, Title: title, Status: status, Detail: detail, Entry: entry, Evidence: append([]analysis.Evidence{}, evidence...)})
}

func firstEvidence(e []analysis.Evidence) analysis.Evidence {
	if len(e) > 0 {
		return e[0]
	}
	return analysis.Evidence{Kind: "file", Span: analysis.Span{File: "package.json", StartLine: 1, EndLine: 1}}
}

// nextPractice runs every practice check over the analyzed report.
func (s *moduleSet) nextPractice(out *analysis.AnalysisReport, selected []string) {
	if s.next == nil || len(s.next.projects) == 0 {
		return
	}
	ps := &practiceSet{out: out, seen: map[string]bool{}}
	s.practiceBoundaries(ps)
	entries := map[string]analysis.EntryPoint{}
	for _, e := range out.Entries {
		entries[e.ID] = e
	}
	for _, p := range s.next.projects {
		s.practiceVersions(ps, p)
		s.practiceConfigBoundaries(ps, p)
		s.practiceRewrites(ps, p)
		s.practiceSecurityHeaders(ps, p)
		s.practiceMiddleware(ps, p, out)
		s.practiceEnvFiles(ps, p)
	}
	for _, file := range selected {
		m := s.modules[file]
		if m == nil || m.tree.RootNode().HasError() || s.nextProjectFor(file) == nil {
			continue
		}
		client := reactClientModule(m) && moduleDirective(m) == "use client"
		s.practiceModuleBoundaries(ps, m, client, out)
		if client {
			s.practiceClientModule(ps, m)
			s.practiceClientAuthorization(ps, m, out)
		}
		if s.next.routeFiles[file] {
			s.practiceRouteModule(ps, m)
		}
		if p := s.nextProjectFor(file); p != nil {
			if _, base, _, ok := p.appSegments(file); ok && (base == "page" || base == "layout") && !client {
				s.practiceGatedRendering(ps, m)
			}
		}
	}
	for _, u := range out.Uses {
		s.practiceUse(ps, u, entries[u.EntryID])
	}
	for _, r := range s.next.clientRequests {
		s.practiceClientRequest(ps, r)
	}
	// NX-BP-16: Host / forwarded headers in a JSON response of a Next.js route.
	for _, p := range s.producers {
		if !nextFramework(p.route.Framework) {
			continue
		}
		for _, d := range p.value.deps {
			text := strings.ToLower(d.Source.Text)
			for _, h := range []string{`"host"`, `"x-forwarded-host"`, `"x-forwarded-proto"`} {
				if strings.Contains(text, "headers.get("+h) {
					ps.add("NX-BP-16", "Host header trust in generated URLs", "observed", "the client-controlled "+strings.Trim(h, `"`)+" header builds a value returned in the "+p.route.Method+" "+p.route.PathPattern+" response; an attacker can poison generated absolute links", p.route.Method+" "+p.route.PathPattern, d.Source, p.sink)
				}
			}
		}
	}
	sort.Slice(out.Practice, func(i, j int) bool {
		a, b := out.Practice[i], out.Practice[j]
		if a.Check != b.Check {
			return a.Check < b.Check
		}
		return a.ID < b.ID
	})
}

// NX-BP-03: resolved framework versions with known boundary advisories. This is
// a manifest observation, not reachability analysis (a step toward Audit).
func (s *moduleSet) practiceVersions(ps *practiceSet, p *nextProject) {
	if p.nextVersion == "" {
		return
	}
	ev := s.manifestEvidence(p, "next")
	if lessVersion(p.nextVersion, "15.2.3") && !lessVersion(p.nextVersion, "15.0.0") || lessVersion(p.nextVersion, "14.2.25") && !lessVersion(p.nextVersion, "11.1.4") || lessVersion(p.nextVersion, "13.5.9") && !lessVersion(p.nextVersion, "13.0.0") {
		ps.add("NX-BP-03", "Framework version advisory", "observed", "next "+p.nextVersion+" is in a range affected by CVE-2025-29927 (middleware authorization bypass via x-middleware-subrequest); fixed in 15.2.3, 14.2.25 and 13.5.9. Manifest observation, not reachability.", "", ev...)
	}
	fixed := map[int]string{15: "", 16: "16.0.7"}
	if p.nextMajor == 15 {
		switch {
		case strings.HasPrefix(p.nextVersion, "15.0."):
			fixed[15] = "15.0.5"
		case strings.HasPrefix(p.nextVersion, "15.1."):
			fixed[15] = "15.1.9"
		case strings.HasPrefix(p.nextVersion, "15.2."):
			fixed[15] = "15.2.6"
		case strings.HasPrefix(p.nextVersion, "15.3."):
			fixed[15] = "15.3.6"
		case strings.HasPrefix(p.nextVersion, "15.4."):
			fixed[15] = "15.4.8"
		case strings.HasPrefix(p.nextVersion, "15.5."):
			fixed[15] = "15.5.7"
		}
	}
	if f := fixed[p.nextMajor]; f != "" && lessVersion(p.nextVersion, f) {
		ps.add("NX-BP-03", "Framework version advisory", "observed", "next "+p.nextVersion+" (App Router, React Server Components) is in a range affected by CVE-2025-66478 / CVE-2025-55182 (React Server Components remote code execution); fixed in "+f+". Manifest observation, not reachability.", "", ev...)
	}
}

func (s *moduleSet) manifestEvidence(p *nextProject, pkg string) []analysis.Evidence {
	res := s.resolvePackage(joinDir(p.dir, "x"), pkg)
	if e, ok := s.declarationEvidence(joinDir(p.dir, "x"), pkg, res); ok {
		return []analysis.Evidence{e}
	}
	return nil
}

// lessVersion compares dotted numeric versions; prerelease tags compare as their base.
func lessVersion(a, b string) bool {
	pa, pb := versionParts(a), versionParts(b)
	for i := 0; i < 3; i++ {
		if pa[i] != pb[i] {
			return pa[i] < pb[i]
		}
	}
	return false
}

func versionParts(v string) [3]int {
	v = strings.TrimLeft(v, "^~>=v ")
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	var out [3]int
	for i, part := range strings.SplitN(v, ".", 3) {
		fmt.Sscanf(part, "%d", &out[i])
	}
	return out
}

// NX-BP-08: literal rewrites that expose API handlers under non-/api public
// paths, especially dotfile paths.
func (s *moduleSet) practiceRewrites(ps *practiceSet, p *nextProject) {
	cfg := s.nextConfig(p)
	if cfg == nil {
		return
	}
	for _, rw := range cfg.rewrites {
		if strings.HasPrefix(rw.destination, "/api/") && !strings.HasPrefix(rw.source, "/api/") {
			detail := "rewrite " + rw.source + " -> " + rw.destination + " makes an API handler reachable under a non-/api public path"
			if strings.HasPrefix(rw.source, "/.") {
				detail += "; the source is a dotfile path that scanners and proxies commonly treat as repository or tool metadata"
			}
			ps.add("NX-BP-08", "Rewrite into an internal handler", "observed", detail, "", rw.evidence)
		}
	}
}

// NX-BP-12: no security headers in next.config headers() and none set in middleware.
func (s *moduleSet) practiceSecurityHeaders(ps *practiceSet, p *nextProject) {
	cfg := s.nextConfig(p)
	if cfg == nil || cfg.module == nil || cfg.object == nil || cfg.hasHeaders {
		return
	}
	if mw := s.nextMiddlewareFor(p); mw != nil && mw.module != nil {
		text := strings.ToLower(string(mw.module.src))
		if strings.Contains(text, "content-security-policy") || strings.Contains(text, "x-frame-options") {
			return
		}
	}
	ps.add("NX-BP-12", "Missing security headers", "observed", "next.config defines no headers() and the middleware sets no Content-Security-Policy or X-Frame-Options; CSP, frame-ancestors, Referrer-Policy and HSTS are not configured in source", "", cfg.module.evidence("next_config", cfg.object))
}

// NX-BP-01 / NX-BP-02: middleware is the only authorization of an entry, and
// a matched page whose data API is not matched.
func (s *moduleSet) practiceMiddleware(ps *practiceSet, p *nextProject, out *analysis.AnalysisReport) {
	mw := s.nextMiddlewareFor(p)
	if mw == nil || mw.module == nil || mw.fn == nil || mw.all {
		return
	}
	body := mw.module.evidence("middleware_handler", mw.fn.ChildByFieldName("body"))
	var matchedPages, apiPaths []string
	for _, e := range out.Entries {
		if e.HTTP == nil || !nextFramework(e.HTTP.Framework) {
			continue
		}
		c := s.nodeHTTP[e.ID]
		staged := c != nil && len(c.stages) > 0
		if staged && len(c.controls) == 0 && !strings.Contains(c.handler.evidence("handler", c.body).Text, "cookies") {
			ps.add("NX-BP-01", "Authorization only in middleware", "observed", e.Name+" is authorized only by the root middleware matcher; the handler itself checks no session. A matcher change, a rewrite alias or a middleware bypass removes the only check", e.Name, body, e.Location)
		}
		if staged && e.HTTP.Surface == "page" {
			matchedPages = append(matchedPages, e.HTTP.Path)
		}
		if strings.HasPrefix(e.HTTP.Path, "/api/") && !staged {
			apiPaths = append(apiPaths, e.HTTP.Path)
		}
	}
	for _, page := range matchedPages {
		first := strings.Split(strings.Trim(page, "/"), "/")[0]
		for _, api := range apiPaths {
			if strings.HasPrefix(api, "/api/"+first+"/") || api == "/api/"+first {
				ps.add("NX-BP-02", "Middleware matcher gap", "review", "the middleware matcher covers page "+page+" but not "+api+", which serves the same area; confirm the API route enforces its own authorization", api, body)
			}
		}
	}
}

// NX-BP-04 (committed env files): secret-like NEXT_PUBLIC_ names in .env files.
// Only names are read; values are never stored or printed.
func (s *moduleSet) practiceEnvFiles(ps *practiceSet, p *nextProject) {
	for _, name := range []string{".env", ".env.local", ".env.development", ".env.production", ".env.example", ".env.sample"} {
		file := joinDir(p.dir, name)
		src, err := os.ReadFile(filepath.Join(s.root, filepath.FromSlash(file)))
		if err != nil || len(src) > 1<<20 {
			continue
		}
		for i, line := range strings.Split(string(src), "\n") {
			key := strings.TrimSpace(strings.SplitN(strings.TrimPrefix(strings.TrimSpace(line), "export "), "=", 2)[0])
			if strings.HasPrefix(key, "NEXT_PUBLIC_") && secretName.MatchString(strings.TrimPrefix(key, "NEXT_PUBLIC_")) {
				e := analysis.Evidence{Kind: "env_key", Text: key, Span: analysis.Span{File: file, StartLine: i + 1, EndLine: i + 1}}
				ps.add("NX-BP-04", "Secret-like public environment variable", "observed", key+" is declared in "+file+"; NEXT_PUBLIC_ values are inlined into browser bundles (the value is not read or reported)", "", e)
			}
		}
	}
}

// Client modules: NX-BP-04 reads, NX-BP-05 server-only imports, NX-BP-19 storage.
func (s *moduleSet) practiceClientModule(ps *practiceSet, m *sourceModule) {
	for _, match := range publicEnvRead.FindAllSubmatchIndex(m.src, -1) {
		name := string(m.src[match[2]:match[3]])
		if !secretName.MatchString(strings.TrimPrefix(name, "NEXT_PUBLIC_")) {
			continue
		}
		if n := parse.NodeAt(m.tree.RootNode(), match[0], match[1]); n != nil {
			ps.add("NX-BP-04", "Secret-like public environment variable", "observed", name+" is read in a \"use client\" module and is inlined into the browser bundle", "", m.evidence("env_read", n))
		}
	}
	root := m.tree.RootNode()
	for i := uint(0); i < root.NamedChildCount(); i++ {
		n := root.NamedChild(i)
		if n.Kind() != "import_statement" {
			continue
		}
		spec, ok := stringLiteral(n.ChildByFieldName("source"), m.src)
		if !ok || strings.HasPrefix(spec, "next") || strings.HasPrefix(spec, "react") {
			continue
		}
		target := s.importModule(m, spec)
		if target == nil || target.tree.RootNode().HasError() {
			continue
		}
		if reason := serverOnlyReason(target); reason != "" && !strings.Contains(string(target.src), `"server-only"`) && !strings.Contains(string(target.src), `'server-only'`) {
			ps.add("NX-BP-05", "Server-only module imported by client code", "observed", m.file+" (use client) imports "+target.file+", which "+reason+" and does not import \"server-only\"", "", m.evidence("client_import", n), target.evidence("file", target.tree.RootNode()))
		}
	}
	walkCalls(root, func(call *sitter.Node) {
		fn := call.ChildByFieldName("function")
		args := call.ChildByFieldName("arguments")
		if fn == nil || args == nil || args.NamedChildCount() < 2 {
			return
		}
		text := fn.Utf8Text(m.src)
		if text != "localStorage.setItem" && text != "sessionStorage.setItem" && text != "window.localStorage.setItem" && text != "window.sessionStorage.setItem" {
			return
		}
		key, _ := stringLiteral(args.NamedChild(0), m.src)
		val := args.NamedChild(1).Utf8Text(m.src)
		lower := strings.ToLower(key + " " + val)
		if secretName.MatchString(key) || strings.Contains(lower, "user") || strings.Contains(lower, "session") || strings.Contains(lower, "jwt") {
			ps.add("NX-BP-19", "Sensitive data in web storage", "review", "web storage key "+fmt.Sprintf("%q", key)+" stores "+val+"; any script on the origin can read it. Confirm its data class (credential, session or identity data)", "", m.evidence("storage_write", call))
		}
	})
}

// serverOnlyReason names what makes a module server-only, or "".
func serverOnlyReason(m *sourceModule) string {
	for _, imp := range m.imports {
		switch {
		case imp.module == "fs" || imp.module == "node:fs" || imp.module == "fs/promises" || imp.module == "child_process" || imp.module == "node:child_process":
			return "imports " + imp.module
		case imp.name == "PrismaClient" || imp.module == "@prisma/client":
			return "constructs the Prisma client"
		}
	}
	for _, match := range regexp.MustCompile(`process\.env\.([A-Z][A-Z0-9_]*)`).FindAllStringSubmatch(string(m.src), -1) {
		if !strings.HasPrefix(match[1], "NEXT_PUBLIC_") && match[1] != "NODE_ENV" && secretName.MatchString(match[1]) {
			return "reads process.env." + match[1]
		}
	}
	return ""
}

// NX-BP-06: error details reflected in route handler responses.
func (s *moduleSet) practiceRouteModule(ps *practiceSet, m *sourceModule) {
	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		if n.Kind() == "catch_clause" {
			param := n.ChildByFieldName("parameter")
			body := n.ChildByFieldName("body")
			if param != nil && body != nil && param.Kind() == "identifier" {
				name := param.Utf8Text(m.src)
				text := body.Utf8Text(m.src)
				if strings.Contains(text, "NextResponse.json") && (strings.Contains(text, name+".message") || strings.Contains(text, "String("+name+")") || strings.Contains(text, name+".stack")) {
					ps.add("NX-BP-06", "Error detail reflected in a response", "observed", "the catch block returns "+name+".message/stack text in a JSON response; database and internal errors reach the client", "", m.evidence("error_reflection", body))
				}
			}
		}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			visit(n.NamedChild(i))
		}
	}
	visit(m.tree.RootNode())
}

// NX-BP-17: a Server Component decides access from a client-controlled header
// or cookie compared with a literal.
func (s *moduleSet) practiceGatedRendering(ps *practiceSet, m *sourceModule) {
	headerish := regexp.MustCompile(`\.get\(\s*["']([^"']+)["']\s*\)`)
	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		if n.Kind() == "if_statement" || n.Kind() == "ternary_expression" {
			if c := n.ChildByFieldName("condition"); c != nil {
				text := c.Utf8Text(m.src)
				// A local bound from a headers()/cookies() read counts as that read.
				walkIdentifiers(c, func(id *sitter.Node) {
					if def := definitionAt(m, id, id.Utf8Text(m.src)); def != nil && headerish.MatchString(def.Utf8Text(m.src)) {
						text += " " + def.Utf8Text(m.src)
					}
				})
				if match := headerish.FindStringSubmatch(text); match != nil && (strings.Contains(string(m.src), "next/headers")) && (strings.Contains(text, "===") || strings.Contains(text, "!==") || strings.HasPrefix(strings.TrimSpace(strings.Trim(text, "()")), "!")) {
					kind := "header"
					if strings.Contains(strings.ToLower(text), "cookie") || !strings.HasPrefix(strings.ToLower(match[1]), "x-") {
						kind = "cookie or header"
					}
					ps.add("NX-BP-17", "Header- or cookie-gated rendering", "observed", "the page decides access from the client-controlled "+kind+" "+fmt.Sprintf("%q", match[1])+"; any client can send it. Authorization context only, not a destination control", "", m.evidence("gate_condition", c))
				}
			}
		}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			visit(n.NamedChild(i))
		}
	}
	visit(m.tree.RootNode())
}

// Use-derived checks: NX-BP-07 client IP headers, NX-BP-10 open redirect,
// NX-BP-16 host-header trust in generated URLs.
func (s *moduleSet) practiceUse(ps *practiceSet, u analysis.CandidateUse, e analysis.EntryPoint) {
	for _, d := range u.Dependencies {
		text := strings.ToLower(d.Source.Text)
		if (strings.Contains(text, `"x-forwarded-for"`) || strings.Contains(text, `"x-real-ip"`)) && (u.Kind == "sql_query_candidate" || u.Kind == "nosql_query_candidate" || u.Kind == "log_sink_candidate") {
			ps.add("NX-BP-07", "Trusting client IP headers", "observed", "a client-supplied "+d.Source.Text+" value reaches "+u.Kind+" as an identity value with no trusted-proxy configuration in source", e.Name, d.Source, u.Sink)
		}
	}
	if u.Kind == "xss_candidate" && u.XSS != nil && u.XSS.OutputContext == "url" && strings.Contains(u.Sink.Text, "location") {
		for _, d := range u.Dependencies {
			if d.Source.Kind == "browser_source" {
				ps.add("NX-BP-10", "Open redirect", "observed", "a browser location value ("+d.Source.Text+") becomes the navigation target with no scheme or origin check", e.Name, d.Source, u.Sink)
			}
		}
	}
}

// Client requests: client_request_path_injection (CSPT),
// client_request_query_injection and NX-BP-20 tokens in URLs.
func (s *moduleSet) practiceClientRequest(ps *practiceSet, r clientRequest) {
	m := r.module
	url := unwrapTS(r.url)
	if url == nil || url.Kind() != "template_string" {
		return
	}
	inQuery := false
	lastName := ""
	for i := uint(0); i < url.NamedChildCount(); i++ {
		c := url.NamedChild(i)
		if c.Kind() == "string_fragment" {
			text := c.Utf8Text(m.src)
			if strings.Contains(text, "?") {
				inQuery = true
			}
			if j := strings.LastIndexAny(text, "?&"); j >= 0 && strings.HasSuffix(text, "=") {
				lastName = strings.TrimSuffix(text[j+1:], "=")
			}
			continue
		}
		if c.Kind() != "template_substitution" || c.NamedChildCount() != 1 {
			continue
		}
		expr := unwrapTS(c.NamedChild(0))
		if !s.browserDerived(m, expr) {
			continue
		}
		encoded := false
		if expr.Kind() == "call_expression" {
			if fn := expr.ChildByFieldName("function"); fn != nil && (fn.Utf8Text(m.src) == "encodeURIComponent") {
				encoded = true
			}
		}
		if !inQuery && !encoded {
			ps.add("CLIENT-PATH", "Client-side path traversal (client_request_path_injection)", "review", "a browser location value is inserted unencoded into the path of a same-origin "+r.method+" request; ../ can send the user's authenticated request to another endpoint", "", m.evidence("client_request", r.call), m.evidence("url_substitution", c))
		}
		if inQuery && !encoded {
			ps.add("CLIENT-QUERY", "Client request parameter injection (client_request_query_injection)", "review", "a browser location value is inserted unencoded into the query string of a same-origin request; & and = can add parameters", "", m.evidence("client_request", r.call), m.evidence("url_substitution", c))
		}
		if inQuery && secretName.MatchString(lastName) {
			ps.add("NX-BP-20", "Token in URL", "observed", "the credential-like parameter "+fmt.Sprintf("%q", lastName)+" is placed in a request URL, where it leaks into history, logs and Referer", "", m.evidence("client_request", r.call))
		}
	}
}

// browserDerived reports an expression whose local binding is initialized from a
// browser location source (useSearchParams().get, useParams, location.*).
func (s *moduleSet) browserDerived(m *sourceModule, n *sitter.Node) bool {
	if n == nil {
		return false
	}
	text := n.Utf8Text(m.src)
	if strings.Contains(text, "location.") || strings.Contains(text, "searchParams.get(") {
		return true
	}
	if n.Kind() == "call_expression" {
		if args := n.ChildByFieldName("arguments"); args != nil && args.NamedChildCount() == 1 {
			return s.browserDerived(m, unwrapTS(args.NamedChild(0)))
		}
	}
	if n.Kind() != "identifier" {
		return false
	}
	def := definitionAt(m, n, text)
	if def == nil {
		return false
	}
	d := def.Utf8Text(m.src)
	return strings.Contains(d, "searchParams.get(") || strings.Contains(d, "useSearchParams()") || strings.Contains(d, "useParams") || strings.Contains(d, "location.")
}

func walkIdentifiers(n *sitter.Node, visit func(*sitter.Node)) {
	if n.Kind() == "identifier" {
		visit(n)
	}
	for i := uint(0); i < n.NamedChildCount(); i++ {
		walkIdentifiers(n.NamedChild(i), visit)
	}
}
