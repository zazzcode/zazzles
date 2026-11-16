package parse

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
)

// TestNextJSOopsStoreAnswerKey is the offline integration test of the Next.js
// adapter against the pinned OSS OopsSec Store sample (kOaDT/oss-oopssec-store
// at 2d530ef). It runs only when ZAZZLES_NEXTJS_SAMPLE names a clean checkout
// at that revision, and it checks the answer-key rows that offline evidence
// owns: entries, candidates with complete evidence, negatives and practice
// observations. Judged outcomes are verified separately by paid runs.
func TestNextJSOopsStoreAnswerKey(t *testing.T) {
	root := os.Getenv("ZAZZLES_NEXTJS_SAMPLE")
	if root == "" {
		t.Skip("set ZAZZLES_NEXTJS_SAMPLE to a clean oss-oopssec-store checkout at 2d530ef")
	}
	if out, err := exec.Command("git", "-C", root, "rev-parse", "--short", "HEAD").Output(); err != nil || strings.TrimSpace(string(out)) != "2d530ef" {
		t.Skipf("sample is not at the pinned revision 2d530ef: %s %v", out, err)
	}
	r, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range r.Uses {
		if _, err := analysispacks.Select(u); err != nil {
			t.Errorf("%s %s:%d: judge selection rejects the record: %v", u.Kind, u.Sink.Span.File, u.Sink.Span.StartLine, err)
		}
	}
	entries := map[string]analysis.EntryPoint{}
	routeHandlers, pages := 0, 0
	for _, e := range r.Entries {
		entries[e.ID] = e
		if strings.HasPrefix(e.Location.Span.File, "docs/") || strings.HasPrefix(e.Location.Span.File, "tests/") || strings.HasPrefix(e.Location.Span.File, "cypress/") {
			t.Errorf("entry from an excluded directory: %s", e.Location.Span.File)
		}
		if e.HTTP != nil && e.HTTP.Surface == "route_handler" {
			routeHandlers++
		}
		if e.HTTP != nil && e.HTTP.Surface == "page" {
			pages++
		}
	}
	if routeHandlers != 76 {
		t.Errorf("route handler entries = %d, want 76 (63 route.ts files)", routeHandlers)
	}
	if pages < 30 {
		t.Errorf("page entries = %d", pages)
	}
	for _, g := range r.Gaps {
		if g.Kind == "parse_error" {
			t.Errorf("parse error %s", g.At.File)
		}
	}
	type row struct {
		id, kind, file, contract string
		line                     int
	}
	complete := []row{
		{"OOPS-SQL-01", "sql_query_candidate", "app/api/products/search/route.ts", "prisma-raw-v1", 55},
		{"OOPS-SQL-02", "sql_query_candidate", "app/api/orders/search/route.ts", "prisma-raw-v1", 58},
		{"OOPS-SQL-03", "sql_query_candidate", "app/api/tracking/route.ts", "prisma-raw-v1", 54},
		{"OOPS-SQL-04", "sql_query_candidate", "app/api/admin/reviews/route.ts", "better-sqlite3-v1", 79},
		{"OOPS-PATH-01", "path_traversal_candidate", "app/api/files/route.ts", "", 0},
		{"OOPS-SSRF-01", "ssrf_candidate", "app/api/support/route.ts", "", 16},
		{"OOPS-LOG-01", "log_sink_candidate", "app/api/auth/login/route.ts", "", 16},
		{"OOPS-XSS-05", "xss_candidate", "app/login/LoginForm.tsx", "", 37},
	}
	for _, want := range complete {
		found := false
		for _, u := range r.Uses {
			if u.Kind != want.kind || u.Sink.Span.File != want.file || (want.line != 0 && u.Sink.Span.StartLine != want.line) {
				continue
			}
			found = true
			if want.contract != "" && (u.APIModel == nil || u.APIModel.ID != want.contract) {
				t.Errorf("%s: contract %+v", want.id, u.APIModel)
			}
			if u.Completeness != nil && len(u.Completeness.Blockers) > 0 {
				t.Errorf("%s: blockers %+v", want.id, u.Completeness.Blockers)
			}
			for _, g := range u.Gaps {
				if g.Kind == "async_response_unresolved" || g.Kind == "unresolved_wrapper" {
					t.Errorf("%s: gap %s on a required path", want.id, g.Kind)
				}
			}
		}
		if !found {
			t.Errorf("%s: no %s at %s:%d", want.id, want.kind, want.file, want.line)
		}
	}
	// Client records that must exist (judged Confirmed or Review).
	for _, file := range []string{"app/products/[id]/ProductDetailClient.tsx", "app/profile/ProfileClient.tsx", "app/admin/analytics/AnalyticsClient.tsx", "app/support/SupportForm.tsx"} {
		if len(usesOf(r, "xss_candidate", file)) == 0 {
			t.Errorf("missing client XSS record in %s", file)
		}
	}
	// Negatives: no XSS record for constant HTML, React-encoded values, the
	// react-markdown body or a fixed-prefix iframe URL; no SSRF for own-API fetches.
	for _, u := range usesOf(r, "xss_candidate", "") {
		switch {
		case u.Sink.Span.File == "app/admin/documents/page.tsx",
			u.Sink.Span.File == "app/products/search/ProductSearchClient.tsx",
			u.Sink.Span.File == "app/live/page.tsx",
			u.Sink.Span.File == "app/vulnerabilities/[slug]/page.tsx" && u.Sink.Span.StartLine == 191:
			t.Errorf("negative row produced an XSS record: %s:%d", u.Sink.Span.File, u.Sink.Span.StartLine)
		}
	}
	for _, u := range usesOf(r, "ssrf_candidate", "") {
		if strings.HasPrefix(u.Sink.Span.File, "app/products/") || strings.HasPrefix(u.Sink.Span.File, "app/vulnerabilities/") {
			t.Errorf("own-API page fetch is not SSRF: %s", u.Sink.Span.File)
		}
	}
	internal := 0
	for _, u := range usesOf(r, "outbound_http_candidate", "") {
		if hasNextGap(u.Gaps, "request_path_in_internal_url") {
			internal++
		}
	}
	if internal < 2 {
		t.Errorf("OOPS-SSR-01/02 request_path_in_internal_url observations = %d", internal)
	}
	// OOPS-MW-01: the middleware stage reaches only /monitoring/internal-status.
	for _, c := range r.InvocationContexts {
		for _, ctl := range c.Controls {
			if ctl.Evidence.Kind == "middleware_handler" && entries[c.EntryID].Name != "GET /monitoring/internal-status" {
				t.Errorf("middleware stage on %s", entries[c.EntryID].Name)
			}
		}
	}
	checks := map[string]bool{}
	for _, p := range r.Practice {
		checks[p.Check] = true
	}
	for _, want := range []string{"NX-BP-01", "NX-BP-03", "NX-BP-04", "NX-BP-06", "NX-BP-07", "NX-BP-08", "NX-BP-10", "NX-BP-16", "NX-BP-17", "NX-BP-19", "NX-BP-20", "CLIENT-PATH", "CLIENT-QUERY"} {
		if !checks[want] {
			t.Errorf("practice observation %s missing", want)
		}
	}
	inv, err := Routes(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, route := range inv.Routes {
		if route.Framework != "nextjs" {
			t.Errorf("non-Next route (client call?) %s %s %s", route.Method, route.PathPattern, route.Registration.File)
		}
	}
}
