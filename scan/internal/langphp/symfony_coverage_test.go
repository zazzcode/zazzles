package langphp

import (
	"slices"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

// symfonyEntryUses returns the candidates of one kind under the named entry.
func symfonyEntryUses(t *testing.T, r *analysis.AnalysisReport, name, kind string) []analysis.CandidateUse {
	t.Helper()
	for _, entry := range r.Entries {
		if strings.TrimSpace(entry.Name) != name {
			continue
		}
		var uses []analysis.CandidateUse
		for _, u := range r.Uses {
			if u.EntryID == entry.ID && u.Kind == kind {
				uses = append(uses, u)
			}
		}
		return uses
	}
	t.Fatalf("missing entry %s", name)
	return nil
}

// TestSymfonyCoverageInputs covers route placeholder syntax, typed arguments
// and the request readers and string builders that carry a value to a Response.
func TestSymfonyCoverageInputs(t *testing.T) {
	r := symfonyCaseReport(t, "coverage")
	for _, tc := range []struct{ id, entry, want string }{
		{"CV-01 digits requirement", `ANY /in/digits/{id<\d+>}`, "encoded"},
		{"CV-02 text requirement", `ANY /in/word/{slug<[a-z-]+>}`, "raw"},
		{"CV-03 optional placeholder", "ANY /in/optional/{page?1}", "raw"},
		{"CV-04 placeholder with suffix", "ANY /in/suffix/{slug}.html", "raw"},
		{"CV-05 int argument", "ANY /in/typed/{id}", "encoded"},
		{"CV-06 getString", "ANY /in/string", "raw"},
		{"CV-07 decoded body", "POST /in/json", "raw"},
		{"CV-08 int cast", "ANY /in/cast", "encoded"},
		{"CV-09 sprintf text", "ANY /in/sprintf", "raw"},
		{"CV-10 sprintf number", "ANY /in/sprintf-number", "encoded"},
		{"CV-11 implode", "ANY /in/implode", "raw"},
		{"CV-12 setContent", "ANY /out/content", "raw"},
		{"CV-13 setContent as text/plain", "ANY /out/plain", ""},
		{"CV-14 invokable controller", "GET /invokable", "raw"},
		{"CV-15 class-level methods", "POST /scoped/a", "raw"},
		{"CV-16 entity from {id}", "ANY /store/read/{id}", "raw"},
		{"CV-17 generated identifier", "ANY /store/id/{id}", ""},
		{"CV-18 unwritten flash type", "ANY /flash", ""},
	} {
		t.Run(tc.id, func(t *testing.T) {
			uses := symfonyEntryUses(t, r, tc.entry, "xss_candidate")
			if tc.want == "" {
				if len(uses) != 0 {
					t.Fatalf("unexpected candidates: %+v", uses)
				}
				return
			}
			if len(uses) != 1 || uses[0].XSS.Protection != tc.want {
				t.Fatalf("got %d candidates %+v; want one with protection %s", len(uses), uses, tc.want)
			}
		})
	}
	t.Run("CV-16 stored link", func(t *testing.T) {
		uses := symfonyEntryUses(t, r, "ANY /store/read/{id}", "xss_candidate")
		if len(uses) != 1 {
			t.Fatalf("got %d candidates; want one", len(uses))
		}
		u := uses[0]
		if u.XSS.StorageKey != "php-sql:item.name" || !u.XSS.OriginResolved || len(u.Dependencies) != 1 {
			t.Fatalf("stored facts: %+v deps=%d", u.XSS, len(u.Dependencies))
		}
	})
}

// TestSymfonyCoverageOperations covers shell command expressions and Doctrine
// chains that pass through setters carrying no query text.
func TestSymfonyCoverageOperations(t *testing.T) {
	r := symfonyCaseReport(t, "coverage")
	for _, tc := range []struct {
		id, entry, kind string
		interpolated    bool
	}{
		{"CV-20 backtick in action", "ANY /cmd/backtick", "command_execution_candidate", false},
		{"CV-21 backtick in file entry", "FILE /public/tick.php", "command_execution_candidate", false},
		{"CV-22 builder from and where", "ANY /sql/builder", "sql_query_candidate", true},
		{"CV-23 builder bound value", "ANY /sql/bound", "sql_query_candidate", false},
		{"CV-24 query setMaxResults", "ANY /sql/paged", "sql_query_candidate", true},
		{"CV-25 repository chain", "ANY /sql/repository", "sql_query_candidate", true},
	} {
		t.Run(tc.id, func(t *testing.T) {
			uses := symfonyEntryUses(t, r, tc.entry, tc.kind)
			if len(uses) != 1 {
				t.Fatalf("got %d candidates; want one", len(uses))
			}
			u := uses[0]
			if !slices.ContainsFunc(u.Dependencies, func(d analysis.Dependency) bool { return d.Source.Kind == "input_source" }) {
				t.Fatalf("no request dependency: %+v", u.Dependencies)
			}
			if tc.kind != "sql_query_candidate" {
				return
			}
			if hasSymfonyGap(u.Gaps, "query_text_interpolated") != tc.interpolated {
				t.Fatalf("interpolation evidence = %v, want %v: %+v", !tc.interpolated, tc.interpolated, u.Gaps)
			}
			if !tc.interpolated && !slices.ContainsFunc(u.Context, func(e analysis.Evidence) bool { return e.Kind == "parameter_binding" }) {
				t.Fatal("missing parameter binding evidence")
			}
		})
	}
	t.Run("CV-26 int cast in file entry", func(t *testing.T) {
		uses := symfonyEntryUses(t, r, "FILE /public/tick.php", "xss_candidate")
		if len(uses) != 1 || uses[0].XSS.Protection != "encoded" {
			t.Fatalf("cast output: %+v", uses)
		}
	})
}

// TestSymfonyCoverageTwig covers conditional branches, autoescape strategies,
// URL attributes, safe filters, macros and the markup evidence of an output.
func TestSymfonyCoverageTwig(t *testing.T) {
	r := symfonyCaseReport(t, "coverage")
	uses := symfonyEntryUses(t, r, "ANY /tw/{name}", "xss_candidate")
	byLine := map[int]analysis.CandidateUse{}
	for _, u := range uses {
		if u.Sink.Span.File == "templates/tw.html.twig" {
			byLine[u.Sink.Span.StartLine] = u
		}
	}
	for _, tc := range []struct {
		id                 string
		line               int
		want, context, gap string
	}{
		{"CV-30 raw branch of a conditional", 1, "raw", "html_text", ""},
		{"CV-31 asset with a literal path prefix", 2, "encoded", "url", ""},
		{"CV-32 markup path prefix", 3, "encoded", "url", ""},
		{"CV-33 whole link URL", 4, "raw", "url", ""},
		{"CV-34 whole image URL", 5, "unknown", "url", ""},
		{"CV-35 script source", 6, "unknown", "url", ""},
		{"CV-36 prefix without a delimiter", 7, "unknown", "url", ""},
		{"CV-37 non-HTML autoescape strategy", 8, "unknown", "html_text", "render_protection_unresolved"},
		{"CV-38 spaceless is marked safe", 9, "raw", "html_text", ""},
		{"CV-39 quoted attribute", 10, "encoded", "html_attribute", ""},
		{"CV-40 macro call", 12, "unknown", "html_text", "twig_expression_unresolved"},
	} {
		t.Run(tc.id, func(t *testing.T) {
			u, ok := byLine[tc.line]
			if !ok {
				t.Fatalf("no candidate at line %d", tc.line)
			}
			if u.XSS.Protection != tc.want || u.XSS.OutputContext != tc.context {
				t.Fatalf("protection=%s context=%s, want %s in %s", u.XSS.Protection, u.XSS.OutputContext, tc.want, tc.context)
			}
			if tc.gap != "" && !hasSymfonyGap(u.Gaps, tc.gap) {
				t.Fatalf("missing %s: %+v", tc.gap, u.Gaps)
			}
		})
	}
	t.Run("CV-39 markup evidence", func(t *testing.T) {
		u, ok := byLine[10]
		if !ok {
			t.Fatal("no candidate at line 10")
		}
		if !slices.ContainsFunc(u.Context, func(e analysis.Evidence) bool {
			return e.Kind == "render_markup_context" && strings.Contains(e.Text, `<input value="{{ q }}">`)
		}) {
			t.Fatalf("surrounding markup is absent: %+v", u.Context)
		}
		if u.Completeness == nil || len(u.Completeness.Evidence["render_context"]) < 2 {
			t.Fatalf("render context lacks the markup: %+v", u.Completeness)
		}
	})
	t.Run("CV-41 macro body", func(t *testing.T) {
		if _, ok := byLine[11]; ok {
			t.Fatal("macro body output was recorded without its arguments")
		}
		for _, entry := range r.Entries {
			if strings.TrimSpace(entry.Name) == "ANY /tw/{name}" && !hasSymfonyGap(entry.Gaps, "twig_template_unresolved") {
				t.Fatal("macro definition has no gap")
			}
		}
	})
	t.Run("CV-42 project autoescape off", func(t *testing.T) {
		raw := symfonyEntryUses(t, symfonyCaseReport(t, "twig-raw"), "ANY /raw", "xss_candidate")
		if len(raw) != 2 || raw[0].XSS.Protection != "raw" || raw[1].XSS.Protection != "encoded" {
			t.Fatalf("autoescape false: %+v", raw)
		}
	})
}
