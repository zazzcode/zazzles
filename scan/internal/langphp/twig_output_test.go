package langphp

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

func TestTwigOutput(t *testing.T) {
	r := symfonyCaseReport(t, "twig")
	for _, tc := range []struct {
		n                  int
		want, context, gap string
	}{
		{1, "encoded", "html_text", ""}, {2, "raw", "html_text", ""}, {3, "encoded", "html_attribute", ""},
		{4, "raw", "url", ""}, {5, "unknown", "script", ""}, {6, "raw", "html_text", ""},
		{7, "encoded", "html_text", ""}, {8, "encoded", "html_text", ""}, {9, "encoded", "html_text", ""},
		{10, "unknown", "html_text", "twig_expression_unresolved"}, {11, "", "", ""},
		{12, "raw", "html_text", ""}, {13, "raw", "html_text", ""}, {14, "raw", "html_text", ""},
		{15, "raw", "html_text", ""}, {16, "raw", "html_text", ""}, {17, "raw", "html_text", ""},
		{18, "encoded", "html_text", ""}, {19, "encoded", "html_text", ""}, {20, "", "", "twig_template_unresolved"},
	} {
		t.Run(fmt.Sprintf("TW-%02d", tc.n), func(t *testing.T) {
			entry, uses := symfonyXSSCases(t, r, fmt.Sprintf("ANY /tw-%02d", tc.n))
			if tc.want == "" {
				if len(uses) != 0 {
					t.Fatalf("unexpected candidates: %+v", uses)
				}
				if tc.gap != "" && !hasSymfonyGap(entry.Gaps, tc.gap) {
					t.Fatalf("missing %s", tc.gap)
				}
				return
			}
			if len(uses) != 1 {
				t.Fatalf("got %d XSS candidates; want one", len(uses))
			}
			u := uses[0]
			file := fmt.Sprintf("templates/tw%02d.html.twig", tc.n)
			if tc.n == 12 {
				file = "templates/part.html.twig"
			}
			if u.Sink.Span.File != file || u.Sink.Span.StartLine != 1 || u.XSS.Protection != tc.want || u.XSS.OutputContext != tc.context {
				t.Fatalf("sink=%+v protection=%s context=%s", u.Sink.Span, u.XSS.Protection, u.XSS.OutputContext)
			}
			if tc.gap != "" && !hasSymfonyGap(u.Gaps, tc.gap) {
				t.Fatalf("missing %s", tc.gap)
			}
			if tc.n == 16 && !slices.ContainsFunc(u.InputFacts.Stages, func(s analysis.InputStage) bool { return s.Name == "request_field" && s.Scope == "z" }) {
				t.Fatal("Twig Request field z is absent")
			}
			if tc.n == 17 && !slices.ContainsFunc(u.Dependencies, func(d analysis.Dependency) bool {
				return slices.ContainsFunc(d.Transfers, func(e analysis.Evidence) bool { return e.Kind == "helper_return" })
			}) {
				t.Fatal("resolved extension return is absent")
			}
		})
	}
}

func TestSymfonyResponse(t *testing.T) {
	r := symfonyCaseReport(t, "response")
	for _, tc := range []struct {
		n, line int
		gap     string
	}{{1, 12, ""}, {2, 0, ""}, {3, 0, ""}, {4, 29, "render_protection_unresolved"}} {
		t.Run(fmt.Sprintf("RS-%02d", tc.n), func(t *testing.T) {
			_, uses := symfonyXSSCases(t, r, fmt.Sprintf("ANY /rs-%02d", tc.n))
			if tc.line == 0 {
				if len(uses) != 0 {
					t.Fatal("non-HTML response emitted XSS")
				}
				return
			}
			if len(uses) != 1 {
				t.Fatalf("got %d candidates", len(uses))
			}
			u := uses[0]
			if u.Sink.Span.File != "src/Controller/ResponseCases.php" || u.Sink.Span.StartLine != tc.line || u.XSS.OutputContext != "html_text" {
				t.Fatalf("unexpected response sink %+v", u.Sink.Span)
			}
			if tc.gap == "" && u.XSS.Protection != "raw" {
				t.Fatal("HTML response is not raw")
			}
			if tc.gap != "" && !hasSymfonyGap(u.Gaps, tc.gap) {
				t.Fatalf("missing %s", tc.gap)
			}
		})
	}
}

func TestDoctrineStorage(t *testing.T) {
	r := symfonyCaseReport(t, "doctrine-storage")
	for _, tc := range []struct{ id, reader, writer, key string }{
		{"ST-01", "GET /notes", "POST /note", "php-sql:note.body"},
		{"ST-02", "GET /notes", "POST /note/save", "php-sql:note.body"},
		{"ST-03", "GET /notes", "POST /note/{note}", "php-sql:note.body"},
		{"ST-08", "GET /flash", "POST /flash", "php-session:flash.notice"},
	} {
		t.Run(tc.id, func(t *testing.T) {
			_, uses := symfonyXSSCases(t, r, tc.reader)
			writer, _ := symfonyXSSCases(t, r, tc.writer)
			if len(uses) != 1 || uses[0].XSS.StorageKey != tc.key || !slices.Contains(uses[0].XSS.RelatedEntries, writer.ID) {
				t.Fatalf("no stored link from %s to %s", tc.writer, tc.reader)
			}
		})
	}
	t.Run("ST-04", func(t *testing.T) {
		_, uses := symfonyXSSCases(t, r, "GET /note/{note}/fields")
		var keys []string
		for _, u := range uses {
			keys = append(keys, u.XSS.StorageKey)
		}
		slices.Sort(keys)
		if !slices.Equal(keys, []string{"php-sql:note.abstract", "php-sql:note.bio"}) {
			t.Fatalf("field keys: %v", keys)
		}
	})
	t.Run("ST-05", func(t *testing.T) {
		root := t.TempDir()
		if err := os.CopyFS(root, os.DirFS(filepath.Join("testdata", "symfony", "doctrine-storage"))); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "config", "packages", "doctrine.yaml"), []byte("doctrine: {orm: {naming_strategy: app.custom}}\n"), 0600); err != nil {
			t.Fatal(err)
		}
		custom, err := Analyze(root, "")
		if err != nil {
			t.Fatal(err)
		}
		entry, uses := symfonyXSSCases(t, custom, "GET /note/{note}/fields")
		if !hasSymfonyGap(entry.Gaps, "doctrine_naming_unresolved") {
			t.Fatal("missing naming gap")
		}
		if len(uses) == 0 || !hasSymfonyGap(uses[0].Gaps, "storage_origin_unresolved") {
			t.Fatal("missing unresolved stored origin")
		}
	})
	t.Run("ST-06", func(t *testing.T) {
		writer, _ := symfonyXSSCases(t, r, "POST /note/{note}/fill")
		count := 0
		for _, reader := range []string{"GET /notes", "GET /note/{note}/fields"} {
			_, uses := symfonyXSSCases(t, r, reader)
			for _, u := range uses {
				if !slices.Contains(u.XSS.RelatedEntries, writer.ID) {
					continue
				}
				for _, d := range u.Dependencies {
					if slices.ContainsFunc(d.Transfers, func(e analysis.Evidence) bool { return e.Kind == "storage_write_wildcard" }) {
						count++
						break
					}
				}
			}
		}
		if count != 3 {
			t.Fatalf("wildcard writer reaches %d mapped fields; want 3", count)
		}
	})
	t.Run("ST-07", func(t *testing.T) {
		_, uses := symfonyXSSCases(t, r, "GET /label/{label}")
		for _, u := range uses {
			if !u.XSS.OriginResolved || slices.ContainsFunc(u.Dependencies, func(d analysis.Dependency) bool { return d.Source.Kind == "input_source" }) {
				t.Fatalf("literal and non-entry writers carry request content: %+v", u)
			}
		}
	})
}

func symfonyCaseReport(t *testing.T, group string) *analysis.AnalysisReport {
	t.Helper()
	r, err := Analyze(filepath.Join("testdata", "symfony", group), "")
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func symfonyXSSCases(t *testing.T, r *analysis.AnalysisReport, name string) (analysis.EntryPoint, []analysis.CandidateUse) {
	t.Helper()
	for _, entry := range r.Entries {
		if strings.TrimSpace(entry.Name) != name {
			continue
		}
		var uses []analysis.CandidateUse
		for _, u := range r.Uses {
			if u.EntryID == entry.ID && u.Kind == "xss_candidate" {
				uses = append(uses, u)
			}
		}
		return entry, uses
	}
	t.Fatalf("missing entry %s", name)
	return analysis.EntryPoint{}, nil
}

func TestSymfonyResponseHeaderMutation(t *testing.T) {
	r := symfonyCaseReport(t, "response")
	for _, tc := range []struct {
		route, want string
	}{{"plain", ""}, {"html", "raw"}, {"dynamic", "unknown"}} {
		t.Run(tc.route, func(t *testing.T) {
			_, uses := symfonyXSSCases(t, r, "ANY /headers/"+tc.route)
			if tc.want == "" {
				if len(uses) != 0 {
					t.Fatal("non-HTML Content-Type still produces an XSS candidate")
				}
				return
			}
			if len(uses) != 1 || uses[0].XSS.Protection != tc.want {
				t.Fatalf("expected one %s response candidate, got %d", tc.want, len(uses))
			}
			if tc.want == "unknown" && !hasSymfonyGap(uses[0].Gaps, "render_protection_unresolved") {
				t.Fatal("dynamic Content-Type lost its gap")
			}
		})
	}
}

func TestTwigRepeatedRenderSharesSink(t *testing.T) {
	root := t.TempDir()
	if err := os.CopyFS(root, os.DirFS(filepath.Join("testdata", "symfony", "twig"))); err != nil {
		t.Fatal(err)
	}
	controller := filepath.Join(root, "src", "Controller", "TwigCases.php")
	content, err := os.ReadFile(controller)
	if err != nil {
		t.Fatal(err)
	}
	source := strings.Replace(string(content), "return $this->render('tw01.html.twig', ['q' => $q]);",
		"$this->render('tw01.html.twig', ['q' => $q]);\n        return $this->render('tw01.html.twig', ['q' => $request->query->get('alternating')]);", 1)
	if err := os.WriteFile(controller, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	_, uses := symfonyXSSCases(t, r, "ANY /tw-01")
	if len(uses) != 1 || len(uses[0].Dependencies) != 2 {
		t.Fatalf("expected both dependency paths on one Twig sink; got %d candidate(s)", len(uses))
	}
}

func TestSymfonyStorageRespectsProjectRoots(t *testing.T) {
	root := t.TempDir()
	source := os.DirFS(filepath.Join("testdata", "symfony", "doctrine-storage"))
	for _, project := range []string{"writer", "reader"} {
		target := filepath.Join(root, project)
		if err := os.CopyFS(target, source); err != nil {
			t.Fatal(err)
		}
		if project == "writer" {
			continue
		}
		controller := filepath.Join(target, "src", "Controller", "StorageCases.php")
		body, err := os.ReadFile(controller)
		if err != nil {
			t.Fatal(err)
		}
		content := strings.NewReplacer(
			"'/notes'", "'/reader/notes'",
			"'/flash'", "'/reader/flash'",
			"$request->get('b')", "'preset'",
			"$request->request->all()", "['body' => 'preset']",
			"'notice', $request->get('m')", "'notice', 'preset'",
		).Replace(string(body))
		if err := os.WriteFile(controller, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	report, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, read := range []string{"GET /notes", "GET /flash"} {
		_, uses := symfonyXSSCases(t, report, read)
		if len(uses) != 1 || len(uses[0].XSS.RelatedEntries) == 0 {
			t.Fatalf("%s must retain its own linked request writer", read)
		}
	}
	for _, read := range []string{"GET /reader/notes", "GET /reader/flash"} {
		_, uses := symfonyXSSCases(t, report, read)
		if len(uses) != 0 {
			t.Fatalf("%s borrowed a request writer from a different project: %+v", read, uses[0].XSS.RelatedEntries)
		}
	}
}
